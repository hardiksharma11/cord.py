from packages.sdk.src import ConfigService, Did, Utils
import cbor2
import base64
from collections import OrderedDict
from packages.identifier.src.identifier import (
    hash_to_uri,
    uri_to_identifier,
    identifier_to_uri
)
from packages.utils.src.idents import SCHEMA_IDENT
from packages.utils.src.prefix import SCHEMA_PREFIX
from packages.utils.src.SDKErrors import Errors
from .schema_types import SchemaModel


def encode_cbor_schema(schema):
    """
    (Internal Function) - Serializes a given schema object for hashing or storing using CBOR encoding.

    This function standardizes the representation of a schema object by removing its `$id` property, if present,
    and then serializing it. This standardized serialization is crucial for consistent hashing and comparison of
    schema objects, ensuring that the serialization output is not affected by the presence or absence of an `$id`
    property. The serialization is done using CBOR (Concise Binary Object Representation) encoding, which is a
    compact and efficient binary format.

    The process includes sorting the properties of the schema to ensure a deterministic order, which is essential
    for consistent hashing. The sorted schema is then encoded into a CBOR format and converted to a base64 string
    to facilitate easy storage and transmission.

    :param schema: The schema object to be serialized. The schema can either include the `$id` property or be any
                   schema object without `$id`. The `$id` property is disregarded during serialization to ensure consistency.
    :returns: A base64 string representing the serialized CBOR encoding of the schema without the `$id` property.
              This string can be used for hashing, comparison, or storage.
    """
    # Remove the $id property if it exists
    schema_without_id = {key: value for key, value in schema.items() if key != "$id"}

    # Sort the schema properties
    sorted_schema = OrderedDict(sorted(schema_without_id.items()))

    # Encode the sorted schema with CBOR
    encoded_schema = cbor2.dumps(sorted_schema)

    # Convert to base64 string
    cbor_schema_base64 = base64.b64encode(encoded_schema).decode("utf-8")

    return cbor_schema_base64


def get_uri_for_schema(schema, creator, space):
    """
    Generates a unique URI for a given schema based on its content, the creator's DID, and the associated space.
    This URI serves as a unique identifier for the schema within the Cord network.

    The function utilizes the content of the schema, the creator's DID, and the space identifier to produce a unique identifier.
    This process is crucial to ensure that each schema can be uniquely identified and retrieved within the Cord network, providing
    a consistent and reliable way to access schema data.

    @param schema: The schema object or a version of the schema object without the `$id` property.
                   The schema object should conform to the ISchema interface.
    @param creator: A decentralized identifier (DID) URI of the schema creator. This DID should be a valid identifier within the Cord network.
    @param space: An identifier for the space (context or category) to which the schema belongs. This helps in categorizing
                   and organizing schemas within the network.

    @returns: An object containing the schema's unique URI and its digest. The `uri` is a string representing
              the unique URI of the schema, and `digest` is a cryptographic hash of the schema, space identifier, and creator's DID.

    @internal
    @throws: Error if the URI generation process fails, indicating an issue with schema data, space, or creator's DID.
    """

    api = ConfigService.get("api")
    serialized_schema = encode_cbor_schema(schema)
    digest = Utils.crypto_utils.hash_str(serialized_schema.encode("utf-8"))

    scale_encoded_schema = api.encode_scale(
        type_string="Bytes", value=serialized_schema
    ).get_remaining_bytes()
    scale_encoded_space = api.encode_scale(
        type_string="Bytes", value=uri_to_identifier(space)
    ).get_remaining_bytes()
    scale_encoded_creator = api.encode_scale(
        type_string="AccountId", value=Did.to_chain(creator)
    ).get_remaining_bytes()

    concatenated_data = (
        scale_encoded_schema + scale_encoded_space + scale_encoded_creator
    )
    id_digest = Utils.crypto_utils.blake2_as_hex(concatenated_data)

    schema_uri = hash_to_uri(id_digest, SCHEMA_IDENT, SCHEMA_PREFIX)

    return {"uri": schema_uri, "digest": digest}


async def is_schema_stored(schema) -> bool:
    """
    Checks if a given schema is stored on the blockchain.
    This function queries the blockchain to determine whether the specified schema exists in the blockchain storage.

    :param schema: The schema object (`ISchema`) to be checked. It must contain a valid `$id` property.

    :returns: It returns `true` if the schema is stored on the blockchain,
              and `false` if it is not.
    """
    api = ConfigService.get("api")
    identifier = uri_to_identifier(schema["$id"])
    encoded = api.query("Schema", "Schemas", [identifier])

    if encoded.value is None: return False
    return True


async def dispatch_to_chain(
    schema, creator, author_account, authorization, sign_callback
):
    """
    Dispatches a schema to the blockchain for storage and tracking. This function handles
    the submission of a schema object to the blockchain, ensuring its uniqueness, immutability,
    and verifiability in a decentralized environment.

    :param schema: The schema object, typically representing a structured data format defining data requirements.
    :param creator: The decentralized identifier (DID) URI representing the digital identity of the creator.
    :param author_account: The blockchain account of the author.
    :param authorization: A unique identifier for authorization purposes, authenticating and signing the transaction.
    :param sign_callback: A callback function that handles the signing of the blockchain transaction (extrinsic).

    :returns: A object that resolves to the unique ID of the dispatched schema upon successful processing by the blockchain.
    """
    try:
        api = ConfigService.get("api")

        exists = await is_schema_stored(schema)
        if exists:
            return schema["$id"]

        authorization_id = uri_to_identifier(authorization)
        encoded_schema = encode_cbor_schema(schema)
        tx = api.compose_call(
            call_module="Schema",
            call_function="create",
            call_params={"tx_schema": encoded_schema, "authorization": authorization_id},
        )
        extrinsic = await Did.authorize_tx(
            creator, tx, sign_callback, author_account.ss58_address
        )

        extrinsic = api.create_signed_extrinsic(call=extrinsic, keypair=author_account)
        api.submit_extrinsic(extrinsic, wait_for_inclusion=True)
        
        return schema["$id"]
    except Exception as error:
        raise Errors.CordDispatchError(f'Error dispatching to chain: "{error}".')

def schema_input_from_chain(input, schema_uri):
    """
    (Internal Function) - Fetches and reconstructs a schema object from the blockchain using its URI.
    This function retrieves encoded schema data from the blockchain, decodes it, and constructs a structured
    schema object.

    :param input: The raw input data in bytes, representing the encoded schema data on the blockchain.
    :param schema_uri: The URI (`$id`) of the schema to be fetched, used to uniquely identify the schema on the blockchain.
    :returns: The reconstructed schema object based on the blockchain data.
              This object includes all the decoded properties and structure of the original schema.
    :raises SDKErrors.SchemaError: Thrown when the input data cannot be decoded into a valid schema, or if the
                                   specified schema is not found on the blockchain. This error provides details
                                   about the nature of the decoding or retrieval issue.
    """
    try:
        base64_input = input.encode('utf-8')
        binary_data = base64.b64decode(base64_input)

        decoded_schema = cbor2.loads(binary_data)

        reconstructed_schema = {
            '$id': schema_uri,
            **decoded_schema
        }
        # If throws if the input was a valid JSON but not a valid Schema.
        from .schema import verify_object_against_schema
        verify_object_against_schema(reconstructed_schema, SchemaModel)
        return reconstructed_schema
    except Exception as cause:
        raise Errors.SchemaError(
            f'The provided payload cannot be parsed as a Schema: {input}',
            cause
        )


def from_chain(encoded_entry, schema_uri):
    """
    Converts a blockchain-encoded schema entry to a more readable and usable format.

    :param encoded_entry: The blockchain-encoded schema entry. It is wrapped in an `Option` type to handle the possibility that the schema might not exist.
    :param schema_uri: The URI (`$id`) of the schema being processed.

    :returns: Returns an object containing the schema information if the schema exists on the blockchain. If the schema does not exist, it returns `null`.
    """
    if encoded_entry.value:
        unwrapped = encoded_entry.value
        schema = unwrapped["schema"]
        digest = unwrapped["digest"]
        creator = unwrapped["creator"]
        space = unwrapped["space"]
      
        return {
            "schema": schema_input_from_chain(schema, schema_uri),
            "digest": digest,
            "space_uri": identifier_to_uri(space),
            "creator_uri": Did.from_chain(creator),
        }
    return None

async def fetch_from_chain(schema_uri):
    """
    Retrieves schema details from the blockchain using a given schema ID.

    :param schema_uri: The unique identifier of the schema, formatted as a URI string.
           This ID is used to locate and retrieve the schema on the blockchain, ensuring accuracy in schema retrieval.

    :returns: A promise that resolves to the schema details if found on the blockchain.
              If the schema is not present, the promise resolves to `null`.
              This approach provides a straightforward method for accessing schema information by their unique identifiers.

    :raises SDKErrors.SchemaError: Thrown if the schema with the provided ID is not found on the blockchain.
    :raises SDKErrors.CordFetchError: Thrown in case of errors during the fetching process, such as network
            issues or problems with querying the blockchain.
    """
    try:
        api = ConfigService.get('api')
        cord_schema_id = uri_to_identifier(schema_uri)

        schema_entry = api.query('Schema','Schemas' ,[cord_schema_id])
        decoded_schema = from_chain(schema_entry, schema_uri)

        if decoded_schema is None:
            raise Errors.SchemaError(
                f'There is not a Schema with the provided URI "{schema_uri}" on chain.'
            )

        return decoded_schema
    except Exception as error:
        print('Error fetching schema from chain:', error)
        raise Errors.CordFetchError(
            f'Error occurred while fetching schema from chain: {error}'
        )

