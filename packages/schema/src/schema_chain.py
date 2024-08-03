from packages.sdk.src import ConfigService,Did,Utils
import cbor2
import base64
from collections import OrderedDict
from packages.identifier.src.identifier import (
    hash_to_uri,
    uri_to_identifier,
)
from packages.utils.src.idents import SCHEMA_IDENT
from packages.utils.src.prefix import SCHEMA_PREFIX



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

    api = ConfigService.get('api')
    serialized_schema = encode_cbor_schema(schema)
    digest = Utils.crypto_utils.hash_str(serialized_schema.encode('utf-8'))
 
    scale_encoded_schema = api.encode_scale(type_string='Bytes', value=serialized_schema).get_remaining_bytes()
    scale_encoded_space = api.encode_scale(type_string='Bytes', value=uri_to_identifier(space)).get_remaining_bytes()
    scale_encoded_creator = api.encode_scale(type_string='AccountId', value=Did.to_chain(creator)).get_remaining_bytes()

    concatenated_data = scale_encoded_schema + scale_encoded_space + scale_encoded_creator
    id_digest = Utils.crypto_utils.blake2_as_hex(concatenated_data)

    schema_uri = hash_to_uri(id_digest, SCHEMA_IDENT, SCHEMA_PREFIX)

    return {'uri': schema_uri, 'digest': digest}