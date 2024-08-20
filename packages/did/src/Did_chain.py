import packages.sdk.src as Cord
from packages.utils.src.crypto_utils import generate_mnemonic
from packages.utils.src.SDKErrors import Errors
from .Did_utils import get_address_by_key, get_did_uri_from_key, parse, get_did_uri
from .Did_rpc import linked_info_from_chain
import re
from urllib.parse import unquote, quote, urlparse
from packages.utils.src.keys import generate_keypairs
from substrateinterface.exceptions import SubstrateRequestException


from .did_document_exporter import did_document_exporter


crypto_type_map = {0: "Ed25519", 1: "Sr25519", 2: "Ecdsa"}


def to_chain(did_uri):
    return parse(did_uri)["address"]

def from_chain(encoded):
    return get_did_uri(encoded)

def resource_id_to_chain(id):
    """
    Format a DID resource ID to be used as a parameter for the blockchain API functions.

    Args:
        id (str): The DID resource ID to format.

    Returns:
        str: The blockchain-formatted ID.
    """
    return re.sub(r"^#", "", id)


def is_uri(string):
    """
    Checks if a string is a valid URI according to RFC#3986.

    Args:
        string (str): String to be checked.

    Returns:
        bool: Whether `string` is a valid URI.
    """
    try:
        # Parse the URL to check if it can be parsed
        result = urlparse(string)
        # Check if the scheme and netloc or path are present, which ensures it's a valid URI
        if not all([result.scheme, result.netloc or result.path]):
            return False
        # Ensure the URI has not been converted implicitly
        return string == result.geturl() or quote(unquote(string)) == string
    except:
        return False


URI_FRAGMENT_REGEX = re.compile(r"^[a-zA-Z0-9._~%+,;=*()'&$!@:/?-]+$")


def is_uri_fragment(string):
    """
    Checks if a string is a valid URI fragment according to RFC#3986.

    Args:
        string (str): String to be checked.

    Returns:
        bool: Whether `string` is a valid URI fragment.
    """
    try:
        # Check if the string matches the regex and can be successfully decoded
        return bool(URI_FRAGMENT_REGEX.match(string)) and bool(unquote(string))
    except:
        return False


def validate_service(endpoint):
    """
    Performs sanity checks on service endpoint data, making sure that the following conditions are met:
      - The `id` property is a string containing a valid URI fragment according to RFC#3986, not a complete DID URI.
      - If the `uris` property contains one or more strings, they must be valid URIs according to RFC#3986.

    Args:
        endpoint (dict): A service endpoint object to check.

    Raises:
        DidError: If any of the checks fail.
    """
    id = endpoint["id"]
    service_endpoint = endpoint["service_endpoint"]

    if id.startswith("did:cord"):
        raise Errors.DidError(
            f"This function requires only the URI fragment part (following '#') of the service ID, not the DID URI, which is violated by id \"{id}\""
        )

    if not is_uri_fragment(resource_id_to_chain(id)):
        raise Errors.DidError(
            f'The service ID must be valid as a URI fragment according to RFC#3986, which "{id}" is not. Make sure not to use disallowed characters (e.g. whitespace) or consider URL-encoding the desired id.'
        )

    for uri in service_endpoint:
        if not is_uri(uri):
            raise Errors.DidError(
                f'A service URI must be a URI according to RFC#3986, which "{uri}" (service id "{id}") is not. Make sure not to use disallowed characters (e.g. whitespace) or consider URL-encoding resource locators beforehand.'
            )


def service_to_chain(service):
    # validate_service(service)
    return {
        "id": resource_id_to_chain(service["id"]),
        "service_types": [service["type"]],
        "urls": [service["service_endpoint"]],
    }


def public_key_to_chain(key):
    """
    Transforms a DID public key record to an enum-type key-value pair required in many key-related extrinsics.

    Args:
        key (dict): Object describing data associated with a public key.

    Returns:
        dict: Data restructured to allow SCALE encoding by polkadot api.
    """

    return [{key["crypto_type"]: "0x" + key["public_key"].hex()}]


def public_key_to_chain_for_keypair(key):

    crypto_type_str = crypto_type_map.get(key.crypto_type, "unknown")
    return {crypto_type_str: "0x" + key.public_key.hex()}


async def get_store_tx(input, submitter, sign_callback):

    api = Cord.ConfigService.get("api")

    authentication = input.get("authentication", [])
    assertion_method = input.get("assertion_method", [])
    capability_delegation = input.get("capability_delegation", [])
    key_agreement = input.get("key_agreement", [])
    service = input.get("service", [])

    if not authentication:
        raise Errors.DidError(
            "The provided DID does not have an authentication key to sign the creation operation"
        )

    if len(assertion_method) > 1:
        raise Errors.DidError(
            f"More than one assertion key ({len(assertion_method)}) specified. The chain can only store one."
        )

    if len(capability_delegation) > 1:
        raise Errors.DidError(
            f"More than one delegation key ({len(capability_delegation)}) specified. The chain can only store one."
        )

    max_key_agreement_keys = api.get_metadata_constant("Did", "MaxNewKeyAgreementKeys")[
        "value"
    ]
    if len(key_agreement) > int.from_bytes(max_key_agreement_keys, byteorder="big"):
        raise Errors.DidError(
            f"The number of key agreement keys in the creation operation is greater than the maximum allowed, which is {max_key_agreement_keys}"
        )

    max_number_of_services_per_did = api.get_metadata_constant(
        "Did", "MaxNumberOfServicesPerDid"
    )["value"]
    if len(service) > int.from_bytes(max_number_of_services_per_did, byteorder="big"):
        raise Errors.DidError(
            f"Cannot store more than {max_number_of_services_per_did} service endpoints per DID"
        )

    authentication_key = authentication[0]
    did = get_address_by_key(authentication_key)

    new_assertion_key = (
        public_key_to_chain_for_keypair(assertion_method[0])
        if assertion_method
        else None
    )
    new_delegation_key = (
        public_key_to_chain_for_keypair(capability_delegation[0])
        if capability_delegation
        else None
    )
    new_key_agreement_keys = [public_key_to_chain(key) for key in key_agreement]
    new_service_details = [service_to_chain(svc) for svc in service]

    api_input = {
        "did": did,
        "submitter": submitter,
        "new_assertion_key": new_assertion_key,
        "new_delegation_key": new_delegation_key,
        "new_key_agreement_keys": new_key_agreement_keys,
        "new_service_details": new_service_details,
    }
    
    encoded = api.encode_scale(type_string='pallet_did::did_details::DidCreationDetails<sp_core::crypto::AccountId32, sp_core::crypto::AccountId32, cord_loom_runtime::MaxNewKeyAgreementKeys, pallet_did::service_endpoints::DidEndpoint<T>>',value=api_input)
    
    signature = sign_callback(encoded)
    encoded_signature = {signature["key_type"]: "0x" + signature["signature"].hex()}

    extrinsic = api.compose_call(
        call_module="Did",
        call_function="create",
        call_params={"details": api_input, "signature": encoded_signature},
    )

    return extrinsic


async def create_did(submitter_account, the_mnemonic=None, did_service_endpoint=None):
    api = Cord.ConfigService.get("api")

    # Generate mnemonic if not provided
    mnemonic = the_mnemonic if the_mnemonic else generate_mnemonic(24)

    # Generate key pairs
    keypairs = generate_keypairs(mnemonic, "sr25519")
    authentication = keypairs["authentication"]
    key_agreement = keypairs["key_agreement"]
    assertion_method = keypairs["assertion_method"]
    capability_delegation = keypairs["capability_delegation"]

    # Prepare service endpoints
    if did_service_endpoint is None:
        did_service_endpoint = [
            {
                "id": "#my-service",
                "type": ["service-type"],
                "service_endpoint": ["https://www.example.com"],
            }
        ]

    # Get transaction for creating the DID
    did_creation_tx = await get_store_tx(
        {
            "authentication": [authentication],
            "key_agreement": [key_agreement],
            "assertion_method": [assertion_method],
            "capability_delegation": [capability_delegation],
            "service": did_service_endpoint,
        },
        submitter_account.ss58_address,
        lambda data: {
            "signature": authentication.sign(data),
            "key_type": crypto_type_map.get(authentication.crypto_type, "unknown"),
        },
    )

    # Sign and submit the transaction
    extrinsic = api.create_signed_extrinsic(did_creation_tx, submitter_account)
    api.submit_extrinsic(extrinsic, wait_for_inclusion=True)

    # Retrieve the DID URI and document
    did_uri = get_did_uri_from_key(authentication)

    encoded_did = api.runtime_call("DidApi", "query", [to_chain(did_uri)])
    document = linked_info_from_chain(encoded_did)

    if not document:
        raise Exception("DID was not successfully created.")

    print(document)

    return {"mnemonic": mnemonic, "document": document["document"]}


async def generate_did_authenticated_tx(params):
    """
    DID-related operations on the CORD blockchain require authorization by a DID. This is realized by requiring that relevant extrinsics are signed with a key featured by a DID as a verification method.
    Such extrinsics can be produced using this function.

    Args:
        params (dict): Object wrapping all input to the function.
        params['did'] (str): Full DID.
        params['keyRelationship'] (str): DID key relationship to be used for authorization.
        params['sign'] (function): The callback to interface with the key store managing the private key to be used.
        params['call'] (Extrinsic): The call or extrinsic to be authorized.
        params['txCounter'] (BN): The nonce or txCounter value for this extrinsic, which must be larger than the current txCounter value of the authorizing DID.
        params['submitter'] (CordAddress): Payment account allowed to submit this extrinsic and cover its fees, which will end up owning any deposit associated with newly created records.
        params['blockNumber'] (int, optional): Block number for determining the validity period of this authorization. If omitted, the current block number will be fetched from chain.

    Returns:
        SubmittableExtrinsic: A DID-authorized extrinsic that, after signing with the payment account mentioned in the params, is ready for submission.
    """

    api = Cord.ConfigService.get("api")

    input = {
        "tx_counter": params["tx_counter"],
        "did": to_chain(params["did"]),
        "call": params["call"],
        "submitter": params["submitter"],
        "block_number": params.get("block_number") or api.query("System", "Number"),
    }
    signable_call = api.encode_scale(
        type_string="pallet_did::did_details::DidAuthorizedCallOperation<sp_core::crypto::AccountId32, cord_runtime::RuntimeCall, BlockNumber, sp_core::crypto::AccountId32, TxCounter>",
        value=input,
    )

    signature = params["sign"](
        {
            "data": signable_call,
            "key_relationship": params["key_relationship"],
            "did": params["did"],
        }
    )

    encoded_signature = {
        crypto_type_map.get(signature["key_type"], "unknown"): signature["signature"]
    }

    extrinsic = api.compose_call(
        "Did",
        "submit_did_call",
        {
            "did_call": input,
            "signature": encoded_signature,
        },
    )
    
    return extrinsic


# ---------FullDidFuntions----------------
MAX_NONCE_VALUE = int(pow(2, 64) - 1)


def increase_nonce(current_nonce, increment=1):
    return increment if current_nonce == MAX_NONCE_VALUE else current_nonce + increment


def get_next_nonce(did):
    try:
        # Fetch the DID document from the blockchain
        result = Cord.ConfigService.get("api").query(
            module="Did", storage_function="Did", params=[to_chain(did)]
        )

        if result is not None and result.value:
            current_nonce = int(result.value["last_tx_counter"])
        else:
            current_nonce = 0

        return increase_nonce(current_nonce)

    except SubstrateRequestException as e:
        print(f"Failed to fetch DID document: {str(e)}")
        return 0


method_mapping = {
    "Statement": "authentication",
    "Schema": "authentication",
    "ChainSpace.add_admin_delegate": "capability_delegation",
    "ChainSpace.add_audit_delegate": "capability_delegation",
    "ChainSpace.add_delegate": "capability_delegation",
    "ChainSpace.remove_delegate": "capability_delegation",
    "ChainSpace.create": "authentication",
    "ChainSpace.archive": "authentication",
    "ChainSpace.restore": "authentication",
    "ChainSpace.subspace_create": "authentication",
    "ChainSpace.update_transaction_capacity_sub": "authentication",
    "Did": "authentication",
    "Did.create": None,
    "Did.submit_did_call": None,
    "DidLookup": "authentication",
    "DidName": "authentication",
    "NetworkScore": "authentication",
    "Asset": "authentication",
}


async def authorize_tx(did, extrinsic, sign, submitter_account, signing_options=None):
    """
    Signs and returns the provided unsigned extrinsic with the right DID key, if present. Otherwise, it will throw an error.

    Args:
        did (DidUri): The DID data.
        extrinsic (Extrinsic): The unsigned extrinsic to sign.
        sign (SignExtrinsicCallback): The callback to sign the operation.
        submitter_account (CordAddress): The account to bind the DID operation to (to avoid MitM and replay attacks).
        signing_options (dict, optional): The signing options.
        signing_options['txCounter'] (BN, optional): The optional DID nonce to include in the operation signatures. By default, it uses the next value of the nonce stored on chain.

    Returns:
        SubmittableExtrinsic: The DID-signed submittable extrinsic.
    """
    if signing_options is None:
        signing_options = {}

    key_relationship = get_key_relationship_for_method(extrinsic)
    if key_relationship is None:
        raise Errors.SDKError("No key relationship found for extrinsic")

    tx_counter = signing_options.get("tx_counter") or (get_next_nonce(did))

    return await generate_did_authenticated_tx(
        {
            "did": did,
            "key_relationship": key_relationship,
            "sign": sign,
            "call": extrinsic,
            "tx_counter": tx_counter,
            "submitter": submitter_account,
        }
    )


def get_key_relationship_for_tx(extrinsic):
    """
    Detect the key relationship for a key which should be used to DID-authorize the provided extrinsic.

    Args:
        extrinsic (Extrinsic): The unsigned extrinsic to inspect.

    Returns:
        VerificationKeyRelationship or None: The key relationship.
    """
    return get_key_relationship_for_method(extrinsic.method)


def get_key_relationship_for_method(call):
    """
    Get the key relationship for the given method.

    Args:
        call (Extrinsic['method']): The method to inspect.

    Returns:
        VerificationKeyRelationship or None: The key relationship.
    """
    section = call.call_module["name"]
    method = call.call_function["name"]

    # Get the VerificationKeyRelationship of a batched call
    if (
        section == "utility"
        and method in ["batch", "batchAll", "forceBatch"]
        and call.call_params[0].to_raw_type() == "Vec<Call>"
    ):
        # Map all calls to their VerificationKeyRelationship and deduplicate the items
        key_relationships = [
            get_key_relationship_for_method(sub_call)
            for sub_call in call.call_params[0]
        ]
        return (
            key_relationships[0]
            if all(x == key_relationships[0] for x in key_relationships)
            else None
        )

    signature = f"{section}.{method}"
    if signature in method_mapping:
        return method_mapping[signature]

    return method_mapping.get(section)
