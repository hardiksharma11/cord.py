import packages.sdk.src as Cord
from packages.utils.src.crypto_utils import generate_mnemonic
from packages.utils.src.SDKErrors import Errors
from .Did_utils import get_address_by_key, get_did_uri_from_key, parse
from .Did_rpc import linked_info_from_chain
import re
from urllib.parse import unquote, quote, urlparse
from packages.utils.src.keys import generate_keypairs

crypto_type_map = {
        0: 'Ed25519',
        1: 'Sr25519',
        2: 'Ecdsa'
    }


def to_chain(did_uri):
    return parse(did_uri)['address']

def resource_id_to_chain(id):
    """
    Format a DID resource ID to be used as a parameter for the blockchain API functions.

    Args:
        id (str): The DID resource ID to format.

    Returns:
        str: The blockchain-formatted ID.
    """
    return re.sub(r'^#', '', id)


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
    id = endpoint['id']
    service_endpoint = endpoint['service_endpoint']

    if id.startswith('did:cord'):
        raise Errors.DidError(
            f'This function requires only the URI fragment part (following \'#\') of the service ID, not the DID URI, which is violated by id "{id}"'
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
    #validate_service(service)
    return  {
        'id':resource_id_to_chain(service['id']),
        'service_types':[service['type']],
        'urls':[service['service_endpoint']]
    }

def public_key_to_chain(key):
    """
    Transforms a DID public key record to an enum-type key-value pair required in many key-related extrinsics.

    Args:
        key (dict): Object describing data associated with a public key.

    Returns:
        dict: Data restructured to allow SCALE encoding by polkadot api.
    """

    return [{key['crypto_type']: '0x' + key['public_key'].hex()}]

def public_key_to_chain_for_keypair(key):
    
    crypto_type_str = crypto_type_map.get(key.crypto_type, 'unknown')
    return {crypto_type_str: '0x' + key.public_key.hex()}

async def get_store_tx(input, submitter, sign_callback):
    
    api = Cord.ConfigService.get('api')

    authentication = input.get('authentication', [])
    assertion_method = input.get('assertion_method', [])
    capability_delegation = input.get('capability_delegation', [])
    key_agreement = input.get('key_agreement', [])
    service = input.get('service', [])
    
    if not authentication:
        raise Errors.DidError("The provided DID does not have an authentication key to sign the creation operation")

    if len(assertion_method) > 1:
        raise Errors.DidError(f"More than one assertion key ({len(assertion_method)}) specified. The chain can only store one.")

    if len(capability_delegation) > 1:
        raise Errors.DidError(f"More than one delegation key ({len(capability_delegation)}) specified. The chain can only store one.")

    max_key_agreement_keys = api.get_metadata_constant('Did', 'MaxNewKeyAgreementKeys')['value']
    if len(key_agreement) > int.from_bytes(max_key_agreement_keys, byteorder='big'):
        raise Errors.DidError(f"The number of key agreement keys in the creation operation is greater than the maximum allowed, which is {max_key_agreement_keys}")

    max_number_of_services_per_did = api.get_metadata_constant('Did', 'MaxNumberOfServicesPerDid')['value']
    if len(service) > int.from_bytes(max_number_of_services_per_did, byteorder='big'):
        raise Errors.DidError(f"Cannot store more than {max_number_of_services_per_did} service endpoints per DID")

    authentication_key = authentication[0]
    did = get_address_by_key(authentication_key)
    
    new_assertion_key = public_key_to_chain_for_keypair(assertion_method[0]) if assertion_method else None
    new_delegation_key = public_key_to_chain_for_keypair(capability_delegation[0]) if capability_delegation else None
    new_key_agreement_keys = [public_key_to_chain(key) for key in key_agreement]
    new_service_details = [service_to_chain(svc) for svc in service]

    api_input = {
        'did': did,
        'submitter': submitter,
        'new_assertion_key': new_assertion_key,
        'new_delegation_key': new_delegation_key,
        'new_key_agreement_keys': new_key_agreement_keys,
        'new_service_details': new_service_details,
    }
    api_input_2 = {
        'did': did,
        'submitter': submitter,
        'new_assertion_key': new_assertion_key,
        'new_delegation_key': new_delegation_key,
        'new_key_agreement_keys': [
            [{'X25519': '0x'+key_agreement[0]['public_key'].hex()}],
        ],
        'new_service_details': [
                    {
                    'id': '#my-service',
                    'service_types': [['service-type']],
                    'urls': [['https://www.example.com']]
                    },
        ],
    }
    
    encoded = api.encode_scale(type_string='scale_info::217',value=api_input)
    
    signature = sign_callback(encoded)
    encoded_signature = {signature['key_type']: '0x' + signature['signature'].hex()}

    extrinsic = api.compose_call(
        call_module='Did',
        call_function='create',
        call_params={
            'details': api_input,
            'signature': encoded_signature
        }
    )

    return extrinsic

async def create_did(submitter_account, the_mnemonic = None, did_service_endpoint = None):
    api = Cord.ConfigService.get('api')

    # Generate mnemonic if not provided
    mnemonic = the_mnemonic if the_mnemonic else generate_mnemonic(24)
    
    # Generate key pairs
    keypairs = generate_keypairs(mnemonic, "sr25519")
    authentication = keypairs['authentication']
    key_agreement = keypairs['key_agreement']
    assertion_method = keypairs['assertion_method']
    capability_delegation = keypairs['capability_delegation']
    
    # Prepare service endpoints
    if did_service_endpoint is None:
        did_service_endpoint = [{
            'id': '#my-service',
            'type': ['service-type'],
            'service_endpoint': ['https://www.example.com']
        }]

    # Get transaction for creating the DID
    did_creation_tx = await get_store_tx(
        {
            'authentication': [authentication],
            'key_agreement': [key_agreement],
            'assertion_method': [assertion_method],
            'capability_delegation': [capability_delegation],
            'service': did_service_endpoint,
        },
        submitter_account.ss58_address,
        lambda data: {
            'signature': authentication.sign(data),
            'key_type': crypto_type_map.get(authentication.crypto_type, 'unknown'),
        }
    )

    # Sign and submit the transaction
    extrinsic = api.create_signed_extrinsic(did_creation_tx, submitter_account)
    api.submit_extrinsic(extrinsic, wait_for_inclusion=True)
    

    # Retrieve the DID URI and document
    did_uri = get_did_uri_from_key(authentication)
    print(did_uri)
    encoded_did = api.runtime_call('didApi','query' ,to_chain(did_uri))
    document = linked_info_from_chain(encoded_did)

    if not document:
        raise Exception('DID was not successfully created.')

    print(document)

    return {'mnemonic': mnemonic, 'document': document}