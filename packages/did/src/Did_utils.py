from packages.utils.src.crypto_utils import blake2_as_u8a, encode_address
from packages.utils.src.ss58_format import ss58_format
from packages.utils.src import data_utils
from packages.utils.src.SDKErrors import Errors
import re

# The latest version for DIDs.
DID_LATEST_VERSION = 1

# Matches the following DIDs
# - did:cord:<cord_address>
# - did:cord:<cord_address>#<fragment>
CORD_DID_REGEX = re.compile('^did:cord:(?P<address>3[1-9a-km-zA-HJ-NP-Z]{47})(?P<fragment>#[^#\n]+)?$')

def parse(did_uri: str):
    """
    Parses a CORD DID uri and returns the information contained within in a structured form.

    :param did_uri: A CORD DID uri as a string.
    :return: Object containing information extracted from the DID uri.
    """
    matches = CORD_DID_REGEX.match(did_uri)
    
    if matches:
        matches_dict = matches.groupdict()
        version_string = matches_dict.get("version")
        fragment = matches_dict.get("fragment")
        address = matches_dict.get("address")
        version = int(version_string) if version_string else DID_LATEST_VERSION

        return {
            "did": did_uri.replace(fragment or '', ''),
            "version": version,
            "type": "full",
            "address": address,
            "fragment": None if fragment == "#" else fragment,
        }

    raise Errors.InvalidDidFormatError(did_uri)


def is_same_subject(did_a: str, did_b: str) -> bool:
    """
    Returns true if both did_a and did_b refer to the same DID subject, i.e., whether they have the same identifier as specified in the method spec.
    
    @param did_a: A CORD DID URI as a string.
    @param did_b: A second CORD DID URI as a string.
    @returns: Whether did_a and did_b refer to the same DID subject.
    """
    return parse(did_a)['address'] == parse(did_b)['address']


def validate_uri(input, expect_type=None):
    """
    Checks that a string (or other input) is a valid CORD DID uri with or without a URI fragment.
    Throws otherwise.

    :param input: Arbitrary input.
    :param expect_type: 'ResourceUri' if the URI is expected to have a fragment (following '#'), 
                        'Did' if it is expected not to have one. Default allows both.
    """
    if not isinstance(input, str):
        raise TypeError(f"DID string expected, got {type(input).__name__}")
    
    parsed = parse(input)
    address = parsed['address']
    fragment = parsed.get('fragment')

    if fragment and (expect_type == 'Did' or (isinstance(expect_type, bool) and not expect_type)):
        raise Errors.DidError(
            'Expected a CORD DidUri but got a DidResourceUri (containing a #fragment)'
        )

    if not fragment and expect_type == 'ResourceUri':
        raise Errors.DidError(
            'Expected a CORD DidResourceUri (containing a #fragment) but got a DidUri'
        )

    data_utils.verify_cord_address(address)

def get_address_by_key(key) -> str:
    """
    Internal: derive the address part of the DID when it is created from the authentication key.

    :param public_key: The public key.
    :param key_type: The type of the key.
    :return: The expected address of the DID.
    """
    public_key = key.public_key
    key_type = key.crypto_type
    if key_type in [0, 1]:
        return encode_address(public_key, ss58_format)

    # Otherwise it’s ecdsa.
    address = blake2_as_u8a(public_key) if len(public_key) > 32 else public_key
    return encode_address(address, ss58_format)

def get_did_uri(did_or_address) -> str:
    """
    Builds the URI an account will have after it’s stored on the blockchain.

    :param did_or_address: The URI of the account. Internally it’s used with the DID "address" as well.
    :return: The expected DID URI.
    """
    if data_utils.is_cord_address(did_or_address):
        address = did_or_address
    else:
        address = parse(did_or_address)['address']
    
    return f"did:cord:{address}"


def get_did_uri_from_key(key) -> str:
    """
    Builds the URI of a DID if it is created with the authentication key provided.

    :param key: The key that will be used as DID authentication key.
    :return: The expected DID URI.
    """
    address = get_address_by_key(key)
    return get_did_uri(address)