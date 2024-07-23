from packages.sdk.src import ConfigService
from packages.utils.src.crypto_utils import blake2_as_hex
from packages.identifier.src.identifier import hash_to_uri, uri_to_identifier, identifier_to_uri
from packages.utils.src.idents import SPACE_IDENT, AUTH_IDENT
from packages.utils.src.prefix import SPACE_PREFIX, AUTH_PREFIX
from packages.did.src.Did_chain import to_chain

async def get_uri_for_space(space_digest, creator_uri):
    
    api = ConfigService.get('api')
    scale_encoded_space_digest = api.encode_scale(type_string='H256', value=space_digest)
    scale_encoded_creator = api.encode_scale(type_string='AccountId', value=to_chain(creator_uri))

    digest = blake2_as_hex(scale_encoded_space_digest.get_remaining_bytes() + scale_encoded_creator.get_remaining_bytes())
    chain_space_uri = hash_to_uri(digest, SPACE_IDENT, SPACE_PREFIX)

    scale_encoded_auth_digest = api.encode_scale(type_string='Bytes', value=uri_to_identifier(chain_space_uri))
    scale_encoded_auth_delegate = api.encode_scale(type_string='AccountId', value=to_chain(creator_uri))

    auth_digest = blake2_as_hex(scale_encoded_auth_digest.get_remaining_bytes() + scale_encoded_auth_delegate.get_remaining_bytes())
    authorization_uri = hash_to_uri(auth_digest, AUTH_IDENT, AUTH_PREFIX)

    chain_space_details = {
        'uri': chain_space_uri,
        'authorization_uri': authorization_uri,
    }

    return chain_space_details