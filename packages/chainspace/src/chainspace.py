import uuid
from packages.utils.src.crypto_utils import blake2_as_hex
from .chainspace_chain import get_uri_for_space
from .chainspace_chain import sudo_approve_chain_space, dispatch_to_chain, dispatch_subspace_create_to_chain

async def build_from_properties(creator_uri, chain_space_desc = None):
    """
    Creates a new ChainSpace object in the CORD blockchain.

    Args:
        creator_uri (DidUri): The decentralized identifier (DID) URI of the entity creating the ChainSpace.
        chain_space_desc (Optional[str]): A custom description to represent the ChainSpace. If not provided, a default
                                          description is generated, incorporating a unique UUID.

    Returns:
        IChainSpace: A dictionary encompassing the ChainSpace's identifier, description, hash digest,
                     creator's DID, and authorization URI.
    """

    if chain_space_desc == None:
        chain_space_description = f'ChainSpace v1.${uuid.uuid4()}'
    else:
     chain_space_description = chain_space_desc

    chain_space_hash = '0x' + blake2_as_hex(chain_space_description.encode())
    uri_info = await get_uri_for_space(chain_space_hash, creator_uri)

    return {
        'uri': uri_info['uri'],
        'desc': chain_space_description,
        'digest': chain_space_hash,
        'creator_uri': creator_uri,
        'authorization_uri': uri_info['authorization_uri'],
    }
