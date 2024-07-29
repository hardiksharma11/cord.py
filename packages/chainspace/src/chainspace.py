import uuid
from packages.utils.src.crypto_utils import blake2_as_hex
from .chainspace_chain import get_uri_for_space, get_uri_for_authorization
from .chainspace_chain import (
    sudo_approve_chain_space,
    dispatch_to_chain,
    dispatch_subspace_create_to_chain,
    dispatch_update_tx_capacity_to_chain,
    dispatch_delegate_authorization,
    fetch_from_chain,
    fetch_authorization_from_chain
)


async def build_from_properties(creator_uri, chain_space_desc=None):
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
        chain_space_description = f"ChainSpace v1.${uuid.uuid4()}"
    else:
        chain_space_description = chain_space_desc

    chain_space_hash = "0x" + blake2_as_hex(chain_space_description.encode())
    uri_info = await get_uri_for_space(chain_space_hash, creator_uri)

    return {
        "uri": uri_info["uri"],
        "desc": chain_space_description,
        "digest": chain_space_hash,
        "creator_uri": creator_uri,
        "authorization_uri": uri_info["authorization_uri"],
    }


async def build_from_authorization_properties(
    space_uri, delegate_uri, permission, creator_uri
):
    """
    Authorizes a delegate within a ChainSpace, allowing them to perform actions on behalf of the creator.

    This function facilitates the delegation of permissions or roles to another entity within a specific ChainSpace.
    It is instrumental in managing the decentralized governance and control within the ChainSpace, enabling
    the ChainSpace's creator or owner to grant specific permissions to a delegate.

    :param space_uri: The unique identifier (URI) of the ChainSpace for which the delegation is being set up.
    :param delegate_uri: The decentralized identifier (DID) URI of the delegate, the entity being authorized.
    :param permission: The type of permission being granted to the delegate, defining their role and actions within the ChainSpace.
    :param creator_uri: The DID URI of the ChainSpace's creator or owner, responsible for authorizing the delegate.
    :returns: A dictionary, encapsulating the details of the granted authorization.

    """
    authorization_uri = await get_uri_for_authorization(
        space_uri, delegate_uri, creator_uri
    )

    return {
        "uri": space_uri,
        "delegate_uri": delegate_uri,
        "permission": permission,
        "authorization_uri": authorization_uri,
        "delegator_uri": creator_uri,
    }
