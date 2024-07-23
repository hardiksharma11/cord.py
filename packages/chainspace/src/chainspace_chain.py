from packages.sdk.src import ConfigService
from packages.utils.src.crypto_utils import blake2_as_hex
from packages.identifier.src.identifier import (
    hash_to_uri,
    uri_to_identifier,
    identifier_to_uri,
)
from packages.utils.src.idents import SPACE_IDENT, AUTH_IDENT
from packages.utils.src.prefix import SPACE_PREFIX, AUTH_PREFIX
from packages.did.src.Did_chain import to_chain
from packages.utils.src.SDKErrors import Errors


async def get_uri_for_space(space_digest, creator_uri):
    """
    Generates unique URIs for a ChainSpace and its associated authorization.

    Args:
        space_digest (str): The digest representing the content or configuration of the ChainSpace.
        creator_uri (str): The DID URI of the creator of the ChainSpace.

    Returns:
        dict: A dictionary containing the ChainSpace URI and authorization URI.


    """
    api = ConfigService.get("api")
    scale_encoded_space_digest = api.encode_scale(
        type_string="H256", value=space_digest
    )
    scale_encoded_creator = api.encode_scale(
        type_string="AccountId", value=to_chain(creator_uri)
    )

    digest = blake2_as_hex(
        scale_encoded_space_digest.get_remaining_bytes()
        + scale_encoded_creator.get_remaining_bytes()
    )
    chain_space_uri = hash_to_uri(digest, SPACE_IDENT, SPACE_PREFIX)

    scale_encoded_auth_digest = api.encode_scale(
        type_string="Bytes", value=uri_to_identifier(chain_space_uri)
    )
    scale_encoded_auth_delegate = api.encode_scale(
        type_string="AccountId", value=to_chain(creator_uri)
    )

    auth_digest = blake2_as_hex(
        scale_encoded_auth_digest.get_remaining_bytes()
        + scale_encoded_auth_delegate.get_remaining_bytes()
    )
    authorization_uri = hash_to_uri(auth_digest, AUTH_IDENT, AUTH_PREFIX)

    chain_space_details = {
        "uri": chain_space_uri,
        "authorization_uri": authorization_uri,
    }

    return chain_space_details


async def sudo_approve_chain_space(authority, space_uri, capacity):
    """
    Approves a ChainSpace on the CORD blockchain using sudo privileges.

    Args:
        authority (CordKeyringPair): The account with sudo privileges to approve the ChainSpace.
        space_uri (str): The URI of the ChainSpace to be approved.
        capacity (int): The approved capacity for the ChainSpace.

    Raises:
        SDKErrors.CordDispatchError: Thrown on error during the dispatch process.

    """
    try:
        api = ConfigService.get("api")
        space_id = uri_to_identifier(space_uri)

        call_tx = api.compose_call(
            call_module="ChainSpace",
            call_function="approve",
            call_params={"space_id": space_id, "txn_capacity": capacity}
        )
        sudo_tx = api.compose_call(
            call_module="Sudo",
            call_function="sudo",
            call_params={'call': call_tx}
        )

        extrinsic = api.create_signed_extrinsic(call=sudo_tx, keypair=authority)
        api.submit_extrinsic(extrinsic, wait_for_inclusion=True)
    except Exception as error:
        raise Errors.CordDispatchError(f"Error dispatching to chain: {error}")
