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
from packages.sdk.src import Did


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
            call_params={"space_id": space_id, "txn_capacity": capacity},
        )
        sudo_tx = api.compose_call(
            call_module="Sudo", call_function="sudo", call_params={"call": call_tx}
        )

        extrinsic = api.create_signed_extrinsic(call=sudo_tx, keypair=authority)
        api.submit_extrinsic(extrinsic, wait_for_inclusion=True)
    except Exception as error:
        raise Errors.CordDispatchError(f"Error dispatching to chain: {error}")


async def prepare_create_space_extrinsic(
    chain_space, creator_uri, sign_callback, author_account
):
    """
    Prepares a ChainSpace creation transaction for the CORD blockchain.

    Args:
        chain_space (IChainSpace): The ChainSpace object containing necessary information for creating the ChainSpace on the blockchain.
        creator_uri (str): The DID URI of the creator, used to authorize the transaction.
        sign_callback (function): The callback function for signing the transaction.
        author_account (CordKeyringPair): The blockchain account used for signing and submitting the transaction.

    Returns:
        The prepared extrinsic ready to be signed and submitted.


    """
    try:
        # Retrieve the API instance from the configuration service
        api = ConfigService.get("api")

        tx = api.compose_call(
            call_module="ChainSpace",
            call_function="create",
            call_params={"space_code": chain_space["digest"]},
        )

        # Authorize the transaction using the creator's URI and the provided sign callback
        extrinsic = await Did.authorize_tx(
            creator_uri, tx, sign_callback, author_account.ss58_address
        )

        return extrinsic
    except Exception as error:
        # Raise a custom dispatch error if any exception occurs
        raise Errors.CordDispatchError(
            f"Error preparing extrinsic for creation of chainspace: {error}"
        )


async def dispatch_to_chain(chain_space, creator_uri, author_account, sign_callback):
    return_object = {
        "uri": chain_space["uri"],
        "authorization": chain_space["authorization_uri"],
    }

    try:
        # Prepare the extrinsic for creating the ChainSpace
        extrinsic = await prepare_create_space_extrinsic(
            chain_space, creator_uri, sign_callback, author_account
        )

        # Sign and submit the extrinsic transaction with the author account
        extrinsic = ConfigService.get("api").create_signed_extrinsic(
            extrinsic, keypair=author_account
        )
        ConfigService.get("api").submit_extrinsic(extrinsic, wait_for_inclusion=True)

        return return_object
    except Exception as error:
        # Raise a custom dispatch error if any exception occurs
        raise Errors.CordDispatchError(f"Error dispatching to chain: {error}")


async def dispatch_subspace_create_to_chain(
    chain_space, creator_uri, author_account, count, parent, sign_callback
):
    return_object = {
        "uri": chain_space["uri"],
        "authorization": chain_space["authorization_uri"],
    }

    try:
        api = ConfigService.get("api")

        tx = api.compose_call(
            call_module="ChainSpace",
            call_function="subspace_create",
            call_params={
                "space_code": chain_space["digest"],
                "count": count,
                "space_id": parent.replace("space:cord:", "") if parent else None,
            },
        )

        extrinsic = await Did.authorize_tx(
            creator_uri, tx, sign_callback, author_account.ss58_address
        )

        extrinsic = api.create_signed_extrinsic(extrinsic, keypair=author_account)
        api.submit_extrinsic(extrinsic, wait_for_inclusion=True)

        return return_object
    except Exception as error:
        raise Errors.CordDispatchError(f'Error dispatching to chain: "{error}".')


async def dispatch_update_tx_capacity_to_chain(
    space, creator_uri, author_account, new_capacity, sign_callback
):
    """
    Dispatches a Sub-ChainSpace update transaction capacity to the CORD blockchain.

    Responsible for updating the transaction capacity of a ChainSpace on the blockchain. It first constructs and submits a transaction to update the ChainSpace. The transaction requires authorization from the creator and is signed by the specified author account.

    :param space: The Space URI of the ChainSpace to be updated.
    :param creator_uri: The DID URI of the creator, used to authorize the transaction.
    :param author_account: The blockchain account used for signing and submitting the transaction.
    :param new_capacity: The new capacity to be set for the ChainSpace.
    :param sign_callback: The callback function for signing the transaction.
    :returns: A promise resolving to an object containing the ChainSpace URI.
    :raises SDKErrors.CordDispatchError: Thrown when there's an error during the dispatch process.
    """
    return_object = {"uri": space}

    try:
        api = ConfigService.get("api")

        tx = api.compose_call(
            call_module="ChainSpace",
            call_function="update_transaction_capacity_sub",
            call_params={
                "space_id": space.replace("space:cord:", ""),
                "new_txn_capacity": new_capacity,
            },
        )

        extrinsic = await Did.authorize_tx(
            creator_uri, tx, sign_callback, author_account.ss58_address
        )

        extrinsic = api.create_signed_extrinsic(extrinsic, keypair=author_account)
        api.submit_extrinsic(extrinsic, wait_for_inclusion=True)

        return return_object
    except Exception as error:
        raise Errors.CordDispatchError(f'Error dispatching to chain: "{error}".')


async def get_uri_for_authorization(space_uri, delegate_uri, creator_uri):
    """
    Generates a unique URI for an authorization within a ChainSpace.

    Constructs a standardized URI for an authorization entity, ensuring unambiguous referencing within the system.

    :param space_uri: The URI of the ChainSpace.
    :param delegate_uri: The DID URI of the delegate involved in the authorization.
    :param creator_uri: The DID URI of the creator of the authorization.
    :returns: A promise resolving to the unique authorization URI.
    """
    api = ConfigService.get("api")

    scale_encoded_space_id = api.encode_scale(
        type_string="Bytes", value=uri_to_identifier(space_uri)
    )
    scale_encoded_auth_delegate = api.encode_scale(
        type_string="AccountId", value=Did.to_chain(delegate_uri)
    )
    scale_encoded_auth_creator = api.encode_scale(
        type_string="AccountId", value=Did.to_chain(creator_uri)
    )

    auth_digest = blake2_as_hex(
        scale_encoded_space_id.get_remaining_bytes()
        + scale_encoded_auth_delegate.get_remaining_bytes()
        + scale_encoded_auth_creator.get_remaining_bytes()
    )

    authorization_uri = hash_to_uri(auth_digest, AUTH_IDENT, AUTH_PREFIX)

    return authorization_uri
