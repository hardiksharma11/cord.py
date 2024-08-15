from packages.utils.src.SDKErrors import Errors
from packages.sdk.src import ConfigService, Did, Utils
from packages.identifier.src.identifier import (
    uri_to_identifier,
    hash_to_uri,
)
import json

async def is_rating_stored(rating_uri: str) -> bool:
    """
    Checks if a specific rating is stored in the blockchain.

    This asynchronous function is used to determine whether a particular rating, identified by its URI,
    is stored in the blockchain. It queries the blockchain using a provided rating URI to verify the existence
    of the rating. This function is essential for validation processes where the presence of a rating in the blockchain
    needs to be confirmed.

    :param rating_uri: The URI of the rating entry to be checked. This URI is used to identify the rating in the blockchain.
    :return: True if the rating is found in the blockchain, False otherwise.
    :raises CordQueryError: Thrown if there's an error during the querying process, such as network issues or problems with the query construction.
    """
    try:
        api = ConfigService.get("api")
        identifier = uri_to_identifier(rating_uri)
        encoded = api.query("NetworkScore", "RatingEntries", [identifier])

        if encoded.value is None:
            return False
        return True

    except Exception as error:
        error_message = str(error)
        raise Errors.CordQueryError(f"Error querying rating entries: {error_message}")


async def dispatch_rating_to_chain(
    rating_entry, author_account, authorization_uri, sign_callback
):
    """
    Dispatches a rating entry to the blockchain.

    This asynchronous function is responsible for dispatching a rating entry to the blockchain.
    It first checks if the rating entry already exists on the blockchain. If it does, the function
    returns the existing entry's URI. If not, it creates, signs, and submits a transaction to the blockchain.

    :param rating_entry: The rating entry object that needs to be dispatched, including its details and unique URI.
    :param author_account: The blockchain account of the author, used for signing the transaction.
    :param authorization_uri: The URI that provides authorization context for the dispatch.
    :param sign_callback: A callback function for signing the extrinsic (blockchain transaction).
    :return: The URI of the rating entry. If the entry was already on the chain, it returns the existing URI.
    :raises CordDispatchError: If there's an error during the dispatch process, such as issues with signing, transaction creation, or submission.
    """
    try:
        api = ConfigService.get("api")
        authorization_id = uri_to_identifier(authorization_uri)
        exists = await is_rating_stored(rating_entry["entry_uri"])

        if exists:
            return rating_entry["entry_uri"]

        tx = api.compose_call(
            call_module="NetworkScore",
            call_function="register_rating",
            call_params={
                "entry": rating_entry["entry"],
                "digest": rating_entry["entry_digest"],
                "message_id": rating_entry["message_id"],
                "authorization": authorization_id,
            },
        )

        extrinsic = await Did.authorize_tx(
            rating_entry["author_uri"], tx, sign_callback, author_account.ss58_address
        )

        extrinsic = api.create_signed_extrinsic(extrinsic, author_account)
        api.submit_extrinsic(extrinsic, wait_for_inclusion=True)

        return rating_entry["entry_uri"]

    except Exception as error:
        error_message = str(error)
        raise Errors.CordDispatchError(
            f'Error dispatching to chain: "{error_message}".'
        )


async def dispatch_revoke_rating_to_chain(
    rating_entry,
    author_account,
    authorization_uri,
    sign_callback,
):
    """
    Dispatches a request to revoke a rating entry from the blockchain.

    This asynchronous function revokes an existing rating entry from the blockchain by verifying the signature,
    checking existence, and then creating and submitting a transaction.

    :param rating_entry: The rating entry object to be revoked, including details like the entry digest and author's signature.
    :param author_account: The blockchain account of the author, used for transaction signing.
    :param authorization_uri: The URI providing authorization context for the revocation.
    :param sign_callback: A callback function for signing the extrinsic (blockchain transaction).
    :return: The URI of the revoked rating entry.
    :raises SDKErrors.CordDispatchError: If there's an error during the dispatch process, such as non-existent rating or issues with signing.
    """
    try:
        api = ConfigService.get("api")
        authorization_id = uri_to_identifier(authorization_uri)

        # Check if the rating entry exists
        if not await is_rating_stored(rating_entry["entry"]["reference_id"]):
            raise Errors.CordDispatchError("Rating Entry not found on chain.")

        rating_entry_id = uri_to_identifier(rating_entry["entry"]["reference_id"])

        # Create the transaction to revoke the rating
        

        tx = api.compose_call(
            call_module="NetworkScore",
            call_function="revoke_rating",
            call_params={
                "entry_identifier": rating_entry_id,
                "message_id": rating_entry["message_id"],
                "digest": rating_entry["entry_digest"],
                "authorization": authorization_id,
            })

        # Authorize and sign the transaction
        extrinsic = await Did.authorize_tx(
            rating_entry["author_uri"],
            tx,
            sign_callback,
            author_account.ss58_address,  
        )

        extrinsic = api.create_signed_extrinsic(extrinsic, author_account)
        api.submit_extrinsic(extrinsic, wait_for_inclusion=True)

        return rating_entry["entry_uri"]

    except Exception as error:
        error_message = (
            str(error) if isinstance(error, Exception) else json.dumps(error)
        )
        raise Errors.CordDispatchError(
            f'Error dispatching to chain: "{error_message}".'
        )
