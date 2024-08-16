from packages.utils.src.SDKErrors import Errors
from packages.sdk.src import ConfigService, Did, Utils
from packages.identifier.src.identifier import (
    uri_to_identifier,
    identifier_to_uri,
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
            },
        )

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


async def dispatch_revise_rating_to_chain(
    rating_entry, author_account, authorization_uri, sign_callback
):
    """
    Dispatches a request to revise an existing rating entry on the blockchain.

    This asynchronous function handles the process of revising a rating entry that is already stored on the blockchain.
    It first checks whether the specified rating entry exists on the blockchain. If it does, the function simply returns
    the existing entry's URI. If the rating entry is not stored, it proceeds to dispatch a revised version of the rating
    to the blockchain. This involves creating and signing a transaction for the revised rating, and then submitting this
    transaction to the blockchain.

    :param rating_entry: The revised rating entry object to be dispatched, including the entry's details and its unique URI.
    :param author_account: The blockchain account of the author, used for signing the transaction.
    :param authorization_uri: The URI that provides authorization context for the rating revision dispatch.
    :param sign_callback: A callback function for signing the extrinsic (blockchain transaction).

    :return: The URI of the revised rating entry. If the entry was already on the chain, it returns the existing URI.
    :raises CordDispatchError: If there's an error during the dispatch process, such as issues with signing, transaction creation, or submission.
    """

    try:
        api = ConfigService.get("api")
        authorization_id = uri_to_identifier(authorization_uri)
        ref_entry_id = uri_to_identifier(rating_entry["entry"]["reference_id"])

        exists = await is_rating_stored(rating_entry["entry_uri"])
        if exists:
            return rating_entry["entry_uri"]

        tx = api.compose_call(
            call_module="NetworkScore",
            call_function="revise_rating",
            call_params={
                "entry": rating_entry["entry"],
                "digest": rating_entry["entry_digest"],
                "message_id": rating_entry["message_id"],
                "debit_ref_id": ref_entry_id,
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
        error_message = (
            str(error) if isinstance(error, Exception) else json.dumps(error)
        )
        raise Errors.CordDispatchError(
            f'Error dispatching to chain: "{error_message}".'
        )
    

def decode_rating_value(encoded_rating, mod = 10):
    return encoded_rating / mod

def decode_entry_details_from_chain(
    encoded,
    stmt_uri,
    time_zone = 'GMT'
):
    """
    Decodes detailed information of a rating entry from its encoded blockchain representation.

    This function translates the encoded rating entry data retrieved from the blockchain
    into a more readable and structured format. It extracts various pieces
    of information from the encoded entry, such as entity UID, provider UID, and rating type,
    and decodes them using utility functions. It also handles conditional data like reference IDs
    and converts timestamps into a readable datetime format based on the specified timezone.

    :param encoded: The encoded rating entry data as retrieved from the blockchain.
    :param stmt_uri: The URI of the statement associated with the rating entry.
    :param time_zone: The timezone to use for converting timestamp data (default is 'GMT').

    :return: The decoded rating entry details in a structured format.
    """

    chain_entry = encoded.value
    encoded_entry = chain_entry["entry"]

    decoded_entry = {
        'entity_id': encoded_entry["entity_id"],
        'provider_id': encoded_entry["provider_id"],
        'rating_type': encoded_entry["rating_type"],
        'count_of_txn': encoded_entry["count_of_txn"],
        'total_rating': decode_rating_value(encoded_entry["total_encoded_rating"])
    }

    reference_id = None
    if chain_entry["reference_id"] is not None:
        reference_id = identifier_to_uri(chain_entry["reference_id"])

    decoded_details = {
        'entry_uri': identifier_to_uri(stmt_uri),
        'entry': decoded_entry,
        'digest': chain_entry["digest"],
        'message_id': chain_entry["message_id"],
        'space': identifier_to_uri(chain_entry["space"]),
        'creator_uri': Did.from_chain(chain_entry["creator_id"]),
        'entry_type': chain_entry["entry_type"],
        'reference_id': reference_id,
        'created_at': Utils.data_utils.convert_unix_time_to_date_time(
            chain_entry["created_at"]/1000.0,  # Convert to seconds from milliseconds
            time_zone
        ),
    }

    return decoded_details
    


async def fetch_rating_details_from_chain(rating_uri, time_zone):
    """
    Fetches and decodes the details of a specific rating entry from the blockchain.

    This asynchronous function retrieves a rating entry from the blockchain using its URI.
    It translates the blockchain's encoded rating entry into a more readable and structured format.
    If the rating entry is found, it decodes the details using the `decode_entry_details_from_chain` function.
    If the entry does not exist on the blockchain, the function returns None.

    :param rating_uri: The URI of the rating entry to be fetched from the blockchain.
    :param time_zone: The timezone to be used for date and time conversions (default is 'GMT').

    :return: The decoded rating entry details or None if not found.
    """

    api = ConfigService.get("api")
    rtng_id = uri_to_identifier(rating_uri)

    chain_entry = api.query("NetworkScore", "RatingEntries", [rtng_id])
    if chain_entry.value is None:
        return None
    
    entry_details = decode_entry_details_from_chain(chain_entry, rating_uri, time_zone)

    return entry_details


async def fetch_entity_aggregate_score_from_chain(
    entity,
    rating_type = None
):
    """
    Fetches and aggregates scores for a specific entity from the blockchain.

    This asynchronous function retrieves aggregate score data for a given entity from the blockchain.
    If a specific rating type is provided, it fetches the aggregate score for that rating type. Otherwise,
    it fetches aggregate scores across all rating types. The function decodes the retrieved data into a readable
    and structured format. This function is crucial for analyzing and presenting an overview of how an entity is 
    rated across different parameters or overall.

    Args:
        entity (str): The identifier of the entity for which aggregate scores are to be fetched.
        rating_type (Optional[str]): (Optional) The specific rating type to fetch the aggregate score for.

    Returns:
        A list of aggregate score objects, or None if no data is found.

    Example:
        entity_id = 'entity123'
        rating_type = 'overall'
        
        aggregate_scores = await fetch_entity_aggregate_score_from_chain(entity_id, rating_type)
        if aggregate_scores:
            print('Aggregate Scores:', aggregate_scores)
        else:
            print('No aggregate scores found for the specified entity and rating type.')
    """
    api = ConfigService.get('api')
    decoded_entries = []

    if rating_type is not None:
        specific_item = api.query("NetworkScore", "AggregateScores", [entity, rating_type])
        if specific_item.value is not None:
            value = specific_item.value
            decoded_entries.append({
                'entity_id': entity,
                'rating_type': rating_type,
                'count_of_txn': value["count_of_txn"],
                'total_rating': decode_rating_value(value["total_encoded_rating"])
            })
    else:
        entries = api.query_map("NetworkScore", "AggregateScores", [entity])
    
        for composite_key, option_value in entries:
            if option_value.value is not None:
                value = option_value.value
                
                decoded_entries.append({
                    'entity_id': entity,
                    'rating_type': composite_key.value,
                    'count_of_txn': value["count_of_txn"],
                    'total_rating': decode_rating_value(value["total_encoded_rating"])
                })

    return decoded_entries if decoded_entries else None