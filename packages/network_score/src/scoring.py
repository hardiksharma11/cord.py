from packages.utils.src.SDKErrors import Errors
import re
from packages.sdk.src import ConfigService, Did, Utils
from packages.identifier.src.identifier import (
    uri_to_identifier,
    hash_to_uri,
)
from packages.utils.src.idents import RATING_IDENT
from packages.utils.src.prefix import RATING_PREFIX


class RatingTypeOf:
    overall = "Overall"
    delivery = "Delivery"


def validate_required_fields(fields):
    """
    Validates that none of the provided fields are empty.

    This utility function checks if any field in the given list is None or an empty string.
    If any such field is found, it raises an error indicating that required fields cannot be empty.

    :param fields: A list of fields to be validated.
    :raises RatingPropertiesError: If any field is empty (None or empty string).
    """

    def is_field_empty(field):
        return field is None or field == ""

    if any(is_field_empty(field) for field in fields):
        raise Errors.RatingPropertiesError("Required fields cannot be empty.")


def validate_hex_string(entry_digest):
    """
    Validates that a given string is a valid hexadecimal format.

    This function checks if the provided string matches the pattern of a hexadecimal string (prefixed with '0x').
    If the string does not match the expected format, it raises an error.

    :param entry_digest: The string to be validated as a HexString.
    :raises RatingPropertiesError: If the string is not in a valid hexadecimal format.
    """
    hex_pattern = re.compile(r"^0x[0-9a-fA-F]+$")
    if not hex_pattern.match(entry_digest):
        raise Errors.RatingPropertiesError("Invalid HexString for entryDigest.")


async def get_uri_for_rating_entry(
    entry_digest: str,
    entity_id: str,
    entry_msg_id: str,
    chain_space: str,
    provider_uri: str,
) -> str:
    """
    Generates a unique URI for a rating entry based on various input parameters.

    This function takes the digest of a rating entry, along with other identifying information,
    and generates a unique URI for that entry. It involves several steps: encoding input parameters
    into SCALE (Simple Concatenated Aggregate Little-Endian) format, combining these encoded values,
    hashing the combined result, and then formatting it as a URI.

    :param entry_digest: The hex string representation of the rating entry's digest.
    :param entity_id: The unique identifier of the entity associated with the rating entry.
    :param entry_msg_id: The message ID associated with the rating entry.
    :param chain_space: The identifier of the chain space where the rating is stored.
    :param provider_uri: The DID URI of the provider associated with the rating entry.
    :return: A unique URI for the rating entry.
    """
    api = ConfigService.get("api")

    scale_encoded_rating_entry_digest = api.encode_scale(
        "H256", entry_digest
    ).get_remaining_bytes()
    scale_encoded_entity_uid = api.encode_scale(
        "Bytes", entity_id
    ).get_remaining_bytes()
    scale_encoded_message_id = api.encode_scale(
        "Bytes", entry_msg_id
    ).get_remaining_bytes()
    scale_encoded_chain_space = api.encode_scale(
        "Bytes", uri_to_identifier(chain_space)
    ).get_remaining_bytes()
    scale_encoded_provider = api.encode_scale(
        "AccountId", Did.to_chain(provider_uri)
    ).get_remaining_bytes()

    combined_encoded = (
        scale_encoded_rating_entry_digest
        + scale_encoded_entity_uid
        + scale_encoded_message_id
        + scale_encoded_chain_space
        + scale_encoded_provider
    )

    digest = Utils.crypto_utils.blake2_as_hex(combined_encoded)

    return hash_to_uri(digest, RATING_IDENT, RATING_PREFIX)


async def create_rating_object(
    entry_digest,
    entity_id,
    message_id,
    chain_space,
    provider_uri,
    author_uri,
):
    """
    Creates a rating object with a unique rating URI and common details.

    This function generates a unique URI for a rating entry using several key pieces of information.
    It also constructs an object containing common details of the rating entry, including the
    generated URI, chain space, message ID, entry digest, author's URI, and the author's digital signature.

    :param entry_digest: The hex string representation of the rating entry's digest.
    :param entity_id: The unique identifier of the entity associated with the rating entry.
    :param message_id: The message ID associated with the rating entry.
    :param chain_space: The identifier of the chain space where the rating is stored.
    :param provider_uri: The DID URI of the provider associated with the rating entry.
    :param author_uri: The DID URI of the author who signed the rating entry.
    :returns: A dictionary containing the rating entry URI and its details.
    """
    rating_uri = await get_uri_for_rating_entry(
        entry_digest, entity_id, message_id, chain_space, provider_uri
    )

    return {
        "uri": rating_uri,
        "details": {
            "entry_uri": rating_uri,
            "chain_space": chain_space,
            "message_id": message_id,
            "entry_digest": entry_digest,
            "author_uri": author_uri,
        },
    }


async def build_from_rating_properties(rating, chain_space, author_uri):
    """
    Constructs a rating entry for dispatch to a blockchain, complete with validation and digital signature.

    This function processes a raw rating entry, validates its content, signs it, and generates a unique URI for it.
    It is primarily used to ensure that the ratings produced are valid, signed, and ready for dispatch to the blockchain.

    :param rating: The raw rating entry including all necessary details like entityId, messageId, entryDigest, and providerSignature.
    :param chain_space: Identifier for the blockchain space where the rating will be stored.
    :param author_uri: The DID URI of the author used for signing the rating.
    :return: A dictionary containing:
        - `uri`: A unique URI representing the rating entry on the blockchain.
        - `details`: An object containing the processed rating entry details ready for dispatch.
    :raises RatingPropertiesError: If there's an issue with the rating's content, signature, or any required fields.
    """
    try:
        # Validate required fields and hex string format
        validate_required_fields(
            [
                chain_space,
                author_uri,
                rating["message_id"],
                rating["entry_digest"],
                rating["entry"]["entity_id"],
                rating["entry"]["provider_did"],
            ]
        )
        validate_hex_string(rating["entry_digest"])

        # Generate the rating object with URI and details
        result = await create_rating_object(
            rating["entry_digest"],
            rating["entry"]["entity_id"],
            rating["message_id"],
            chain_space,
            Did.get_did_uri(rating["entry"]["provider_did"]),
            author_uri,
        )
        uri = result["uri"]
        details = result["details"]

        details["entry"] = rating["entry"]
        return {"uri": uri, "details": details}

    except Exception as error:
        raise Errors.RatingPropertiesError(
            f'Rating content transformation error: "{error}".'
        )


async def build_from_revoke_rating_properties(rating, chain_space, author_uri):
    """
    Constructs a revocation entry for a previously submitted rating on the blockchain.

    This function processes a rating revocation entry, verifies the original rating's signature,
    validates required fields, and generates the necessary signatures for the revocation entry.

    :param rating: The rating revoke entry to process, including the original rating's digest, signature, and other details.
    :param chain_space: The identifier of the blockchain space where the rating is being revoked.
    :param author_uri: The DID URI of the author who is revoking the rating.
    :return: A dictionary containing the unique URI for the revocation entry and its details.
    :raises RatingPropertiesError: If there is an issue with the revocation's content or signature verification.
    """
    try:
        validate_required_fields(
            [
                chain_space,
                author_uri,
                rating["entry"]["message_id"],
                rating["entry"]["entry_digest"],
            ]
        )
        validate_hex_string(rating["entry"]["entry_digest"])

        result = await create_rating_object(
            rating["entry"]["entry_digest"],
            rating["entity_id"],
            rating["entry"]["message_id"],
            chain_space,
            rating["provider_did"],
            author_uri,
        )

        result["details"]["entry"] = rating["entry"]
        return result

    except Exception as error:
        raise Errors.RatingPropertiesError(
            f'Rating content transformation error: "{error}".'
        )


async def build_from_revise_rating_properties(rating, chain_space, author_uri):
    """
    Constructs a revised entry for a previously amended rating on the blockchain.

    This function is responsible for building a rating object from revised rating properties.
    It verifies the signature of the amended rating, validates required fields, and generates
    the necessary signatures for the revised entry.

    :param rating: The rating revise entry to process, including the original rating's digest, signature, and other relevant details.
    :param chain_space: The identifier of the blockchain space (as a URI) where the rating is being revised.
    :param author_uri: The Decentralized Identifier (DID) URI of the author who is revising the rating.

    :return: A dictionary containing the URI of the rating entry and its details.
    :raises RatingPropertiesError: If there is an error during the transformation process.
    """
    try:
        validate_required_fields(
            [
                chain_space,
                author_uri,
                rating["entry"]["entity_id"],
                rating["entry"]["provider_id"],
                rating["reference_id"],
                rating["entry"]["count_of_txn"],
                rating["entry"]["total_encoded_rating"],
            ]
        )
        validate_hex_string(rating["entry_digest"])

        result = await create_rating_object(
            rating["entry_digest"],
            rating["entry"]["entity_id"],
            rating["message_id"],
            chain_space,
            Did.get_did_uri(rating["entry"]["provider_did"]),
            author_uri,
        )

        uri = result["uri"]
        details = result["details"]

        details["entry"] = rating["entry"]
        return {"uri": uri, "details": details}

    except Exception as error:
        raise Errors.RatingPropertiesError(
            f'Rating content transformation error: "{error}".'
        )
