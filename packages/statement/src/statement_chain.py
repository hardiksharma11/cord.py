from packages.sdk.src import ConfigService, Did, Utils
from packages.identifier.src.identifier import (
    hash_to_uri,
    uri_to_identifier,
    build_statement_uri,
    identifier_to_uri
)


def get_uri_for_statement(digest, space_uri, creator_uri):
    """
    Generates a unique URI for a statement based on its digest, space URI, and creator URI.
    
    This function constructs a statement URI by combining the provided digest with the identifiers
    of the space and the creator. It's a crucial function for creating a standard and unique identifier
    for statements on the CORD blockchain.
    
    Args:
        digest: The hexadecimal string representing the digest of the statement.
        spaceUri: The unique identifier of the space related to the statement.
        creatorUri: The decentralized identifier (DID) URI of the creator of the statement.
    
    Returns:
        The unique URI that represents the statement on the blockchain.
    
    Example:
        digest = '0x1234abcd...'
        spaceUri = 'space:cord:example_uri'
        creatorUri = 'did:cord:creator_uri'
        
        statement_uri = get_uri_for_statement(digest, spaceUri, creatorUri)
        print('Statement URI:', statement_uri)
    """

    api = ConfigService.get("api")
    
    scale_encoded_schema = api.encode_scale(
        type_string="H256", value=digest
    ).get_remaining_bytes()
    scale_encoded_space = api.encode_scale(
        type_string="Bytes", value=uri_to_identifier(space_uri)
    ).get_remaining_bytes()
    scale_encoded_creator = api.encode_scale(
        type_string="AccountId", value=Did.to_chain(creator_uri)
    ).get_remaining_bytes()

    concatenated_data = (
        scale_encoded_schema + scale_encoded_space + scale_encoded_creator
    )
    id_digest = '0x' + Utils.crypto_utils.blake2_as_hex(concatenated_data)

    return build_statement_uri(id_digest,digest)
