from .statement_chain import get_uri_for_statement
from packages.utils.src.SDKErrors import Errors
from packages.identifier.src.identifier import (
    check_identifier
)
from packages.utils.src import data_utils

def verify_data_structure(input: dict) -> None:
    """
    Verifies the data structure of a given statement entry.
    
    :param input: The statement entry object to be validated.
    :raises SDKErrors.StatementHashMissingError: If the `digest` field is missing.
    :raises SDKErrors.InvalidIdentifierError: If `spaceUri` or `schemaUri` are invalid.
    :raises ValueError: If `digest` is not a valid 256-bit hexadecimal string.
    """
    if 'digest' not in input:
        raise Errors.StatementHashMissingError()
    
    check_identifier(input['space_uri'])
    
    if 'schema_uri' in input and input['schema_uri']:
        check_identifier(input['schema_uri'])
    
    data_utils.verify_is_hex(input['digest'], 256)


def build_from_properties(digest: str, space_uri: str, creator_uri: str, schema_uri: str = None) -> dict:
    """
    Constructs a statement entry object from given properties.
    
    :param digest: The hexadecimal string representing the digest of the statement.
    :param space_uri: The URI of the ChainSpace associated with the statement.
    :param creator_uri: The DID URI of the statement's creator.
    :param schema_uri: The URI of the schema linked to the statement (optional).
    :returns: A fully constructed statement entry object.
    :raises Various errors from `verify_data_structure` if validation fails.
    """
    stmt_uri = get_uri_for_statement(digest, space_uri, creator_uri)
    
    statement = {
        'element_uri': stmt_uri,
        'digest': digest,
        'creator_uri': creator_uri,
        'space_uri': space_uri,
        'schema_uri': schema_uri if schema_uri else None,
    }
    
    verify_data_structure(statement)
    return statement