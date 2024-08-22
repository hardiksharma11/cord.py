from packages.sdk.src import ConfigService, Did, Utils
from packages.identifier.src.identifier import (
    uri_to_identifier,
    build_statement_uri,
    uri_to_statement_id_and_digest
)
from packages.utils.src.SDKErrors import Errors


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
    id_digest = "0x" + Utils.crypto_utils.blake2_as_hex(concatenated_data)

    return build_statement_uri(id_digest, digest)


async def is_statement_stored(digest: str, space_uri: str) -> bool:
    """
    Checks if a statement is stored on the CORD blockchain.

    Args:
        digest (str): The hexadecimal string representing the digest of the statement to check.
        space_uri (str): The unique identifier of the space where the statement is expected to be stored.

    Returns:
        bool: True if the statement is stored, or False otherwise.

    Example:
        digest = '0x1234abcd...'
        space_uri = 'space:cord:example_uri'

        is_stored = await is_statement_stored(digest, space_uri)
        if is_stored:
            print('Statement is stored on the blockchain.')
        else:
            print('Statement not found.')
    """

    api = ConfigService.get("api")
    space = uri_to_identifier(space_uri)
    encoded = api.query("Statement", "IdentifierLookup", [digest, space])

    return False if encoded.value is None else True


async def prepare_extrinsic_to_register(
    stmt_entry, creator_uri, author_account, authorization_uri, sign_callback
):
    """
    This function prepares and returns a SubmittableExtrinsic for registering a statement on the blockchain.

    Args:
        stmt_entry (dict): The stmtEntry parameter is a dictionary containing information about a statement entry.
        creator_uri (str): The creatorUri parameter is a URI that identifies the creator of the statement entry.
                           It is used to authorize the transaction when preparing the extrinsic.
        author_account (Keypair): The authorAccount parameter represents the keyring pair used for signing the extrinsic
                                  transaction. This keyring pair contains the cryptographic key pair necessary for signing
                                  and verifying messages.
        authorization_uri (str): The authorizationUri parameter is a URI that represents the authorization needed for
                                 the statement entry. It is used to identify and retrieve the authorization details required
                                 for registering the statement on the chain.
        sign_callback (function): The signCallback parameter is a callback function that is used to sign the extrinsic
                                  transaction before it is submitted to the blockchain. This function typically takes care
                                  of the signing process using the private key of the account that is authorizing the transaction.

    Returns:
        dict: A SubmittableExtrinsic is being returned from the prepare_extrinsic_to_register function.
    """
    try:
        api = ConfigService.get("api")

        authorization_id = uri_to_identifier(authorization_uri)
        schema_id = (
            uri_to_identifier(stmt_entry["schema_uri"])
            if "schema_uri" in stmt_entry
            else None
        )

        exists = await is_statement_stored(
            stmt_entry["digest"], stmt_entry["space_uri"]
        )

        if exists:
            raise Errors.DuplicateStatementError(
                f"The statement is already anchored in the chain\nIdentifier: {stmt_entry['elementUri']}"
            )

        tx = api.compose_call(
            call_module="Statement",
            call_function="register",
            call_params={
                "digest": stmt_entry["digest"],
                "authorization": authorization_id,
                "schema_id": schema_id if schema_id else None,
            },
        )

        # Authorize the transaction
        extrinsic = await Did.authorize_tx(
            creator_uri, tx, sign_callback, author_account.ss58_address
        )

        return extrinsic

    except Exception as error:
        raise Errors.CordDispatchError(f"Error returning extrinsic: {error}")


async def dispatch_register_to_chain(stmt_entry, creator_uri, author_account, authorization_uri, sign_callback):
    """
    This function dispatches a statement entry to a blockchain after preparing the extrinsic
    and signing it.

    Args:
        stmt_entry (dict): The statement entry object containing the necessary information for registering the statement on the blockchain.
        creator_uri (str): The DID URI of the creator of the statement. This identifier is used to authorize the transaction.
        author_account (Keypair): The blockchain account used to sign and submit the transaction.
        authorization_uri (str): The URI of the authorization used for the statement.
        sign_callback (function): A callback function that handles the signing of the transaction.

    Returns:
        str: The element URI of the registered statement.

    Raises:
        Exception: Raised when there is an error during the dispatch process.

    Example:
        stmt_entry = {
            # ... initialization of statement properties ...
        }
        creator_uri = 'did:cord:creator_uri'
        author_account = Keypair.create_from_uri('//Alice')
        authorization_uri = 'auth:cord:example_uri'
        sign_callback = # ... implementation ...

        statement_uri = await dispatch_register_to_chain(stmt_entry, creator_uri, author_account, authorization_uri, sign_callback)
        print('Statement registered with URI:', statement_uri)
    """
    try:
        api = ConfigService.get('api')
        extrinsic = await prepare_extrinsic_to_register(
            stmt_entry,
            creator_uri,
            author_account,
            authorization_uri,
            sign_callback
        )

        extrinsic = api.create_signed_extrinsic(extrinsic, author_account)
        api.submit_extrinsic(extrinsic,wait_for_inclusion=True)

        return stmt_entry['element_uri']
    except Exception as error:
        raise Exception(f'Error dispatching to chain: "{error}".')


async def dispatch_update_to_chain(
    stmt_entry, creator_uri, author_account, authorization_uri, sign_callback
):
    """
    Dispatches a statement update transaction to the CORD blockchain.

    This function is used to update an existing statement on the blockchain.
    It first checks if the statement with the given digest and space URI already exists.
    If it does, the function constructs and submits a transaction to update the statement.
    The transaction is authorized by the creator and signed by the provided author account.

    Args:
        stmt_entry (dict): The statement entry object containing the necessary information
            for updating the statement on the blockchain. This includes the digest, element URI,
            creator URI, space URI, and optionally a schema URI.
        creator_uri (str): The DID URI of the creator of the statement. This identifier is
            used to authorize the transaction.
        author_account (object): The blockchain account used to sign and submit the transaction.
        authorization_uri (str): The URI of the authorization used for the statement.
        sign_callback (function): A callback function that handles the signing of the transaction.

    Returns:
        str: The element URI of the updated statement.

    Raises:
        CordDispatchError: Thrown when there is an error during the dispatch process,
            such as issues with constructing the transaction, signing, or submission to the blockchain.

    Example:
        stmt_entry = {
            # ... initialization of statement properties ...
        }
        creator_uri = 'did:cord:creator_uri'
        author_account = # ... initialization ...
        authorization_uri = 'auth:cord:example_uri'
        sign_callback = # ... implementation ...

        dispatch_update_to_chain(stmt_entry, creator_uri, author_account, authorization_uri, sign_callback)
        .then(statement_uri => {
            print('Statement updated with URI:', statement_uri)
        })
        .catch(error => {
            print('Error dispatching statement update to chain:', error)
        })
    """
    try:
        api = ConfigService.get('api')
        authorization_id = uri_to_identifier(authorization_uri)
        exists = await is_statement_stored(stmt_entry['digest'], stmt_entry['space_uri'])

        if exists:
            return stmt_entry['element_uri']

        stmt_id_digest = uri_to_statement_id_and_digest(stmt_entry['element_uri'])
        
        tx = api.compose_call(
            call_module='Statement',
            call_function='update',
            call_params={
                'statement_id': stmt_id_digest['identifier'],
                'new_statement_digest': stmt_entry['digest'],
                'authorization': authorization_id
            }
        )

        extrinsic = await Did.authorize_tx(
            creator_uri,
            tx,
            sign_callback,
            author_account.ss58_address
        )

        extrinsic = api.create_signed_extrinsic(extrinsic, author_account)
        api.submit_extrinsic(extrinsic, wait_for_inclusion=True)

        return stmt_entry['element_uri']
    except Exception as error:
        raise Errors.CordDispatchError(f'Error dispatching to chain: "{error}".')
