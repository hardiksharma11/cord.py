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
from packages.utils.src.permissions import Permission


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


async def dispatch_delegate_authorization_tx(permission, space_id, delegate_id, auth_id):
    """
    Dispatches a delegate authorization request to the CORD blockchain.

    This function handles the submission of delegate authorization requests to the CORD blockchain. It manages
    the process of transaction preparation, signing, and submission, facilitating the delegation of specific
    permissions within a ChainSpace. The function ensures that the authorization is correctly dispatched to
    the blockchain with the necessary signatures.

    :param permission: The type of permission being granted.
    :param space_id: The identifier of the space to which the delegate authorization is being added.
    :param delegate_id: The decentralized identifier (DID) of the delegate receiving the authorization.
    :param auth_id: The identifier of the specific authorization transaction being constructed.
    :throws: SDKErrors.CordDispatchError - Thrown when there's an error during the dispatch process.
    """
    api = ConfigService.get("api")

    try:
        if permission == Permission.ASSERT:
            call = api.compose_call(
                call_module='ChainSpace',
                call_function='add_delegate',
                call_params={'space_id': space_id, 'delegate': delegate_id, 'authorization': auth_id}
            )
        elif permission == Permission.DELEGATE:
            call = api.compose_call(
                call_module='ChainSpace',
                call_function='add_delegator',
                call_params={'space_id': space_id, 'delegate': delegate_id, 'authorization': auth_id}
            )
        elif permission == Permission.ADMIN:
            call = api.compose_call(
                call_module='ChainSpace',
                call_function='add_admin_delegate',
                call_params={'space_id': space_id, 'delegate': delegate_id, 'authorization': auth_id}
            )
        else:
            raise Errors.InvalidPermissionError(f'Permission not valid: "{permission}".')

        return call
    except Exception as error:
        raise Errors.CordDispatchError(f'Error dispatching to chain: "{error}".')
    

async def dispatch_delegate_authorization(request, author_account, authorization_uri, sign_callback):
    """
    Dispatches a delegate authorization transaction to the CORD blockchain.

    This function manages the process of submitting a delegate authorization request to the blockchain. It checks if
    the specified authorization already exists. If it does not, the function constructs and submits a transaction to
    authorize a delegate for a specific space. The transaction is authorized by the delegator's DID and signed using
    the provided blockchain account.


    :param request: The space authorization request containing necessary information for dispatching the authorization.
    :param author_account: The blockchain account used to sign and submit the transaction.
    :param authorization_uri: The URI of the authorization used for delegating permissions.
    :param sign_callback: A callback function that handles the signing of the transaction.
    :returns: A promise resolving to the authorization ID after successful processing by the blockchain.
    :throws: SDKErrors.CordDispatchError - Thrown on error during the dispatch process.
    """
    try:
        api = ConfigService.get("api")

        space_id = uri_to_identifier(request['uri'])
        delegate_id = Did.to_chain(request['delegate_uri'])
        delegator_auth_id = uri_to_identifier(authorization_uri)

        tx = await dispatch_delegate_authorization_tx(
            request['permission'],
            space_id,
            delegate_id,
            delegator_auth_id
        )

        extrinsic = await Did.authorize_tx(
            request['delegator_uri'], tx, sign_callback, author_account.ss58_address
        )

        extrinsic = api.create_signed_extrinsic(extrinsic, keypair=author_account)
        api.submit_extrinsic(extrinsic, wait_for_inclusion=True)
        
        return request['authorization_uri']
    except Exception as error:
        raise Errors.CordDispatchError(f'Error dispatching delegate authorization: {error}')


def decode_space_details_from_chain(encoded, space_uri):
    """
    Decodes the details of a space from its blockchain-encoded representation.

    This internal function is pivotal for converting blockchain-specific encoded data into a structured
    format that aligns with the `ISpaceDetails` interface. It is used to interpret and transform data
    stored on the blockchain into a format that is more accessible and meaningful for application use.

    :param encoded: The blockchain-encoded representation of space details. This data is typically
                    stored in a format specific to the blockchain and requires decoding to be used in applications.
    :param space_uri: The unique identifier (URI) of the space. This URI helps in identifying the correct
                      space record on the blockchain for which details are to be decoded.
    :returns: An `ISpaceDetails` object containing the decoded space details, including the space URI,
              creator's DID, transaction capacity, transaction usage, approval status, and archival status.
              This structured format simplifies interaction with space data within the application context.
    """

    chain_statement = encoded.value
    decoded_details = {
        "uri": space_uri,
        "creator_uri": Did.from_chain(chain_statement['creator']),
        "txn_capacity": chain_statement['txn_capacity'],
        "txn_usage": chain_statement['txn_count'],
        "approved": chain_statement['approved'],
        "archive": chain_statement['archive'],
    }
   
    return decoded_details


async def fetch_from_chain(space_uri: str):
    """
    Fetches space details from the blockchain based on a given space URI.

    This function queries the CORD blockchain to retrieve details about a specific space, identified by the `spaceUri`.
    It decodes the blockchain data into a more accessible format. If the space details are not found or cannot be decoded,
    the function throws an error.

    :param space_uri: The unique identifier (URI) of the space to be fetched.
    :returns: A promise that resolves to the space details if found. The details include information such as
              the space URI, creator DID, transaction capacity, and other relevant data.
    :throws: SDKErrors.ChainSpaceMissingError - Thrown when no space is found with the provided URI.
             SDKErrors.CordFetchError - Thrown when an error occurs during the fetching process.

    """
    try:
        api = ConfigService.get("api")
        space_id = uri_to_identifier(space_uri)

        space_entry = api.query('ChainSpace', 'Spaces', [space_id])
        space_details = decode_space_details_from_chain(space_entry, space_uri)

        if space_details is None:
            raise Errors.ChainSpaceMissingError(
                f'There is no chain space with the provided ID "{space_uri}" present on the chain.'
            )

        return space_details
    except Exception as error:
        raise Errors.CordDispatchError(
            f'Error occurred while fetching from the chain: {error}'
        )
    
def decode_authorization_details_from_chain(encoded, authorization_uri):
    """
    Decodes the details of a space authorization from its blockchain representation.

    This internal function is crucial for translating blockchain-specific encoded data of space authorizations into
    a more user-friendly and application-oriented format. It adheres to the `ISpaceAuthorization` interface, which
    facilitates easier interaction with authorization data within applications. This process involves unwrapping the
    encoded data and reformatting it into a structured object.

    :param encoded: The encoded authorization details retrieved from the blockchain, typically in a format unique
                    to the blockchain that requires decoding for application use.
    :param authorization_uri: The unique identifier for the authorization being decoded. This ID is essential for
                              pinpointing the correct authorization record on the blockchain.
    :returns: Dictionary containing the decoded details of the space authorization. This object
              includes information such as the space URI, delegate DID, permissions granted, authorization ID, and
              delegator DID. The structured format of this object is tailored for easy integration and use within
              application workflows.
    """

    chain_auth = encoded.value
    decoded_details = {
        "uri": identifier_to_uri(chain_auth['space_id']),
        "delegate_uri": Did.from_chain(chain_auth['delegate']),
        "permission": chain_auth['permissions']['bits'],
        "authorization_uri": authorization_uri,
        "delegator_uri": Did.from_chain(chain_auth['delegator']),
    }
    
    return decoded_details


async def fetch_authorization_from_chain(authorization_uri):
    """
    Fetches authorization details from the CORD chain based on a given authorization ID.

    This function queries the CORD blockchain to retrieve details about a specific authorization, using the provided
    authorization URI. It is designed to fetch and decode the authorization details stored on the blockchain. If the
    authorization details are not found or cannot be decoded, the function throws an error.

    :param authorization_uri: The unique identifier (URI) of the authorization to be fetched.
    :returns: A promise that resolves to the authorization details if found. Includes information such as the space ID, delegate DID, permissions,
              authorization ID, and delegator DID. The function returns `null` if the authorization details are not found
              or cannot be decoded.
    :throws: SDKErrors.AuthorizationMissingError - Thrown when no authorization is found with the provided ID.
             SDKErrors.CordFetchError - Thrown when an error occurs during the fetching process, such as issues with
             network connectivity or problems querying the blockchain.
    """
    try:
        api = ConfigService.get("api")
        auth_id = uri_to_identifier(authorization_uri)
        auth_entry = api.query('ChainSpace', 'Authorizations', [auth_id])
        auth_details = decode_authorization_details_from_chain(auth_entry, authorization_uri)

        if auth_details is None:
            raise Errors.AuthorizationMissingError(
                f'There is no authorization with the provided ID "{authorization_uri}" present on the chain.'
            )

        return auth_details
    except Exception as error:
        raise Errors.CordFetchError(
            f'Error occurred while fetching authorization: {error}'
        )