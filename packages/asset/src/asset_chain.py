from packages.sdk.src import ConfigService, Did, Utils
from packages.identifier.src.identifier import (
    uri_to_identifier,
)
import json
from packages.utils.src.SDKErrors import Errors
from packages.utils.src.prefix import ASSET_PREFIX

async def dispatch_create_to_chain(
    asset_entry,
    author_account,
    authorization_uri,
    sign_callback
):
    try:
        api = ConfigService.get('api')
        authorization_id = uri_to_identifier(authorization_uri)

        
        tx = api.compose_call(
            call_module="Asset",
            call_function="create",
            call_params={"entry": asset_entry['entry'], "digest": asset_entry['digest'], "authorization": authorization_id},
        )

        extrinsic = await Did.authorize_tx(
            asset_entry["creator"],
            tx,
            sign_callback,
            author_account.ss58_address
        )

        extrinsic = api.create_signed_extrinsic(extrinsic, keypair= author_account)
        api.submit_extrinsic(extrinsic, wait_for_inclusion=True)

        return asset_entry["uri"]
    except Exception as error:
        error_message = str(error) if isinstance(error, Exception) else json.dumps(error)
        raise Errors.CordDispatchError(
            f'Error dispatching to chain: "{error_message}".'
        )
    
async def prepare_extrinsic(
    asset_entry,
    author_account,
    authorization_uri,
    sign_callback
):
    try:
        api = ConfigService.get('api')

        authorization_id = uri_to_identifier(authorization_uri)

        tx = api.compose_call(
            call_module='Asset',
            call_function='issue',
            call_params={
                'entry': asset_entry['entry'],
                'digest': asset_entry['digest'],
                'authorization': authorization_id
            }
        )

        extrinsic = await Did.authorize_tx(
            asset_entry['issuer'],
            tx,
            sign_callback,
            author_account.ss58_address
        )

        return extrinsic
    except Exception as error:
        error_message = str(error)
        raise Errors.CordDispatchError(
            f'Error preparing extrinsic: "{error_message}".'
        )


async def dispatch_issue_to_chain(
    asset_entry,
    author_account,
    authorization_uri,
    sign_callback
):
    try:
        api = ConfigService.get('api')
        extrinsic = await prepare_extrinsic(
            asset_entry, author_account, authorization_uri, sign_callback
        )
        extrinsic = api.create_signed_extrinsic(extrinsic, keypair=author_account)
        api.submit_extrinsic(extrinsic, wait_for_inclusion=True)

        return asset_entry['uri']
    except Exception as error:
        error_message = str(error)
        raise Errors.CordDispatchError(
            f'Error dispatching to chain: "{error_message}".'
        )

async def dispatch_transfer_to_chain(
    asset_entry,
    author_account,
    sign_callback
):
    try:
        api = ConfigService.get('api')

        tx = api.compose_call(
            call_module='Asset',
            call_function='transfer',
            call_params={'entry': asset_entry['entry'], 'digest': asset_entry['digest']}
        )

        extrinsic = await Did.authorize_tx(
            asset_entry['owner'],
            tx,
            sign_callback,
            author_account.ss58_address
        )
        extrinsic = api.create_signed_extrinsic(extrinsic, keypair=author_account)
        api.submit_extrinsic(extrinsic, wait_for_inclusion=True)

        return f"{ASSET_PREFIX}{asset_entry['entry']['asset_id']}:{asset_entry['entry']['asset_instance_id']}"
    except Exception as error:
        error_message = str(error) if isinstance(error, Exception) else json.dumps(error)
        raise Errors.CordDispatchError(
            f"Error dispatching to chain: \"{error_message}\"."
        )
