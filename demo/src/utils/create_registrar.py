import packages.sdk.src as Cord
import asyncio
from substrateinterface.exceptions import SubstrateRequestException


async def set_registrar(authority, registrar):
    api = Cord.ConfigService.get('api')
    
    call_tx = api.compose_call(
        call_module='Identity',
        call_function='add_registrar',
        call_params={'account': registrar}
    )

    sudo_tx = api.compose_call(
        call_module='Sudo',
        call_function='sudo',
        call_params={'call': call_tx}
    )

    extrinsic = api.create_signed_extrinsic(call=sudo_tx, keypair=authority)
    api.submit_extrinsic(extrinsic, wait_for_inclusion=True)


async def set_identity(account):
    api = Cord.ConfigService.get('api')

    # Define the identity information
    identity_info = {
        'additional': [[]],
        'display': {'Raw': 'Cord_Demo'},
        'legal': {'Raw': 'CORD Demo Account'},
        'web': {'Raw': 'dhiway.com'},
        'email': {'Raw': 'engineering@dhiway.com'},
        'image': {'Raw': ''}
    }
    
    # Create the extrinsic for setting identity
    call = api.compose_call(
        call_module='Identity',
        call_function='set_identity',
        call_params={
            'info': identity_info
        }
    )
    
    # Create a signed extrinsic
    extrinsic = api.create_signed_extrinsic(
        call=call,
        keypair=account
    )

    api.submit_extrinsic(extrinsic, wait_for_inclusion=True)
    
async def request_judgement(account,registrar):
    api = Cord.ConfigService.get('api')
    
    call = api.compose_call(
        call_module='Identity',
        call_function='request_judgement',
        call_params={
            'registrar': registrar,
        }
    )
    
    extrinsic = api.create_signed_extrinsic(
        call=call,
        keypair=account
    )
    
    api.submit_extrinsic(extrinsic, wait_for_inclusion=True)


async def provide_judgement(registrar, account):
    api = Cord.ConfigService.get('api')
    identity_infos = api.query('Identity', 'IdentityOf', [account])

    
    