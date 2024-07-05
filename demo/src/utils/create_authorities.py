import packages.sdk.src as Cord
import asyncio
from substrateinterface.exceptions import SubstrateRequestException


async def failproof_submit(tx, submitter):
    try:
        # Submit transaction and wait for inclusion
        api = Cord.ConfigService.get('api')
        receipt = api.submit_extrinsic(tx, wait_for_inclusion=True)
        if not receipt.is_success:
            raise SubstrateRequestException("Transaction failed")
    except SubstrateRequestException as e:
        waiting_time = 6  # 6 seconds
        print(f"First submission failed. Waiting {waiting_time * 1000} ms before retrying. Exception: {e}")
        await asyncio.sleep(waiting_time)
        print("Retrying...")

        nonce = api.get_account_nonce(submitter.ss58_address)
        signed_tx = api.create_signed_extrinsic(call=tx.call, keypair=submitter, nonce=nonce)

        try:
            receipt = api.submit_extrinsic(signed_tx, wait_for_inclusion=True)
            if not receipt.is_success:
                raise SubstrateRequestException("Transaction failed")
        except SubstrateRequestException as e:
            print(f"Second submission failed: {e}")

async def add_network_member(author_account, authority):
    api = Cord.ConfigService.get('api')
    call_tx = api.compose_call(
        call_module='NetworkMembership',
        call_function='nominate',
        call_params={'authority': authority, 'immediate': False}
    )

    # sudo_tx = api.compose_call(
    #     call_module='Sudo',
    #     call_function='sudo',
    #     call_params={'call': call_tx}
    # )

    # extrinsic = api.create_signed_extrinsic(call=sudo_tx, keypair=author_account)

    # await failproof_submit(extrinsic, author_account)