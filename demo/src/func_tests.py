import asyncio
import packages.sdk.src as Cord
from utils.create_account import create_account


async def main():
    network_address = 'ws://127.0.0.1:9944'
    Cord.ConfigService.set({'submitTxResolveOn': Cord.Chain.is_in_block})
    await Cord.connect(network_address)

    #Step 1: Setup Membership
    #Setup transaction author account - CORD Account.

    print('\n❄️  New Network Member')
    authority_author_identity = Cord.Utils.crypto_utils.make_keypair_from_uri('//Alice','sr25519')

    #Setup network authority account 
    account = create_account()
    authority_identity = account['account']
    crypto_type_map = {
        0: 'ed25519',
        1: 'sr25519',
        2: 'ecdsa'
    }

    # Get the crypto type as a string
    crypto_type_str = crypto_type_map.get(authority_identity.crypto_type, 'unknown')
    print(f"🏦  Member ({crypto_type_str}): {authority_identity.ss58_address}")

if __name__ == "__main__":
    asyncio.run(main())