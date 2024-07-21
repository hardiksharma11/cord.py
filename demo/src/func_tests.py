import asyncio
import packages.sdk.src as Cord
from utils.create_account import create_account
from utils.create_authorities import add_network_member
from utils.create_registrar import set_registrar, set_identity, request_judgement, provide_judgement
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def main():
    network_address = 'ws://127.0.0.1:9944'
    Cord.ConfigService.set({'submitTxResolveOn': Cord.Chain.is_in_block})
    await Cord.connect(network_address)

    # Step 1: Setup Membership
    # Setup transaction author account - CORD Account.

    logger.info('❄️  New Network Member')
    authority_author_identity = Cord.Utils.crypto_utils.make_keypair_from_uri('//Alice', 'sr25519')

    # Setup network authority account 
    authority_account = create_account()
    authority_identity = authority_account['account']
    crypto_type_map = {
        0: 'ed25519',
        1: 'sr25519',
        2: 'ecdsa'
    }

    # Get the crypto type as a string
    crypto_type_str = crypto_type_map.get(authority_identity.crypto_type, 'unknown')
    logger.info(f"🏦  Member ({crypto_type_str}): {authority_identity.ss58_address}")

    await add_network_member(authority_author_identity, authority_identity.ss58_address)
    await set_registrar(authority_author_identity, authority_identity.ss58_address)
    logger.info('✅ Network Authority created!')

    # Setup network member account.
    author_account = create_account()
    author_identity = author_account['account']
    logger.info(f"🏦  Member ({crypto_type_map.get(author_identity.crypto_type, 'unknown')}): {author_identity.ss58_address}")
    await add_network_member(authority_author_identity, author_identity.ss58_address)
    logger.info('🔏  Member permissions updated')
    await set_identity(author_identity)
    logger.info('🔏  Member identity info updated')
    await request_judgement(author_identity, authority_identity.ss58_address)
    logger.info('🔏  Member identity judgement requested')
    await provide_judgement(authority_author_identity, author_identity.ss58_address)
    logger.info('🔏  Member identity judgement provided')
    logger.info('✅ Network Member added!')

    # Step 2: Setup Identities
    logger.info('❄️  Demo Identities (KeyRing)')

    # Creating the DIDs for the different parties involved in the demo.
    # Create Verifier DID
    verifier = await Cord.Did.create_did(author_identity)
    verifier_mnemonic = verifier.get('mnemonic')
    verifier_did = verifier.get('document')

    logger.info(f'🏢  Verifier ({verifier_did["assertion_method"][0]["type"]}): {verifier_did["uri"]}')

    # Create Holder DID
    holder = await Cord.Did.create_did(author_identity)
    holder_mnemonic = holder.get('mnemonic')
    holder_did = holder.get('document')

    logger.info(f'👩‍⚕️  Holder ({holder_did["assertion_method"][0]["type"]}): {holder_did["uri"]}')

    # Create Issuer DID
    issuer = await Cord.Did.create_did(author_identity)
    issuer_mnemonic = issuer.get('mnemonic')
    issuer_did = issuer.get('document')
    issuer_keys = Cord.Did.generate_keypairs(issuer_mnemonic, "sr25519")
    print(issuer_keys)
    logger.info(f'🏦  Issuer ({issuer_did["assertion_method"][0]["type"]}): {issuer_did["uri"]}')

if __name__ == "__main__":
    asyncio.run(main())
