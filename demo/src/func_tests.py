import asyncio
import packages.sdk.src as Cord
from utils.create_account import create_account
from utils.create_authorities import add_network_member
from utils.create_registrar import set_registrar, set_identity, request_judgement, provide_judgement
import logging
import logging
from pprint import pformat
from colorama import Fore, Style, init

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
    
    logger.info(f'🏦  Issuer ({issuer_did["assertion_method"][0]["type"]}): {issuer_did["uri"]}')
    
        
    conforming_did_document = Cord.Did.did_document_exporter.export_to_did_document(issuer_did,'application/json')
    formatted_obj = pformat(conforming_did_document)
    logger.info(Fore.GREEN + formatted_obj + Style.RESET_ALL)

    # # Create Delegate One DID
    # delegate_one = await Cord.Did.create_did(author_identity)
    # delegate_one_mnemonic = delegate_one.get('mnemonic')
    # delegate_one_did = delegate_one.get('document')

    # logger.info(f'🏛  Delegate ({delegate_one_did["assertion_method"][0]["type"]}): {delegate_one_did["uri"]}')

    # # Create Delegate Two DID
    # delegate_two = await Cord.Did.create_did(author_identity)
    # delegate_two_mnemonic = delegate_two.get('mnemonic')
    # delegate_two_did = delegate_two.get('document')

    # logger.info(f'🏦  Delegate ({delegate_two_did["assertion_method"][0]["type"]}): {delegate_two_did["uri"]}')
    # # Create Delegate 3 DID
    # delegate_three = await Cord.Did.create_did(author_identity)
    # delegate_three_mnemonic = delegate_three.get('mnemonic')
    # delegate_three_did = delegate_three.get('document')

    # logger.info(f'🏦  Delegate ({delegate_three_did["assertion_method"][0]["type"]}): {delegate_three_did["uri"]}')

    # logger.info('✅ Identities created!')

    # Step 3: Create a new Chain Space
    logger.info('\n❄️  Chain Space Creation')
    space_properties = await Cord.Chainspace.build_from_properties(issuer_did['uri'])
    logger.info(space_properties)

if __name__ == "__main__":
    asyncio.run(main())
