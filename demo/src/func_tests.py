import asyncio
import packages.sdk.src as Cord
from utils.create_account import create_account
from utils.create_authorities import add_network_member
from utils.create_registrar import (
    set_registrar,
    set_identity,
    request_judgement,
    provide_judgement,
)
import logging
import logging
from pprint import pformat
from colorama import Fore, Style, init
import json
import uuid
from datetime import datetime,timezone

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def main():
    network_address = "ws://127.0.0.1:9944"
    Cord.ConfigService.set({"submitTxResolveOn": Cord.Chain.is_in_block})
    await Cord.connect(network_address)

    # Step 1: Setup Membership
    # Setup transaction author account - CORD Account.

    logger.info("❄️  New Network Member")
    authority_author_identity = Cord.Utils.crypto_utils.make_keypair_from_uri(
        "//Alice", "sr25519"
    )

    # Setup network authority account
    authority_account = create_account()
    authority_identity = authority_account["account"]
    crypto_type_map = {0: "ed25519", 1: "sr25519", 2: "ecdsa"}

    # Get the crypto type as a string
    crypto_type_str = crypto_type_map.get(authority_identity.crypto_type, "unknown")
    logger.info(f"🏦  Member ({crypto_type_str}): {authority_identity.ss58_address}")

    await add_network_member(authority_author_identity, authority_identity.ss58_address)
    await set_registrar(authority_author_identity, authority_identity.ss58_address)
    logger.info("✅ Network Authority created!")

    # Setup network member account.
    author_account = create_account()
    author_identity = author_account["account"]
    logger.info(
        f"🏦  Member ({crypto_type_map.get(author_identity.crypto_type, 'unknown')}): {author_identity.ss58_address}"
    )
    await add_network_member(authority_author_identity, author_identity.ss58_address)
    logger.info("🔏  Member permissions updated")
    await set_identity(author_identity)
    logger.info("🔏  Member identity info updated")
    await request_judgement(author_identity, authority_identity.ss58_address)
    logger.info("🔏  Member identity judgement requested")
    await provide_judgement(authority_author_identity, author_identity.ss58_address)
    logger.info("🔏  Member identity judgement provided")
    logger.info("✅ Network Member added!")

    # Step 2: Setup Identities
    logger.info("❄️  Demo Identities (KeyRing)")

    # Creating the DIDs for the different parties involved in the demo.
    # Create Verifier DID
    verifier = await Cord.Did.create_did(author_identity)
    verifier_mnemonic = verifier.get("mnemonic")
    verifier_did = verifier.get("document")

    logger.info(
        f'🏢  Verifier ({verifier_did["assertion_method"][0]["type"]}): {verifier_did["uri"]}'
    )

    # Create Holder DID
    holder = await Cord.Did.create_did(author_identity)
    holder_mnemonic = holder.get("mnemonic")
    holder_did = holder.get("document")

    logger.info(
        f'👩‍⚕️  Holder ({holder_did["assertion_method"][0]["type"]}): {holder_did["uri"]}'
    )

    # Create Issuer DID
    issuer = await Cord.Did.create_did(author_identity)
    issuer_mnemonic = issuer.get("mnemonic")
    issuer_did = issuer.get("document")
    issuer_keys = Cord.Did.generate_keypairs(issuer_mnemonic, "sr25519")

    logger.info(
        f'🏦  Issuer ({issuer_did["assertion_method"][0]["type"]}): {issuer_did["uri"]}'
    )

    conforming_did_document = Cord.Did.did_document_exporter.export_to_did_document(
        issuer_did, "application/json"
    )

    logger.info(Fore.GREEN + pformat(conforming_did_document) + Style.RESET_ALL)

    # Create Delegate One DID
    delegate_one = await Cord.Did.create_did(author_identity)
    delegate_one_mnemonic = delegate_one.get('mnemonic')
    delegate_one_did = delegate_one.get('document')

    logger.info(f'🏛  Delegate ({delegate_one_did["assertion_method"][0]["type"]}): {delegate_one_did["uri"]}')

    # Create Delegate Two DID
    delegate_two = await Cord.Did.create_did(author_identity)
    delegate_two_mnemonic = delegate_two.get('mnemonic')
    delegate_two_did = delegate_two.get('document')
    delegate_two_keys = Cord.Did.generate_keypairs(delegate_two_mnemonic, "sr25519")

    logger.info(f'🏦  Delegate ({delegate_two_did["assertion_method"][0]["type"]}): {delegate_two_did["uri"]}')
    # Create Delegate 3 DID
    delegate_three = await Cord.Did.create_did(author_identity)
    delegate_three_mnemonic = delegate_three.get('mnemonic')
    delegate_three_did = delegate_three.get('document')

    logger.info(f'🏦  Delegate ({delegate_three_did["assertion_method"][0]["type"]}): {delegate_three_did["uri"]}')

    logger.info('✅ Identities created!')

    # Step 3: Create a new Chain Space
    logger.info("❄️  Chain Space Creation")
    space_properties = await Cord.Chainspace.build_from_properties(issuer_did["uri"])
    logger.info(Fore.GREEN + pformat(space_properties) + Style.RESET_ALL)

    logger.info("\n❄️  Chain Space Properties ")
    space = await Cord.Chainspace.dispatch_to_chain(
        space_properties,
        issuer_did["uri"],
        author_identity,
        lambda data: {
            "signature": issuer_keys["authentication"].sign(data["data"]),
            "key_type": issuer_keys["authentication"].crypto_type,
        },
    )
    logger.info(Fore.GREEN + pformat(space) + Style.RESET_ALL)
    logger.info("✅ Chain Space created!")
    logger.info("❄️  Chain Space Approval ")

    await Cord.Chainspace.sudo_approve_chain_space(
        authority_author_identity, space["uri"], 1000
    )
    logger.info("✅ Chain Space approved!")

    # Step 3.5: Subspace
    subspace_properties = await Cord.Chainspace.build_from_properties(issuer_did["uri"])
    logger.info(Fore.GREEN + pformat(subspace_properties) + Style.RESET_ALL)

    subspace = await Cord.Chainspace.dispatch_subspace_create_to_chain(
        subspace_properties,
        issuer_did["uri"],
        author_identity,
        200,
        space['uri'],
        lambda data: {
            "signature": issuer_keys["authentication"].sign(data["data"]),
            "key_type": issuer_keys["authentication"].crypto_type,
        },
    
    )
    logger.info(Fore.GREEN + pformat(subspace) + Style.RESET_ALL)
    logger.info("✅ Subspace created!")

    subspace_tx = await Cord.Chainspace.dispatch_update_tx_capacity_to_chain(
        subspace['uri'],
        issuer_did["uri"],
        author_identity,
        300,
        lambda data: {
            "signature": issuer_keys["authentication"].sign(data["data"]),
            "key_type": issuer_keys["authentication"].crypto_type,
        },
    )

    logger.info('❄️  SubSpace limit is updated')

    # Step 4: Add Delelegate Two as Registry Delegate
    logger.info("❄️  Space Delegate Authorization ")
    permission = Cord.Permission.ASSERT
    space_auth_properties = await Cord.Chainspace.build_from_authorization_properties(space["uri"],delegate_two_did["uri"],permission,issuer_did["uri"])
    logger.info(Fore.GREEN + pformat(space_auth_properties) + Style.RESET_ALL)

    logger.info('❄️  Space Delegation To Chain ')
    delegate_auth = await Cord.Chainspace.dispatch_delegate_authorization(
        space_auth_properties,
        author_identity,
        space['authorization'],
        lambda data: {
            "signature": issuer_keys["capability_delegation"].sign(data["data"]),
            "key_type": issuer_keys["capability_delegation"].crypto_type,
        },
    )
    logger.info(Fore.GREEN + pformat(delegate_auth) + Style.RESET_ALL)
    logger.info(f"✅ Space Authorization - {delegate_auth} - added!")

    logger.info('❄️  Query From Chain - Chain Space Details ')

    space_from_chain = await Cord.Chainspace.fetch_from_chain(space['uri'])
    logger.info(Fore.GREEN + pformat(space_from_chain) + Style.RESET_ALL)

    logger.info('❄️  Query From Chain - Chain Space Authorization Details ')
    space_auth_from_chain = await Cord.Chainspace.fetch_authorization_from_chain(delegate_auth)
    logger.info(Fore.GREEN + pformat(space_auth_from_chain) + Style.RESET_ALL)

    logger.info('✅ Chain Space Functions Completed!')

    # Step 5: Create a new Schema
    logger.info('❄️  Schema Creation ')
    with open('demo/res/schema.json', 'r') as file:
        new_schema_content = json.load(file)

    new_schema_name = f"{new_schema_content['title']}:{uuid.uuid4()}"
    new_schema_content['title'] = new_schema_name

    schema_properties = Cord.Schema.schema.build_from_properties(new_schema_content,space['uri'],issuer_did['uri'])
    logger.info(Fore.GREEN + pformat(schema_properties) + Style.RESET_ALL)

    schema_uri = await Cord.Schema.schema_chain.dispatch_to_chain(
        schema_properties["schema"],
        issuer_did["uri"],
        author_identity,
        space["authorization"],
        lambda data: {
            "signature": issuer_keys["authentication"].sign(data["data"]),
            "key_type": issuer_keys["authentication"].crypto_type,
        },
    )
    logger.info(f"✅ Schema - {schema_uri} - added!")

    logger.info('❄️  Query From Chain - Schema ')
    schema_from_chain = await Cord.Schema.schema_chain.fetch_from_chain(schema_properties["schema"]["$id"])
    logger.info(Fore.GREEN + pformat(schema_from_chain) + Style.RESET_ALL)
    logger.info('✅ Schema Functions Completed!')

    # Step 6: Delegate creates a new Verifiable Document
    logger.info("❄️  Statement Creation ")
    with open('demo/res/cred.json', 'r') as file:
        new_cred_content = json.load(file)

    new_cred_content['issuanceDate'] = datetime.now(timezone.utc).isoformat()
    serialized_cred = Cord.Utils.crypto_utils.encode_object_as_str(new_cred_content)
    cred_hash ='0x'+ Cord.Utils.crypto_utils.hash_str(serialized_cred.encode('utf-8'))

    logger.info(Fore.GREEN + pformat(new_cred_content) + Style.RESET_ALL)

    statement_entry = Cord.Statement.statement.build_from_properties(
        cred_hash,
        space['uri'],
        issuer_did['uri'],
        schema_uri
    )
    logger.info(Fore.GREEN + pformat(statement_entry) + Style.RESET_ALL)

    statement = await Cord.Statement.statement_chain.dispatch_register_to_chain(
        statement_entry,
        issuer_did["uri"],
        author_identity,
        space["authorization"],
        lambda data: {
            "signature": issuer_keys["authentication"].sign(data["data"]),
            "key_type": issuer_keys["authentication"].crypto_type,
        }
    )

    logger.info(f"✅ Statement element registered - {statement}")

    logger.info("❄️  Statement Updation ")
    update_cred_content = new_cred_content
    update_cred_content['issuanceDate'] = datetime.now(timezone.utc).isoformat()
    update_cred_content['name'] = 'Bachelor of Science'
    serialized_up_cred  = Cord.Utils.crypto_utils.encode_object_as_str(update_cred_content)
    up_cred_hash = '0x'+ Cord.Utils.crypto_utils.hash_str(serialized_up_cred.encode('utf-8'))

    updated_statement_entry = Cord.Statement.statement.build_from_update_properties(
        statement_entry['element_uri'],
        up_cred_hash,
        space['uri'],
        delegate_two_did['uri'],
    )

    logger.info(Fore.GREEN + pformat(updated_statement_entry) + Style.RESET_ALL)

    updated_statement = await Cord.Statement.statement_chain.dispatch_update_to_chain(
        updated_statement_entry,
        delegate_two_did['uri'],
        author_identity,
        delegate_auth,
        lambda data: {
            "signature": delegate_two_keys["authentication"].sign(data["data"]),
            "key_type": delegate_two_keys["authentication"].crypto_type,
        }
    )

    logger.info(f"✅ Statement element registered - {updated_statement}")

    logger.info("❄️  Statement verification ")
    verification_result = await Cord.Statement.statement.verify_against_properties(
        statement_entry['element_uri'],
        cred_hash,
        issuer_did['uri'],
        space["uri"],
        schema_uri
    ) 

    if(verification_result['is_valid']):
        logger.info(f"✅ Verification successful! {statement_entry['element_uri']} 🎉")
    else:
        logger.info(f"🚫 Verification failed! - {verification_result['message']} 🚫")

    another_verification_result = await Cord.Statement.statement.verify_against_properties(
        updated_statement_entry['element_uri'],
        up_cred_hash,
        delegate_two_did['uri'],
        space["uri"],
        schema_uri
    )

    if(another_verification_result['is_valid']):
        logger.info(f"✅ Verification successful! {updated_statement_entry['element_uri']} 🎉")
    else:
        logger.info(f"🚫 Verification failed! - {another_verification_result['message']} 🚫")

    logger.info(f"❄️  Revoke Statement - {updated_statement_entry['element_uri']}")

    await Cord.Statement.statement_chain.dispatch_revoke_to_chain(
        updated_statement_entry['element_uri'],
        delegate_two_did['uri'],
        author_identity,
        delegate_auth,
        lambda data: {
            "signature": delegate_two_keys["authentication"].sign(data["data"]),
            "key_type": delegate_two_keys["authentication"].crypto_type,
        }
    )

    logger.info("✅ Statement revoked!")

    logger.info("❄️  Statement Re-verification ")
    re_verification_result = await Cord.Statement.statement.verify_against_properties(
        updated_statement_entry['element_uri'],
        up_cred_hash,
        issuer_did['uri'],
        space["uri"]
    )

    if(re_verification_result['is_valid']):
        logger.info(f"✅ Verification successful! {updated_statement_entry['element_uri']} 🎉")
    else:
        logger.info(f"🚫 Verification failed! - {re_verification_result['message']} 🚫")


    logger.info(f"❄️  Restore Statement - {updated_statement_entry['element_uri']}")
    await Cord.Statement.statement_chain.dispatch_restore_to_chain(
        updated_statement_entry['element_uri'],
        delegate_two_did['uri'],
        author_identity,
        delegate_auth,
        lambda data: {
            "signature": delegate_two_keys["authentication"].sign(data["data"]),
            "key_type": delegate_two_keys["authentication"].crypto_type,
        }
    )

    logger.info("✅ Statement restored!")

    logger.info("❄️  Statement Re-verification ")
    re_verification_result = await Cord.Statement.statement.verify_against_properties(
        updated_statement_entry['element_uri'],
        up_cred_hash,
        delegate_two_did['uri'],
        space["uri"]
    )

    if(re_verification_result['is_valid']):
        logger.info(f"✅ Verification successful! {updated_statement_entry['element_uri']} 🎉")
    else:
        logger.info(f"🚫 Verification failed! - {re_verification_result['message']} 🚫")

if __name__ == "__main__":
    asyncio.run(main())
    logger.info("Bye! 👋 👋 👋 ")
    Cord.disconnect()
