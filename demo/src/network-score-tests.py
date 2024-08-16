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

    logger.info("❄️  New Network Member")
    dev_author_identity = Cord.Utils.crypto_utils.make_keypair_from_uri(
        "//Alice", "sr25519"
    )
    logger.info("🌐 Network Score Initial Setup")
    logger.info("🎎 Particpants ")
    network_author_identity = create_account()["account"]
    crypto_type_map = {0: "ed25519", 1: "sr25519", 2: "ecdsa"}

    # Get the crypto type as a string
    crypto_type_str = crypto_type_map.get(dev_author_identity.crypto_type, "unknown")
    logger.info(f"🔐 Network Member ({crypto_type_str}): {dev_author_identity.ss58_address}")

    await add_network_member(dev_author_identity, network_author_identity.ss58_address)
    logger.info("✅ Network Membership Approved! 🎉")

    chain_space_admin = await Cord.Did.create_did(network_author_identity)
    chain_space_admin_mnemonic = chain_space_admin.get("mnemonic")
    chain_space_admin_did = chain_space_admin.get("document")
    chain_space_admin_keys = Cord.Did.generate_keypairs(chain_space_admin_mnemonic, "sr25519")

    logger.info(
        f'🔐  Network Score Admin ({chain_space_admin_did["authentication"][0]["type"]}): {chain_space_admin_did["uri"]}'
    )

    network_provider = await Cord.Did.create_did(network_author_identity)
    network_provider_mnemonic = network_provider.get("mnemonic")
    network_provider_did = network_provider.get("document")
    network_provider_keys = Cord.Did.generate_keypairs(network_provider_mnemonic, "sr25519")

    logger.info(
        f'🔐  Network Participant (Provider) ({network_provider_did["authentication"][0]["type"]}): {network_provider_did["uri"]}'
    )

    network_author = await Cord.Did.create_did(network_author_identity)
    network_author_mnemonic = network_author.get("mnemonic")
    network_author_did = network_author.get("document")
    network_author_keys = Cord.Did.generate_keypairs(network_author_mnemonic, "sr25519")

    logger.info(
        f'🔐 Network Author (API -> Node) ({network_author_did["authentication"][0]["type"]}): {network_author_did["uri"]}'
    )

    logger.info("✅ Network Members created! 🎉")


    logger.info("🌐  Network Score Chain Space Creation ")
    space_properties = await Cord.Chainspace.build_from_properties(chain_space_admin_did["uri"])
    logger.info(Fore.GREEN + pformat(space_properties) + Style.RESET_ALL)

    chain_space = await Cord.Chainspace.dispatch_to_chain(
        space_properties,
        chain_space_admin_did["uri"],
        dev_author_identity,
        lambda data: {
            "signature": chain_space_admin_keys["authentication"].sign(data["data"]),
            "key_type": chain_space_admin_keys["authentication"].crypto_type,
        },
    )
    logger.info(Fore.GREEN + pformat(chain_space) + Style.RESET_ALL)
    logger.info("✅ Chain Space created! 🎉")

    await Cord.Chainspace.sudo_approve_chain_space(
        dev_author_identity, chain_space["uri"], 1000
    )

    logger.info("🌐  Chain Space Authorization (Author) ")
    permission = Cord.Permission.ASSERT
    space_auth_properties = await Cord.Chainspace.build_from_authorization_properties(chain_space["uri"],network_author_did["uri"],permission,chain_space_admin_did["uri"])
    logger.info(Fore.GREEN + pformat(space_auth_properties) + Style.RESET_ALL)

    logger.info('❄️  Space Delegation To Chain ')
    delegate_auth = await Cord.Chainspace.dispatch_delegate_authorization(
        space_auth_properties,
        network_author_identity,
        chain_space['authorization'],
        lambda data: {
            "signature": chain_space_admin_keys["capability_delegation"].sign(data["data"]),
            "key_type": chain_space_admin_keys["capability_delegation"].crypto_type,
        },
    )
    logger.info("✅ Chain Space Authorization Approved! 🎉")

    logger.info('❄️  Query From Chain - Chain Space Details ')

    space_from_chain = await Cord.Chainspace.fetch_from_chain(chain_space['uri'])
    logger.info(Fore.GREEN + pformat(space_from_chain) + Style.RESET_ALL)

    logger.info('❄️  Query From Chain - Chain Space Authorization Details ')
    space_auth_from_chain = await Cord.Chainspace.fetch_authorization_from_chain(delegate_auth)
    logger.info(Fore.GREEN + pformat(space_auth_from_chain) + Style.RESET_ALL)

    logger.info('✅ Initial Setup Completed! 🎊')

    logger.info("⏳ Network Rating Transaction Flow")
    logger.info("💠  Write Rating - (Genesis) Credit Entry ")
    rating_content = {
        "entity_id":'0x' + uuid.uuid4().hex,
        "provider_id":'0x' + uuid.uuid4().hex,
        "rating_type": Cord.Score.scoring.RatingTypeOf.overall,
        "count_of_txn": 100,
        "total_rating": 320
    }

    logger.info(Fore.GREEN + pformat(rating_content) + Style.RESET_ALL)

    entry_digest = Cord.Utils.crypto_utils.hash_object_as_hex_string(rating_content)
    total_rating = rating_content["total_rating"]
    rest_of_rating = {k: v for k, v in rating_content.items() if k != 'total_rating'}

    transformed_entry = {
        "entry": {
                **rest_of_rating,
                "provider_did": network_provider_did["uri"].replace('did:cord:', ''),
                "total_encoded_rating": round(total_rating * 10)
        },
        "message_id": '0x' + uuid.uuid4().hex,
        "entry_digest": entry_digest,
    }

    logger.info("🌐  Rating Information to API endpoint (/write-ratings) ")
    logger.info(Fore.GREEN + pformat(transformed_entry) + Style.RESET_ALL)

    dispatch_entry = await Cord.Score.scoring.build_from_rating_properties(
        transformed_entry,
        chain_space["uri"],
        network_author_did["uri"],
    )

    logger.info("🌐  Rating Information to Ledger (API -> Ledger) ")
    logger.info(Fore.GREEN + pformat(dispatch_entry) + Style.RESET_ALL)

    rating_uri = await Cord.Score.scoring_chain.dispatch_rating_to_chain(
        dispatch_entry["details"],
        network_author_identity,
        delegate_auth,
        lambda data: {
            "signature": network_author_keys["authentication"].sign(data["data"]),
            "key_type": network_author_keys["authentication"].crypto_type,
        },
    )

    if(Cord.Identifier.identifier.is_valid_identifier(rating_uri)):
        logger.info("✅ Rating addition successful! 🎉")
    else:
        logger.info("🚫 Ledger Anchoring failed! 🚫")

    logger.info("💠  Revoke Rating - Debit Entry ")
    revoke_input = {
        "entry_uri": rating_uri,
        "entity_id": transformed_entry["entry"]["entity_id"],
    }

    logger.info(Fore.GREEN + pformat(revoke_input) + Style.RESET_ALL)

    # msg_id can be decided by application
    msg_id = f'msg-0x{uuid.uuid4().hex}'
    transaction_time = datetime.now(timezone.utc).isoformat()

    # this is used for digest, but its again eco-system policy
    entry_transform = {
        "entry_uri": rating_uri,
        "msg_id": msg_id,
        "provider": network_provider_did["uri"],
        "transaction_time": transaction_time,
    }

    revoke_digest = Cord.Utils.crypto_utils.hash_object_as_hex_string(entry_transform)

    revoke_rating_entry = {
        "entry":{
            "message_id": msg_id,
            "entry_digest": revoke_digest,
            "reference_id": rating_uri
        },
        "entity_id": transformed_entry["entry"]["entity_id"],
        "provider_did": network_provider_did["uri"]
    }

    logger.info("🌐  Rating Revoke (Debit) Information to API endpoint (/amend-ratings)")
    logger.info(Fore.GREEN + pformat(revoke_rating_entry) + Style.RESET_ALL)

    revoke_rating_dispatch_entry = await Cord.Score.scoring.build_from_revoke_rating_properties(
        revoke_rating_entry,
        chain_space["uri"],
        network_author_did["uri"]
    )

    logger.info("🌐  Rating Revoke (Debit) Information to Ledger (API -> Ledger)")
    logger.info(Fore.GREEN + pformat(revoke_rating_dispatch_entry) + Style.RESET_ALL)

    revoked_rating_uri = await Cord.Score.scoring_chain.dispatch_revoke_rating_to_chain(
        revoke_rating_dispatch_entry["details"],
        network_author_identity,
        delegate_auth,
        lambda data: {
            "signature": network_author_keys["authentication"].sign(data["data"]),
            "key_type": network_author_keys["authentication"].crypto_type,
        },
    )

    if(Cord.Identifier.identifier.is_valid_identifier(revoked_rating_uri)):
        logger.info("✅ Rating Revoke (Debit) successful! 🎉")
    else:
        logger.info("🚫 Debit Anchoring failed!  🚫")

    logger.info("💠  Revised Rating - Credit Entry")
    revised_rating_content = {
        **rating_content,
        "provider_did" :transformed_entry["entry"]["provider_did"],
        "reference_id" :rating_uri,
        "count_of_txn": 80,
        "total_rating": 280
    } 

    logger.info(Fore.GREEN + pformat(revised_rating_content) + Style.RESET_ALL)

    revised_entry_digest = Cord.Utils.crypto_utils.hash_object_as_hex_string(revised_rating_content)
    transformed_revised_entry = {
        "entry":{
            **revised_rating_content,
            "reference_id": revoked_rating_uri,
            "total_encoded_rating": round(revised_rating_content["total_rating"] * 10)
        },
        "message_id": '0x' + uuid.uuid4().hex,
        "reference_id": revoked_rating_uri,
        "entry_digest": revised_entry_digest
    }

    del transformed_revised_entry["entry"]["total_rating"]

    logger.info("🌐  Rating Revised(Credit) Information to API endpoint (/write-ratings)")
    
    dispatch_revised_rating = await Cord.Score.scoring.build_from_revise_rating_properties(
        transformed_revised_entry,
        chain_space["uri"],
        network_author_did["uri"],
    )

    logger.info(Fore.GREEN + pformat(dispatch_revised_rating) + Style.RESET_ALL)
    logger.info("🌐  Rating Revised(Credit) Information to Ledger (API -> Ledger) ")

    revised_rating_uri = await Cord.Score.scoring_chain.dispatch_revise_rating_to_chain(
        dispatch_revised_rating["details"],
        network_author_identity,
        delegate_auth,
        lambda data: {
            "signature": network_author_keys["authentication"].sign(data["data"]),
            "key_type": network_author_keys["authentication"].crypto_type,
        },
    )

    if(Cord.Identifier.identifier.is_valid_identifier(revised_rating_uri)):
        logger.info("✅ Rating Revision(Credit) successful! 🎉")
    else:
        logger.info("🚫 Revision Anchoring failed!  🚫")

    logger.info("🌐  Query From Chain - Rating Entry ")
    rating_entry_from_chain = await Cord.Score.scoring_chain.fetch_rating_details_from_chain(revised_rating_uri,'Asia/Kolkata')
    logger.info(Fore.GREEN + pformat(rating_entry_from_chain) + Style.RESET_ALL)

    logger.info("🌐  Query From Chain - Aggregate Score ")
    aggregate_score_from_chain = await Cord.Score.scoring_chain.fetch_entity_aggregate_score_from_chain(rating_content["entity_id"],Cord.Score.scoring.RatingTypeOf.overall)
    logger.info(Fore.GREEN + pformat(aggregate_score_from_chain) + Style.RESET_ALL)


if __name__ == "__main__":
    asyncio.run(main())
    logger.info("Bye! 👋 👋 👋 ")
    Cord.disconnect()
