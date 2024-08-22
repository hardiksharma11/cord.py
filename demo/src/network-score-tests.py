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

if __name__ == "__main__":
    asyncio.run(main())
    logger.info("Bye! 👋 👋 👋 ")
    Cord.disconnect()
