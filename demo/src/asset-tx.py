import asyncio
import packages.sdk.src as Cord
from utils.create_account import create_account
from utils.create_authorities import add_network_member
import logging
from pprint import pformat
from colorama import Fore, Style, init
import uuid

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def main():
    network_address = "ws://127.0.0.1:9944"
    anchor_uri = "//Alice"
    Cord.ConfigService.set({"submitTxResolveOn": Cord.Chain.is_in_block})
    await Cord.connect(network_address)

    logger.info('On-Chain Assets & Transactions  ')
    # Step 1: Setup Identities

    logger.info("❄️  Identities")
    network_authority_identity = Cord.Utils.crypto_utils.make_keypair_from_uri(
        anchor_uri, "sr25519"
    )

    # Create Issuer DID
    issuer = await Cord.Did.create_did(network_authority_identity)
    issuer_mnemonic = issuer.get("mnemonic")
    issuer_did = issuer.get("document")
    issuer_keys = Cord.Did.generate_keypairs(issuer_mnemonic, "sr25519")
    logger.info(
        f'🏦  Issuer ({issuer_did["assertion_method"][0]["type"]}): {issuer_did["uri"]}'
    )

    # Create Holder DID
    holder = await Cord.Did.create_did(network_authority_identity)
    holder_mnemonic = holder.get("mnemonic")
    holder_did = holder.get("document")
    holder_keys = Cord.Did.generate_keypairs(holder_mnemonic, "sr25519")
    logger.info(
        f'👩‍⚕️  Holder ({holder_did["assertion_method"][0]["type"]}): {holder_did["uri"]}'
    )

    # Create Holder 2 DID
    holder2 = await Cord.Did.create_did(network_authority_identity)
    holder2_mnemonic = holder2.get("mnemonic")
    holder2_did = holder2.get("document")

    logger.info(
        f'👩‍⚕️  Holder 2 ({holder2_did["assertion_method"][0]["type"]}): {holder2_did["uri"]}'
    )
    
    authority_account = create_account()
    api_identity = authority_account["account"]
    crypto_type_map = {0: "ed25519", 1: "sr25519", 2: "ecdsa"}

    # Get the crypto type as a string
    crypto_type_str = crypto_type_map.get(api_identity.crypto_type, "unknown")
    logger.info(f"🏦  API Provider ({crypto_type_str}): {api_identity.ss58_address}")

    await add_network_member(network_authority_identity, api_identity.ss58_address)
    logger.info("✅ Identities created!")


    # Step 3: Create a new Chain Space
    logger.info("❄️  Chain Space Creation")
    space_properties = await Cord.Chainspace.build_from_properties(issuer_did["uri"])
    logger.info(Fore.GREEN + pformat(space_properties) + Style.RESET_ALL)

    logger.info("\n❄️  Chain Space Properties ")
    space = await Cord.Chainspace.dispatch_to_chain(
        space_properties,
        issuer_did["uri"],
        network_authority_identity,
        lambda data: {
            "signature": issuer_keys["authentication"].sign(data["data"]),
            "key_type": issuer_keys["authentication"].crypto_type,
        },
    )
    logger.info(Fore.GREEN + pformat(space) + Style.RESET_ALL)
    logger.info("✅ Chain Space created!")
    logger.info("❄️  Chain Space Approval ")

    await Cord.Chainspace.sudo_approve_chain_space(
        network_authority_identity, space["uri"], 1000
    )
    logger.info("✅ Chain Space approved!")

    # Step 2: Create assets on-chain
    asset_properties = {
        "asset_type" : Cord.Asset.asset.AssetTypeOf.art,
        "asset_desc" : f"Asset - {uuid.uuid4()}",
        "asset_qty" : 10000,
        "asset_value" : 100,
        "asset_tag" : f"Tag - {uuid.uuid4()}",
        "asset_meta" : f"Meta - {uuid.uuid4()}",
    }

    logger.info("❄️  Asset Properties - Created by Issuer  ")
    logger.info(Fore.GREEN + pformat(asset_properties) + Style.RESET_ALL)

    asset_entry = await Cord.Asset.asset.build_from_asset_properties(
        asset_properties, issuer_did["uri"], space["uri"]
    )    

    logger.info("❄️  Asset Transaction  - Created by Issuer  ")
    logger.info(Fore.GREEN + pformat(asset_entry) + Style.RESET_ALL)

    extrinsic  =await Cord.Asset.asset_chain.dispatch_create_to_chain(
        asset_entry,
        network_authority_identity,
        space["authorization"],
        lambda data: {
            "signature": issuer_keys["authentication"].sign(data["data"]),
            "key_type": issuer_keys["authentication"].crypto_type,
        },
    )

    logger.info("✅ Asset created!")

    # Step 3: Issue Asset to Holder
    logger.info("❄️  Issue Asset to Holder - Issuer Action  ")
    asset_issuence = await Cord.Asset.asset.build_from_issue_properties(
        asset_entry["uri"],
        holder_did["uri"],
        1,
        issuer_did["uri"],
        space["uri"],
    )

    logger.info(Fore.GREEN + pformat(asset_issuence) + Style.RESET_ALL)
    issue_extrinsic = await Cord.Asset.asset_chain.dispatch_issue_to_chain(
        asset_issuence,
        network_authority_identity,
        space["authorization"],
        lambda data: {
            "signature": issuer_keys["authentication"].sign(data["data"]),
            "key_type": issuer_keys["authentication"].crypto_type,
        },
    )
if __name__ == "__main__":
    asyncio.run(main())
    logger.info("Bye! 👋 👋 👋 ")
    Cord.disconnect()