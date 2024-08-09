from packages.sdk.src import ConfigService, Did, Utils
from packages.identifier.src.identifier import (
    uri_to_identifier,
    hash_to_uri,
)
from packages.utils.src.idents import ASSET_IDENT, ASSET_INSTANCE_IDENT
from packages.utils.src.prefix import ASSET_PREFIX

class AssetTypeOf:
    art = "ART"
    bond = "BOND"
    mf = "MF"

class AssetStatusOf:
  active = "Active"
  inactive = "Inactive"
  expired = "Expired"


async def build_from_asset_properties(asset_input: dict, issuer: str, space_uri: str) -> dict:
    entry_digest = Utils.crypto_utils.hash_object_as_hex_string(asset_input)
    
    # Get the API instance
    api = ConfigService.get("api")
    
    # Encode asset digest, issuer, and space in blockchain-compatible format
    scale_encoded_asset_digest = api.encode_scale("H256", entry_digest).get_remaining_bytes()
    scale_encoded_issuer = api.encode_scale("AccountId", Did.to_chain(issuer)).get_remaining_bytes()
    scale_encoded_space = api.encode_scale("Bytes", uri_to_identifier(space_uri)).get_remaining_bytes()

    # Generate the asset ID digest
    combined_bytes = scale_encoded_asset_digest + scale_encoded_space + scale_encoded_issuer
    asset_id_digest = Utils.crypto_utils.blake2_as_hex(combined_bytes)
    
    # Create the asset identifier URI
    asset_identifier = hash_to_uri(asset_id_digest, ASSET_IDENT, ASSET_PREFIX)

    # Construct the transformed entry
    transformed_entry = {
        "entry": asset_input,
        "creator": issuer,
        "space": space_uri,
        "digest": entry_digest,
        "uri": asset_identifier,
    }
    
    return transformed_entry

async def build_from_issue_properties(
    asset_uri,
    asset_owner,
    asset_qty,
    issuer,
    space,
):
    api = ConfigService.get("api")

    issuance_entry = {
        "asset_id": uri_to_identifier(asset_uri),
        "asset_owner": Did.to_chain(asset_owner),
        "asset_issuance_qty": asset_qty,
    }

    issue_entry_digest = Utils.crypto_utils.hash_object_as_hex_string(issuance_entry)

    scale_encoded_asset_id = api.encode_scale("Bytes", issuance_entry["asset_id"]).get_remaining_bytes()
    scale_encoded_space = api.encode_scale("Bytes", uri_to_identifier(space)).get_remaining_bytes()
    scale_encoded_owner_id = api.encode_scale("AccountId", issuance_entry["asset_owner"]).get_remaining_bytes()
    scale_encoded_issuer = api.encode_scale("AccountId", Did.to_chain(issuer)).get_remaining_bytes()
    scale_encoded_asset_digest = api.encode_scale("H256", issue_entry_digest).get_remaining_bytes()

    combined_bytes = scale_encoded_asset_id + scale_encoded_owner_id + scale_encoded_space + scale_encoded_issuer + scale_encoded_asset_digest
    asset_instance_id_digest = Utils.crypto_utils.blake2_as_hex(combined_bytes)

    asset_instance_id = hash_to_uri(
        asset_instance_id_digest,
        ASSET_INSTANCE_IDENT,
        ASSET_PREFIX
    ) 

    asset_instance_identifier = f"{asset_uri}:{asset_instance_id.split(ASSET_PREFIX)[-1]}"

    issuance_details = {
        "entry": issuance_entry,
        "issuer": issuer,
        "space": space,
        "digest": issue_entry_digest,
        "uri": asset_instance_identifier,
    }

    return issuance_details