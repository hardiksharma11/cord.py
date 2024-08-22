from packages.sdk.src import ConfigService, Did, Utils
from packages.identifier.src.identifier import (
    uri_to_identifier,
    hash_to_uri,
)
from packages.utils.src.idents import ASSET_IDENT
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