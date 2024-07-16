from packages.utils.src.crypto_utils import (
    generate_mnemonic,
    blake2_as_u8a,
    make_keypair_from_uri,
    make_encryption_keypair_from_seed,
)
from substrateinterface import Keypair, KeypairType
from mnemonic import Mnemonic


def generate_key_agreement(mnemonic: str, key_type: str):
    # Convert mnemonic to seed
    mnemo = Mnemonic("english")
    seed = mnemo.to_seed(mnemonic)[:32]

    # Create the initial keypair from seed
    if key_type == "sr25519":
        secret_keypair = Keypair.create_from_seed(seed, crypto_type=KeypairType.SR25519)
    else:
        secret_keypair = Keypair.create_from_seed(seed, crypto_type=KeypairType.ED25519)
    
    # Derive the keypair using the path
    derived_keypair = secret_keypair.create_from_uri(
        "//did//keyAgreement//0",
        crypto_type=(
            KeypairType.SR25519 if key_type == "sr25519" else KeypairType.ED25519
        ),
    )

    # Generate encryption keypair from the derived secret key
    encryption_keypair = make_encryption_keypair_from_seed(
        blake2_as_u8a(derived_keypair.private_key)
    )

    return encryption_keypair


def generate_keypairs(mnemonic, key_type="ed25519"):
    if not mnemonic:
        mnemonic = generate_mnemonic()
    
    authentication = make_keypair_from_uri(
        f"{mnemonic}//did//authentication//0", key_type=key_type
    )
    assertion_method = make_keypair_from_uri(
        f"{mnemonic}//did//assertion//0", key_type=key_type
    )
    capability_delegation = make_keypair_from_uri(
        f"{mnemonic}//did//delegation//0", key_type=key_type
    )
    key_agreement = generate_key_agreement(mnemonic, key_type)

    return {
        "authentication": authentication,
        "assertion_method": assertion_method,
        "capability_delegation": capability_delegation,
        "key_agreement": key_agreement,
    }


if __name__ == "__main__":
    generate_keypairs(None, "sr25519")
