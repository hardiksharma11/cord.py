from substrateinterface import Keypair, KeypairType
from substrateinterface.utils import ss58
import hashlib
import base58
import nacl.utils
from nacl.public import PrivateKey
from collections import OrderedDict
import json
import unicodedata

#generate mnemonic function
def generate_mnemonic(size=24):
    return Keypair.generate_mnemonic(words=size)


def create_from_mnemonic(mnemonic, crypto_type='sr25519'):
    type = KeypairType.SR25519 if crypto_type == 'sr25519' else KeypairType.ED25519 if crypto_type == 'ed25519' else KeypairType.ECDSA
    return Keypair.create_from_mnemonic(mnemonic, type)
    
# Equivalent functions for blake2AsHex, blake2AsU8a
def blake2_as_hex(data, digest_size=32):
    return hashlib.blake2b(data, digest_size=digest_size).hexdigest()

def blake2_as_u8a(data, digest_size=32):
    return hashlib.blake2b(data, digest_size=digest_size).digest()

# Equivalent functions for base58Encode, base58Decode
def base58_encode(data):
    return base58.b58encode(data).decode('utf-8')

def base58_decode(data):
    return base58.b58decode(data)

# Function to check address (simplified version)
def check_address(address, expected_prefix=42):
    try:
        ss58.ss58_decode(address, valid_ss58_format=expected_prefix)
        return True
    except ValueError:
        return False

# Generate random bytes
def random_as_u8a(length):
    return bytes(length)

# Verify a signature (simplified version)
def signature_verify(message, signature, public_key):
    keypair = Keypair(public_key=public_key, ss58_format=42)
    return keypair.verify(message, signature)


# Address encoding/decoding
def encode_address(public_key, ss58_format=42):
    return ss58.ss58_encode(public_key, ss58_format)

def decode_address(address):
    return ss58.ss58_decode(address)

# Utility functions
def is_hex(data, bit_length):
    if data.startswith('0x'):
        data = data[2:]
    else :
        return False
    
    if len(data)*4 != bit_length:
        return False
    return True

def hex_to_bn(hex_string):
    return int(hex_string, 16)

def assert_condition(condition, message):
    assert condition, message

def is_string(data):
    return isinstance(data, str)

def string_to_u8a(string):
    return string.encode('utf-8')

def u8a_concat(*args):
    return b''.join(args)

def u8a_to_hex(u8a):
    return u8a.hex()

def u8a_to_string(u8a):
    return u8a.decode('utf-8')

def u8a_to_u8a(data):
    if isinstance(data, bytes):
        return data
    elif isinstance(data, str):
        if data.startswith('0x'):
            return bytes.fromhex(data[2:])
        else:
            return string_to_u8a(data)
    else:
        raise TypeError("Unsupported input type for conversion to u8a")

def make_keypair_from_uri(uri: str, key_type: str = 'ed25519') -> Keypair:
    """
    Generate typed CORD blockchain keypair from a polkadot keypair URI.

    :param uri: The URI (mnemonic or URI) to generate the keypair from.
    :param key_type: Optional type of the keypair ('ed25519', 'sr25519', 'ecdsa').
    :return: The keypair.
    """
    if key_type not in ['ed25519', 'sr25519', 'ecdsa']:
        raise ValueError(f"Unsupported key_type: {key_type}")
    type = KeypairType.ED25519 if key_type == 'ed25519' else KeypairType.SR25519
    keypair = Keypair.create_from_uri(uri, crypto_type=type)
    return keypair

def nacl_box_pair_from_secret(secret):
    private_key = PrivateKey(secret)
    public_key = private_key.public_key

    return {
        'public_key': bytes(public_key),
        'secret_key': bytes(private_key)
    }

def make_encryption_keypair_from_seed(seed = None):
    if seed is None:
        seed = nacl.utils.random(32)
    keypair = nacl_box_pair_from_secret(seed)
    return {
        **keypair,
        'crypto_type': 'X25519'
    }

def hash(value,bit_length = 32):
    return  blake2_as_u8a(value, bit_length)


def hash_str(value,bit_length = 32):
    return u8a_to_hex(hash(value, bit_length))

def encode_object_as_str(value):
    if isinstance(value, dict):
        # Sort the dictionary by keys using OrderedDict
        sorted_value = OrderedDict(sorted(value.items()))
        input_str = json.dumps(sorted_value, ensure_ascii=False)
    elif isinstance(value, (int, bool)):
        input_str = json.dumps(value)
    else:
        input_str = value
    
    # Normalize the string to NFC form
    normalized_str = unicodedata.normalize('NFC', input_str)
    
    return normalized_str


def hash_object_as_hex_string(value, bit_length = 32, nonce = None):
    input_str = encode_object_as_str(value)
    if nonce is not None:
        input_str = f"{input_str}{nonce}"
    return '0x' + hash_str(input_str.encode('utf-8'), bit_length)