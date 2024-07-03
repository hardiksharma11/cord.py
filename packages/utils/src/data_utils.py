import json
from datetime import datetime
import pytz
from packages.utils.src.crypto_utils import check_address, is_hex
from packages.utils.src.SDKErrors import Errors
from .ss58_format import ss58_format

def flatten_object(obj, prefix=''):
    """
    Flattens a nested dictionary.

    :param obj: The dictionary to flatten.
    :param prefix: The prefix to use for the keys.
    :return: A flattened dictionary.
    """
    flat_object = {}

    for key in obj:
        new_key = f'{prefix}{key}'

        if isinstance(obj[key], dict) and obj[key] is not None and not isinstance(obj[key], list):
            deeper = flatten_object(obj[key], f'{new_key}.')
            flat_object.update({new_key: obj[key]}, **deeper)
        else:
            flat_object[new_key] = obj[key]

    return flat_object


def extract_key_part_from_statement(statement: str) -> str | None:
    try:
        obj = json.loads(statement)
        keys = list(obj.keys())
        if keys:
            # Always retain 'issuer' and 'holder'
            if keys[0] == 'issuer' or keys[0] == 'holder':
                return keys[0]
            
            parts = keys[0].split('#')
            return parts[1] if len(parts) > 1 else None
        return None
    except (json.JSONDecodeError, TypeError):
        return None  # If parsing fails, return null


def filter_statements(statements, selected_attributes):
    filtered_statements = []
    for statement in statements:
        key_part = extract_key_part_from_statement(statement)
        if key_part:
            if key_part == 'issuer' or key_part == 'holder' or key_part in selected_attributes:
                filtered_statements.append(statement)
    return filtered_statements


def verify_cord_address(input) -> None:
    """
    Verifies a given address string against the External Address Format (SS58) with our Prefix of 29.

    @param input: Address string to validate for correct format.
    """
    if not isinstance(input, str):
        raise Errors.AddressTypeError()
    if not check_address(input, ss58_format):
        raise Errors.AddressInvalidError(input)
    
def is_cord_address(input) -> bool:
    """
    Type guard to check whether input is an SS58 address with our prefix of 29.

    :param input: Address string to validate for correct format.
    :returns: True if input is a valid CordAddress, False otherwise.
    """
    try:
        verify_cord_address(input)
        return True
    except (Errors.AddressTypeError, Errors.AddressInvalidError):
        return False


def verify_is_hex(input, bit_length= None):
    """
    Validates the format of a hex string via regex.

    :param input: Hex string to validate for correct format.
    :param bit_length: Expected length of hex in bits.
    :raises SDKErrors.HashMalformedError: When the input is not a valid hex string.
    """
    if not is_hex(input, bit_length):
        raise Errors.HashMalformedError(
            input if isinstance(input, str) else None
        )
    
def convert_unix_time_to_date_time(unix_time: int, time_zone: str) -> str:
    # Convert the Unix timestamp to a datetime object
    date = datetime.fromtimestamp(unix_time, pytz.timezone(time_zone))
    
    # Format the date according to the specified options
    formatted_date = date.strftime('%Y-%B-%d %H:%M:%S %Z')

    return formatted_date


def convert_date_time_to_unix_time(date_time_str: str) -> int:
    # Note: The date_time_str format should match the output of convert_unix_time_to_date_time
    date = datetime.strptime(date_time_str, '%Y-%B-%d %H:%M:%S %Z')
    unix_time = int(date.timestamp())
    
    return unix_time                                                                          