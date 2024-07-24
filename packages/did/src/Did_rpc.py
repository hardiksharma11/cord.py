from .Did_utils import get_did_uri
from packages.utils.src.crypto_utils import encode_address, base58_encode


def from_chain(encoded) -> str:
    return get_did_uri(encoded)


def did_public_key_details_from_chain(key_id, key_details):
    if "PublicEncryptionKey" in key_details["key"]:
        key = key_details["key"]["PublicEncryptionKey"]
    else:
        key = key_details["key"]["PublicVerificationKey"]

    type, value = next(iter(key.items()))
    return {
        "id": key_id,
        "type": type.lower(),
        "public_key": value,
    }


def resource_id_to_chain(id):
    return id.replace("#", "")


def document_from_chain(encoded: dict) -> dict:
    public_keys = encoded["public_keys"]
    authentication_key = encoded["authentication_key"]
    assertion_key = encoded["assertion_key"]
    delegation_key = encoded["delegation_key"]
    key_agreement_keys = encoded["key_agreement_keys"]
    last_tx_counter = encoded["last_tx_counter"]

    keys = {
        resource_id_to_chain(
            key_id
        ): did_public_key_details_from_chain(key_id, key_details)
        for key_id, key_details in public_keys
    }

    authentication = keys[authentication_key]

    #------
    did_record = {"authentication": [authentication], "last_tx_counter": last_tx_counter}

    if assertion_key:
        key = keys[assertion_key]
        did_record["assertion_method"] = [key]
    if delegation_key:
        key = keys[delegation_key]
        did_record["capability_delegation"] = [key]

    key_agreement_key_ids = [
        key_id for key_id in key_agreement_keys
    ]
    if key_agreement_key_ids:
        did_record["key_agreement"] = [keys[id] for id in key_agreement_key_ids]

    return did_record

def service_from_chain(encoded):
    id = encoded['id']
    service_types = encoded['service_types']
    urls = encoded['urls']
    return {
        'id': f'#{id}',
        'type': [url for url in service_types],
        'service_endpoint': [url for url in urls]
    }

def services_from_chain(encoded):
    return [service_from_chain(encoded_value) for encoded_value in encoded]

def linked_info_from_chain(encoded):
    data = encoded.value
    identifier = data['identifier']
    account = data['account']
    name = data['name']
    service_endpoints = data['service_endpoints']
    details = data['details']
    
    did_rec = document_from_chain(details)
    
    did = {
        'uri': from_chain(identifier),
        'authentication': did_rec['authentication'],
        'assertion_method': did_rec['assertion_method'],
        'capability_delegation': did_rec['capability_delegation'],
        'key_agreement': did_rec['key_agreement'],
    }

    service = services_from_chain(service_endpoints)
    if service:
        did['service'] = service

    did_name = None if name is None else name
    did_account = account

    return {
        'document': did,
        'account': did_account,
        'didName': did_name
    }
