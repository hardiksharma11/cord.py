from .Did_utils import get_did_uri
from packages.utils.src.crypto_utils import encode_address, base58_encode


def from_chain(encoded) -> str:
    return get_did_uri(encode_address(encoded))


def did_public_key_details_from_chain(key_id, key_details):
    key = (
        key_details["key"]["asPublicEncryptionKey"]
        if key_details["key"]["isPublicEncryptionKey"]
        else key_details["key"]["asPublicVerificationKey"]
    )
    return {
        "id": f"#{key_id.hex()}",
        "type": key["type"].lower(),
        "publicKey": key["value"],
    }


def resource_id_to_chain(id):
    return id.replace("#", "")


def document_from_chain(encoded: dict) -> dict:
    public_keys = encoded["publicKeys"]
    authentication_key = encoded["authenticationKey"]
    assertion_key = encoded["assertionKey"]
    delegation_key = encoded["delegationKey"]
    key_agreement_keys = encoded["keyAgreementKeys"]
    last_tx_counter = encoded["lastTxCounter"]

    keys = {
        resource_id_to_chain(
            key_id
        ): did_public_key_details_from_chain(key_id, key_details)
        for key_id, key_details in public_keys.items()
    }

    authentication = keys[authentication_key.hex()]

    #------
    did_record = {"authentication": [authentication], "lastTxCounter": last_tx_counter}

    if assertion_key['isSome']:
        key = keys[assertion_key.hex()]
        did_record["assertionMethod"] = [key]
    if delegation_key['isSome']:
        key = keys[delegation_key.hex()]
        did_record["capabilityDelegation"] = [key]

    key_agreement_key_ids = [
        key_id.hex() for key_id in key_agreement_keys
    ]
    if key_agreement_key_ids:
        did_record["keyAgreement"] = [keys[id] for id in key_agreement_key_ids]

    return did_record

def service_from_chain(encoded):
    id = encoded['id']
    service_types = encoded['service_types']
    urls = encoded['urls']
    return {
        'id': f'#{id}',
        'type': [url for url in service_types],
        'serviceEndpoint': [url for url in urls]
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
        'assertionMethod': did_rec['assertionMethod'],
        'capabilityDelegation': did_rec['capabilityDelegation'],
        'keyAgreement': did_rec['keyAgreement'],
    }

    service = services_from_chain(service_endpoints)
    if service:
        did['service'] = service

    did_name = None if name is None else name.value
    did_account = account.value

    return {
        'document': did,
        'account': did_account,
        'didName': did_name
    }
