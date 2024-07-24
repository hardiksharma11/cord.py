from .did_contexts import CORD_DID_CONTEXT_URL, W3C_DID_CONTEXT_URL
from packages.utils.src.SDKErrors import Errors
from packages.utils.src.crypto_utils import base58_encode

verification_key_types_map= {
    # proposed and used by dock.io
    'sr25519': 'Sr25519VerificationKey2020',
    # part of current w3 security vocab
    'ed25519': 'Ed25519VerificationKey2018',
    'ecdsa': 'EcdsaSecp256k1VerificationKey2019',
}

encryption_key_types_map = {
    'x25519': 'X25519KeyAgreementKey2019',
}
def to_absolute_uri(key_id, controller):
    if key_id.startswith(controller):
        return key_id
    return f"{controller}{key_id}"

def export_to_json_did_document(did) :
    controller = did['uri']
    authentication = did['authentication']
    assertion_method = did.get('assertion_method', [])
    capability_delegation = did.get('capability_delegation', [])
    key_agreement = did.get('key_agreement', [])
    service = did.get('service', [])

    verification_method = [
        *authentication,
        *assertion_method,
        *capability_delegation,
    ]
    
    verification_method = [
        {**key, 'type': verification_key_types_map[key['type']]}
        for key in verification_method
    ] + [
        {**key, 'type': encryption_key_types_map[key['type']]}
        for key in key_agreement
    ]
    
    verification_method = [
        {
            'id': to_absolute_uri(key['id'], controller),
            'controller': controller,
            'type': key['type'],
            'publicKeyBase58': base58_encode(key['public_key'])
        }
        for key in verification_method
    ]

    verification_method = list({v['id']: v for v in verification_method}.values())  # Remove duplicates

    result = {
        'id': controller,
        'verificationMethod': verification_method,
        'authentication': [to_absolute_uri(authentication[0]['id'], controller)],
    }

    if assertion_method:
        result['assertionMethod'] = [to_absolute_uri(assertion_method[0]['id'], controller)]
    if capability_delegation:
        result['capabilityDelegation'] = [to_absolute_uri(capability_delegation[0]['id'], controller)]
    if key_agreement:
        result['keyAgreement'] = [to_absolute_uri(key_agreement[0]['id'], controller)]
    if service:
        result['service'] = [
            {**endpoint, 'id': f"{controller}{endpoint['id']}"}
            for endpoint in service
        ]

    return result

def export_to_json_ld_did_document(did) :
    conforming_document = export_to_json_did_document(did)
    json_ld_document = {
        **conforming_document,
        '@context': [W3C_DID_CONTEXT_URL, CORD_DID_CONTEXT_URL],
    }
    return json_ld_document

def export_to_did_document(did, mime_type) :
    if mime_type == 'application/json':
        return export_to_json_did_document(did)
    elif mime_type == 'application/ld+json':
        return export_to_json_ld_did_document(did)
    else:
        raise Errors.DidExporterError(f'The MIME type "{mime_type}" not supported by any of the available exporters')