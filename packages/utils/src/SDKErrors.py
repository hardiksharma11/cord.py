class SDKError(Exception):
    def __init__(self, message: str = "", options: dict = None):
        super().__init__(message)
        self.name = self.__class__.__name__
        self.options = options


# config
class BlockchainApiMissingError(SDKError):
    def __init__(self, options: dict = None):
        message = 'Blockchain API is missing. Please set the "api" configuration.'
        super().__init__(message, options)


# network
class SubscriptionsNotSupportedError(SDKError):
    def __init__(self, options: dict = None):
        message = (
            "This function is not available if the blockchain API does not support state or event subscriptions, "
            "use `WsProvider` to enable the complete feature set"
        )
        super().__init__(message, options)


class TimeoutError(SDKError):
    def __init__(self, options: dict = None):
        message = "Promise timed out"
        super().__init__(message, options)


# identifier errors
class InvalidURIError(SDKError):
    pass


class InvalidIdentifierError(SDKError):
    pass


class InvalidInputError(SDKError):
    pass


# DID errors
class InvalidDidFormatError(SDKError):
    def __init__(self, did: str, options: dict = None):
        message = f'Not a valid CORD DID "{did}"'
        super().__init__(message, options)


class DidError(SDKError):
    pass


class AddressInvalidError(SDKError):
    def __init__(self, id=None, type=None, options: dict = None):
        if id and type:
            message = f'Provided {type} identifier "{id}" is invalid'
        elif id:
            message = f'Provided identifier "{id}" is invalid'
        else:
            message = "Provided identifier is invalid"
        super().__init__(message, options)


class AddressTypeError(SDKError):
    pass


# utils
class HashMalformedError(SDKError):
    def __init__(self, hash: str = None, type: str = None, options: dict = None):
        if hash and type:
            message = f'Provided {type} hash "{hash}" is invalid or malformed'
        elif hash:
            message = f'Provided hash "{hash}" is invalid or malformed'
        else:
            message = "Provided hash is invalid or malformed"
        super().__init__(message, options)

# Exporter
class DidExporterError(SDKError):
    pass

class CordDispatchError(SDKError):
    pass

class InvalidPermissionError(SDKError):
    pass

class ChainSpaceMissingError(SDKError):
    pass

class AuthorizationMissingError(SDKError):
    pass

class CordFetchError(SDKError):
    pass
    
class SchemaStructureError(SDKError):
    pass

class ObjectUnverifiableError(SDKError):
    pass

class SchemaIdMismatchError(SDKError):
    def __init__(self, from_schema, provided, options: dict = None):
        message = f"Provided $id {provided} does not match schema $id {from_schema}"
        super().__init__(message, options)

class SchemaError(SDKError):
    pass

class Errors:
    SDKError = SDKError
    SubscriptionsNotSupportedError = SubscriptionsNotSupportedError
    InvalidURIError = InvalidURIError
    InvalidIdentifierError = InvalidIdentifierError
    TimeoutError = TimeoutError
    BlockchainApiMissingError = BlockchainApiMissingError
    InvalidInputError = InvalidInputError
    InvalidDidFormatError = InvalidDidFormatError
    DidError = DidError
    AddressInvalidError = AddressInvalidError
    AddressTypeError = AddressTypeError
    DidExporterError = DidExporterError
    CordDispatchError = CordDispatchError
    InvalidPermissionError = InvalidPermissionError
    ChainSpaceMissingError = ChainSpaceMissingError
    AuthorizationMissingError = AuthorizationMissingError
    CordFetchError = CordFetchError
    SchemaStructureError = SchemaStructureError
    ObjectUnverifiableError = ObjectUnverifiableError
    SchemaIdMismatchError = SchemaIdMismatchError
    SchemaError = SchemaError
