from jsonschema import Draft7Validator
from .schema_chain import get_uri_for_schema
from packages.utils.src.SDKErrors import Errors
from .schema_types import SchemaModel, SchemaModelV1


def verify_object_against_schema(obj, schema, messages=None, referenced_schemas=None):
    """
    Validates an incoming schema object against a JSON schema model (draft-07).

    This function takes an object and a JSON schema, then uses a JSON Schema Validator
    to determine if the object conforms to the schema. It supports validation against
    complex schemas that may include references to other schemas. If the object does not
    conform to the schema, the function throws an error with details about the validation
    failures.

    @param obj: The object to be validated against the schema.
    @param schema: The JSON schema to validate the object against.
    @param messages: An optional array to store error messages. If provided,
                     validation errors will be pushed into this array.
    @param referenced_schemas: An optional array of additional schemas
                               that might be referenced in the main schema. This is useful for complex schemas that
                               include references to other schemas.
    @throws: SDKErrors.ObjectUnverifiableError if the object does not
             conform to the schema. The error includes details about the validation failures.
    """
    validator = Draft7Validator(schema)
    if referenced_schemas:
        for ref_schema in referenced_schemas:
            validator.VALIDATORS["$ref"](validator, "", ref_schema)

    errors = list(validator.iter_errors(obj))
    if not errors:
        return

    if messages is not None:
        for error in errors:
            messages.append(error['message'])

    raise Errors.ObjectUnverifiableError(
        f"JSON schema verification failed for object : {errors}"
    )


def verify_schema_structure(input_schema, creator, space):
    """
    Validates the structure of a given schema and checks for consistency in its identifier.

    This function performs two critical checks: firstly, it validates the structure of the provided schema
    against a predefined schema model (SchemaModel), ensuring adherence to the expected format and rules.
    Secondly, it verifies that the schema's identifier ($id) is consistent with an identifier generated
    from the schema's content, the creator's DID, and the provided space identifier. This ensures that
    each schema is uniquely and correctly identified, maintaining integrity in schema management.

    @param input_schema: The schema to be validated. This schema should conform to the structure
                         defined by the ISchema interface.
    @param creator: The decentralized identifier (DID) of the creator of the schema.
                    This DID is used in conjunction with the schema content and space identifier
                    to generate the expected schema identifier.
    @param space: An identifier for the space (context or category) associated with the schema.
                  This parameter is part of the criteria for generating the expected schema identifier.

    @throws: SDKErrors.SchemaIdMismatchError if the actual schema identifier ($id) does not
             match the expected identifier derived from the schema content, creator's DID, and space identifier.
             This check is crucial to ensure that each schema's identifier is both unique and correctly formatted,
             avoiding conflicts and inconsistencies in schema identification.
    """
    verify_object_against_schema(input_schema, SchemaModel)
    uri_from_schema = get_uri_for_schema(input_schema, creator, space)
    if uri_from_schema["uri"] != input_schema.get("$id"):
        raise Errors.SchemaIdMismatchError(
            uri_from_schema["uri"], input_schema.get("$id")
        )


def build_from_properties(schema, space_uri, creator_uri):
    """
    Constructs a schema object from specified properties, required fields, and other schema attributes.
    This function is pivotal in dynamically generating schemas based on specific requirements and attributes,
    facilitating the creation of structured and standardized schema objects.

    @param schema: An object defining the properties, required fields, and other attributes of the schema.
                   This includes the structure and data types for each field within the schema, providing the blueprint
                   for the schema's format and content.
    @param space_uri: An identifier for the space (context or category) within which the schema is created.
                      This categorization aids in organizing and managing schemas, particularly in diverse and complex systems.
    @param creator_uri: The decentralized identifier (DID) of the creator of the schema. This DID is used
                        to generate a unique identifier for the schema, ensuring its uniqueness and traceability within the system.

    @returns: A fully constructed schema object including the schema itself, its cryptographic
              digest, the space identifier, and the creator's DID. This object can be utilized for data validation
              and various other purposes, serving as a cornerstone in data structuring and management.

    @throws: SDKErrors.SchemaStructureError if the constructed schema fails to conform to the expected structure
             or standards. This error ensures the integrity and compliance of the schema with predefined models.
    """
    schema_copy = {k: v for k, v in schema.items() if k != "$id"}
    schema_copy["additionalProperties"] = False
    schema_copy["$schema"] = SchemaModelV1['$id']

    uri_and_digest = get_uri_for_schema(schema_copy, creator_uri, space_uri)
    uri = uri_and_digest["uri"]
    digest = uri_and_digest["digest"]

    schema_type = {"$id": uri, **schema_copy}

    schema_details = {
        "schema": schema_type,
        "digest": digest,
        "spaceUri": space_uri,
        "creatorUri": creator_uri,
    }

    try:
        verify_schema_structure(schema_type, creator_uri, space_uri)
    except Exception as e:
        raise Errors.SchemaStructureError(
            "Schema structure verification failed."
        ) from e

    return schema_details
