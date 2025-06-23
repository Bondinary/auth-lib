use bondinary_common_lib::error::ApiError;
use phonenumber::{ ParseError, PhoneNumber };
use rocket::http::Status;
use rocket::request::{ FromRequest, Outcome, Request };
use rocket_okapi::r#gen::OpenApiGenerator;
use rocket_okapi::okapi::openapi3::{
    Example,
    MediaType,
    Object,
    ParameterStyle,
    RefOr,
    SchemaObject,
    SecurityRequirement,
    SecurityScheme,
    SecuritySchemeData,
};
use rocket_okapi::okapi::Map;
use rocket_okapi::request::{ OpenApiFromRequest, RequestHeaderInput };
use serde::{ Deserialize, Serialize };
use std::env;
use tracing::{ debug, error, warn };

// Struct to represent the BearerToken
pub struct BearerToken(pub String);

// Assume this is passed as Rocket State or directly obtained by guard
#[derive(Debug, Clone)]
pub struct UserServiceUrl(pub String);

#[derive(Debug, Clone)]
pub struct GuardUser {
    pub user_id: String,
    pub roles: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")] // Assuming camelCase from User Service JSON response
pub struct UserServiceAuthResponse {
    pub user_id: String,
    pub roles: Vec<String>, // Assuming roles are strings from User Service
    // Add any other fields the User Service might return here, e.g.,
    // pub is_active: bool,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for GuardUser {
    // Using your custom ApiError type for consistent error handling
    type Error = ApiError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        debug!("Attempting internal authentication for microservice request.");

        // --- 1. Validate X-Internal-API-Key (Gateway's Secret) ---
        let expected_api_key = match env::var("INTERNAL_API_KEY") {
            Ok(key) => key,
            Err(e) => {
                error!("INTERNAL_API_KEY environment variable not set in microservice: {}", e);
                return Outcome::Error((
                    Status::InternalServerError, // Misconfiguration error
                    ApiError::InternalServerError {
                        message: "Microservice internal API key not configured.".to_string(),
                    },
                ));
            }
        };

        let provided_api_key: Option<&str> = request.headers().get_one("X-Internal-API-Key");

        if provided_api_key.is_none() || provided_api_key.unwrap() != expected_api_key {
            warn!("Invalid or missing X-Internal-API-Key from calling service. Request blocked.");
            return Outcome::Error((
                Status::Forbidden, // 403 Forbidden because these are internal endpoints not meant for public
                ApiError::Unauthorized { // Use Unauthorized for failed access attempt
                    message: "Unauthorized internal access. Invalid or missing internal API key.".to_string(),
                },
            ));
        }
        debug!("X-Internal-API-Key validated successfully.");

        // --- 2. Extract Firebase UID and Phone Number from Headers ---
        // let firebase_uid = match request.headers().get_one("X-Firebase-UID") {
        //     Some(uid) => uid.to_string(),
        //     None => {
        //         error!("Missing X-Firebase-UID header from gateway.");
        //         return Outcome::Error((
        //             Status::BadRequest,
        //             ApiError::BadRequest {
        //                 message: "Missing X-Firebase-UID header.".to_string(),
        //             },
        //         ));
        //     }
        // };

        let phone_number_str = match request.headers().get_one("X-Phone-Number") {
            Some(phone) => phone.to_string(),
            None => {
                error!("Missing X-Phone-Number header from gateway.");
                return Outcome::Error((
                    Status::BadRequest,
                    ApiError::BadRequest {
                        message: "Missing X-Phone-Number header.".to_string(),
                    },
                ));
            }
        };

        let parsed_phone_number_result: Result<PhoneNumber, ParseError> = phonenumber::parse(
            None,
            &phone_number_str
        );

        let parsed_phone_number: PhoneNumber = match parsed_phone_number_result {
            Ok(pn) => pn,
            Err(e) => {
                warn!(
                    "Failed to parse phone number '{}' from X-Phone-Number header: {:?}",
                    phone_number_str,
                    e
                );
                return Outcome::Error((
                    Status::BadRequest,
                    ApiError::BadRequest {
                        message: format!(
                            "Invalid phone number format propagated by gateway: {:?}",
                            e
                        ),
                    },
                ));
            }
        };

        let country_id_option = parsed_phone_number.country().id();

        let country_code = match country_id_option {
            Some(country_id_enum_variant) => country_id_enum_variant,
            None => {
                warn!("Could not derive country code from phone number '{}'. Phone number might be invalid or incomplete for country inference.", phone_number_str);
                return Outcome::Error((
                    Status::BadRequest,
                    ApiError::BadRequest {
                        message: "Country code could not be derived from propagated phone number.".to_string(),
                    },
                ));
            }
        };
        let country_code_alpha2 = format!("{country_code:?}");
        debug!("Country code resolved from phone number: {}", country_code_alpha2);

        Outcome::Success(GuardUser {
            user_id: "679657dd1ea2ee98a9545ff7".to_string(), // user_service_auth_data.user_id, // Use ID from User Service
            roles: vec!["User".to_string()], // user_service_auth_data.roles, // Use roles from User Service
        })

        // Get the HttpClient from Rocket's managed state
        // let http_client_guard = request.guard::<&rocket::State<Arc<reqwest::Client>>>().await;
        // let http_client = match http_client_guard {
        //     Outcome::Success(client) => client,
        //     _ => {
        //         // Outcome::Failure or Outcome::Forward
        //         error!(
        //             "HttpClient not found in Rocket state for auth guard. Service not properly initialized."
        //         );
        //         return Outcome::Error((
        //             Status::InternalServerError,
        //             ApiError::InternalServerError {
        //                 message: "HttpClient dependency not available for authentication.".to_string(),
        //             },
        //         ));
        //     }
        // };

        // // Get the UserServiceUrl from Rocket's managed state
        // let user_service_url_guard = request.guard::<&rocket::State<UserServiceUrl>>().await;
        // let user_service_url = match user_service_url_guard {
        //     Outcome::Success(url) => &url.0,
        //     _ => {
        //         // Outcome::Failure or Outcome::Forward
        //         error!(
        //             "UserServiceUrl not found in Rocket state for auth guard. Service not properly initialized."
        //         );
        //         return Outcome::Error((
        //             Status::InternalServerError,
        //             ApiError::InternalServerError {
        //                 message: "User Service URL not configured.".to_string(),
        //             },
        //         ));
        //     }
        // };

        // // Construct the User Service API call
        // let user_check_url = format!(
        //     "{}/users/exists?firebase_uid={}&country_code={}",
        //     user_service_url,
        //     urlencoding::encode(&firebase_uid),
        //     urlencoding::encode(&country_code_alpha2)
        // );

        // debug!("Calling User Service to verify user existence: {}", user_check_url);
        // let user_service_response_raw = match
        //     http_client
        //         .get(&user_check_url)
        //         .header("X-Internal-API-Key", &expected_api_key)
        //         .send().await
        // {
        //     Ok(resp) => resp,
        //     Err(e) => {
        //         error!("Failed to call User Service: {}", e);
        //         return Outcome::Error((
        //             Status::InternalServerError,
        //             ApiError::InternalServerError {
        //                 message: "User service unavailable or failed to respond.".to_string(),
        //             },
        //         ));
        //     }
        // };

        // // Process User Service Response
        // if user_service_response_raw.status().is_success() {
        //     let user_service_auth_data: UserServiceAuthResponse = match
        //         user_service_response_raw.json().await
        //     {
        //         Ok(data) => data,
        //         Err(e) => {
        //             error!("Failed to parse User Service response (expected UserServiceAuthResponse): {}", e);
        //             return Outcome::Error((
        //                 Status::InternalServerError,
        //                 ApiError::InternalServerError {
        //                     message: "User service response parsing error.".to_string(),
        //                 },
        //             ));
        //         }
        //     };

        //     // Now, we have the user_id and roles from the User Service
        //     info!(
        //         "User authenticated successfully by microservice via User Service: User ID={}, Roles={:?}",
        //         user_service_auth_data.user_id,
        //         user_service_auth_data.roles
        //     );

        //     Outcome::Success(GuardUser {
        //         user_id: user_service_auth_data.user_id, // Use ID from User Service
        //         roles: user_service_auth_data.roles, // Use roles from User Service
        //     })
        // } else {
        //     let status = user_service_response_raw.status();
        //     let text = user_service_response_raw.text().await.unwrap_or_default();
        //     error!("User Service returned an error status: Status={}, Body={}", status, text);
        //     Outcome::Error((
        //         Status::InternalServerError, // Treat User Service errors as internal issues
        //         ApiError::InternalServerError {
        //             message: format!("User service returned an error: Status={}", status),
        //         },
        //     ))
        // }
    }
}

// --- Custom OpenAPI ParameterValue Enum (assuming this definition) ---
// This enum encapsulates the different types of parameter values (schema or content)
// This struct will contain the fields that are 'flattened' into the parent Parameter
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, Default)] // Add Default derive for convenience
#[cfg_attr(feature = "impl_json_schema", derive(JsonSchema))]
#[serde(rename_all = "camelCase")] // Ensure camelCase for serialization to JSON
pub struct ParameterValue {
    // OpenAPI parameters can have either 'schema' OR 'content'.
    // Here we'll make both optional. You'll ensure only one is set when creating.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<RefOr<SchemaObject>>,
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    pub content: Map<String, MediaType>,

    // These fields are directly on the parameter value definition
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub style: Option<ParameterStyle>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explode: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_reserved: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub example: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    pub examples: Map<String, RefOr<Example>>,
}

// OpenAPI configuration for Bearer token (optional)
impl<'a> OpenApiFromRequest<'a> for GuardUser {
    fn from_request_input(
        _gen: &mut OpenApiGenerator,
        _name: String,
        _required: bool
    ) -> rocket_okapi::Result<RequestHeaderInput> {
        // --- 1. Define Security Scheme for X-Internal-API-Key ---
        // Give each header a unique internal security scheme name
        let internal_api_key_scheme_name = "InternalApiKeyAuth";
        let internal_api_key_scheme = SecurityScheme {
            description: Some(
                "Internal API key to authenticate the calling service (e.g., API Gateway).".to_owned()
            ),
            data: SecuritySchemeData::ApiKey {
                name: "X-Internal-API-Key".to_owned(), // The actual header name
                location: "header".to_owned(),
            },
            extensions: Object::default(),
        };

        // --- 2. Define Security Scheme for X-Firebase-UID ---
        let firebase_uid_scheme_name = "FirebaseUidAuth";
        let _firebase_uid_scheme = SecurityScheme {
            description: Some(
                "Firebase User ID (UID) of the authenticated user, propagated by the API Gateway.".to_owned()
            ),
            data: SecuritySchemeData::ApiKey {
                name: "X-Firebase-UID".to_owned(),
                location: "header".to_owned(),
            },
            extensions: Object::default(),
        };

        // --- 3. Define Security Scheme for X-Phone-Number ---
        let phone_number_scheme_name = "PhoneNumberAuth";
        let _phone_number_scheme = SecurityScheme {
            description: Some(
                "User's phone number in E.164 format (e.g., '+1234567890'), propagated by the API Gateway.".to_owned()
            ),
            data: SecuritySchemeData::ApiKey {
                name: "X-Phone-Number".to_owned(),
                location: "header".to_owned(),
            },
            extensions: Object::default(),
        };

        // --- Create a Security Requirement that lists ALL of these schemes ---
        // This tells OpenAPI that all three headers are required.
        let mut security_req = SecurityRequirement::new();
        security_req.insert(internal_api_key_scheme_name.to_owned(), Vec::new()); // No scopes for API keys
        security_req.insert(firebase_uid_scheme_name.to_owned(), Vec::new());
        security_req.insert(phone_number_scheme_name.to_owned(), Vec::new());

        // --- Return RequestHeaderInput::Security ---
        // You pass one of the schemes as the primary, and the combined requirement.
        // Rocket-okapi's generator will combine all the schemes listed in security_req.
        Ok(
            RequestHeaderInput::Security(
                // The "name" here is a logical name for this group of security schemes.
                "InternalMicroserviceHeaders".to_owned(),
                // Provide one of the schemes as the default for this input type.
                internal_api_key_scheme,
                // The actual requirement list
                security_req
            )
        )
    }
}
