use common_lib::constants::INTERNAL_API_KEY;
use common_lib::error::ApiError;
use phonenumber::{ ParseError, PhoneNumber };
use rocket::http::Status;
use rocket::request::{ FromRequest, Outcome, Request };
use rocket_okapi::r#gen::OpenApiGenerator;
use rocket_okapi::okapi::openapi3::{
    Object,
    SecurityRequirement,
    SecurityScheme,
    SecuritySchemeData,
};
use rocket_okapi::request::{ OpenApiFromRequest, RequestHeaderInput };
use serde::{ Deserialize, Serialize };
use std::env;
use std::sync::Arc;
use tracing::{ debug, error, info, warn };

// Struct to represent the BearerToken
pub struct BearerToken(pub String);

// Assume this is passed as Rocket State or directly obtained by guard
#[derive(Debug, Clone)]
pub struct UsersServiceUrl(pub String);


#[derive(Debug, Clone)]
pub struct GuardAnonymous {
    pub firebase_user_id: String,
    pub city: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GuardUser {
    pub user_id: String,
    pub firebase_user_id: String,
    pub phone_number: Option<String>,
    pub country_code: String,
    pub city: Option<String>,
    pub user_state: UserState,
    pub roles: HashSet<UserRole>,
    pub verifications: UserVerifications,
}

#[derive(Debug, Clone)]
pub struct GuardNewUser {
    pub firebase_user_id: String,
    pub phone_number: String,
    pub country_code: String,
}

#[derive(Debug, Clone)]
pub struct GuardInternal;

// === User State and Role System ===

#[derive(Debug, Clone, PartialEq)]
pub enum UserState {
    Anonymous,       // Just Firebase anonymous
    PhoneVerified,   // Phone number verified
    Verified,        // Has email/university verifications
}

#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub enum UserRole {
    Student,
    UniversityStaff,
    ConferenceAttendee,
    CoffeeShopAttendee,
    CoworkingSpaceAttendee
    Sponsor,
    ClientAdmin,
}


// === Verification System ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserVerifications {
    pub phone_verified: bool,
    pub phone_verified_at: Option<chrono::DateTime<chrono::Utc>>,
    pub university_verifications: Vec<UniversityVerification>,
    pub venue_verifications: Vec<VenueVerification>,
    pub client_verifications: Vec<ClientVerification>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UniversityVerification {
    pub university_id: String,
    pub verified_email: String,
    pub role: UniversityRole,
    pub verified_at: chrono::DateTime<chrono::Utc>,
    pub status: VerificationStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VenueVerification {
    pub venue_id: String,
    pub venue_type: VenueType,
    pub verification_method: VerificationMethod,
    pub verified_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub status: VerificationStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientVerification {
    pub client_id: String,
    pub role: ClientRole,
    pub scope: ClientScope,
    pub verified_at: chrono::DateTime<chrono::Utc>,
    pub status: VerificationStatus,
}

#[derive(Debug, Clone, PartialEq)]
pub enum UniversityRole {
    Student,
    Admin,
    Staff,
    Faculty,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ClientRole {
    Admin,
    Manager,
    Sponsor,
}

#[derive(Debug, Clone, PartialEq)]
pub enum VerificationMethod {
    Email,
    Token,
    Manual,
}


#[derive(Debug, Clone, PartialEq)]
pub enum VerificationStatus {
    Active,
    Expired,
    Revoked,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ClientScope {
    AllVenues,
    SpecificVenues(Vec<String>),
    VenueTypes(Vec<VenueType>),
}


// === Flexible User Guard with Permissions ===

impl GuardUser {
    /// Check if user can perform action in specific context
    pub fn can_perform_action(&self, permission: &Permission, context: &ActionContext) -> bool {
        PermissionEngine::evaluate_permission(self, permission, context)
    }
    
    /// Require permission or return error
    pub fn require_permission(&self, permission: &Permission, context: &ActionContext) -> Result<(), ApiError> {
        if !self.can_perform_action(permission, context) {
            return Err(ApiError::Forbidden {
                message: format!(
                    "User {} lacks permission {:?} in context {:?}. Current state: {:?}, roles: {:?}",
                    self.user_id, permission, context, self.user_state, self.roles
                ),
            });
        }
        Ok(())
    }
    
    /// Get user's current capabilities
    pub fn get_capabilities(&self, context: &ActionContext) -> HashSet<Permission> {
        PermissionEngine::get_user_capabilities(self, context)
    }
    
    /// Check if user has specific role
    pub fn has_role(&self, role: &UserRole) -> bool {
        self.roles.contains(role)
    }
    
    /// Check verification status
    pub fn is_university_verified(&self) -> bool {
        self.verifications.university_verifications
            .iter()
            .any(|v| v.status == VerificationStatus::Active)
    }
    
    pub fn is_venue_verified(&self, venue_id: &str) -> bool {
        self.verifications.venue_verifications
            .iter()
            .any(|v| v.venue_id == venue_id && v.status == VerificationStatus::Active)
    }
}


#[derive(Debug, Clone)]
pub struct GuardUser {
    pub user_id: String,
    pub roles: Vec<String>,
    pub country_code: String,
    pub firebase_user_id: Option<String>,
    pub phone_number: Option<String>,
    pub current_client_id: Option<String>,
    pub current_venue_id: Option<String>,
    pub major_id: Option<String>,
    pub area_of_interest_ids: Option<Vec<String>>,
    pub default_language: Option<String>,
    pub current_venue_type: Option<String>,
    pub industry_ids: Option<Vec<String>>,
    pub city: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GuardNewUser {
    pub country_code: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")] // Assuming camelCase from User Service JSON response
pub struct UserServiceAuthResponse {
    pub user_id: String,
    pub roles: Vec<String>, // Assuming roles are strings from User Service
    pub current_client_id: Option<String>,
    pub current_venue_id: Option<String>,
    pub major_id: Option<String>,
    pub area_of_interest_ids: Option<Vec<String>>,
    pub default_language: Option<String>,
    pub current_venue_type: Option<String>,
    pub industry_ids: Option<Vec<String>>,
    // Add any other fields the User Service might return here, e.g.,
    // pub is_active: bool,
}

pub struct InternalApiKeyGuard;

#[rocket::async_trait]
impl<'r> FromRequest<'r> for InternalApiKeyGuard {
    type Error = ApiError; // Or a simpler error if desired
    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let expected_api_key = env
            ::var(INTERNAL_API_KEY)
            .map_err(|e| {
                error!("INTERNAL_API_KEY env var not set: {}", e);
                ApiError::InternalServerError { message: "Server misconfiguration".to_string() }
            })
            .expect("INTERNAL_API_KEY must be set"); // Or handle this gracefully.

        let provided_api_key: Option<&str> = request.headers().get_one(X_INTERNAL_API_KEY);

        if provided_api_key.is_none() || provided_api_key.unwrap() != expected_api_key {
            warn!("Unauthorized internal access: Invalid or missing X-Internal-API-Key.");
            Outcome::Error((
                Status::Forbidden,
                ApiError::Unauthorized { message: "Unauthorized".to_string() },
            ))
        } else {
            Outcome::Success(InternalApiKeyGuard)
        }
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for GuardUser {
    // Using your custom ApiError type for consistent error handling
    type Error = ApiError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        debug!("Attempting internal authentication for microservice request.");

        // --- 1. Validate X-Internal-API-Key (Gateway's Secret) ---
        let expected_api_key = match env::var(INTERNAL_API_KEY) {
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

        let provided_api_key: Option<&str> = request.headers().get_one(X_INTERNAL_API_KEY);

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
        let firebase_user_id = match request.headers().get_one(X_FIREBASE_UID) {
            Some(uid) => uid.to_string(),
            None => {
                error!("Missing X-Firebase-UID header from gateway.");
                return Outcome::Error((
                    Status::BadRequest,
                    ApiError::BadRequest {
                        message: "Missing X-Firebase-UID header.".to_string(),
                    },
                ));
            }
        };

        let phone_number_str = match request.headers().get_one(X_PHONE_NUMBER) {
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

        // --- 3. Extract City from Headers (Optional) ---
        let city = request
            .headers()
            .get_one("X-City")
            .map(|c| c.to_string());
        debug!("City from header: {:?}", city);

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
                        message: format!("Invalid phone number format propagated by gateway: {e}"),
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

        // Get the HttpClient from Rocket's managed state
        let http_client_guard = request.guard::<&rocket::State<Arc<reqwest::Client>>>().await;
        let http_client = match http_client_guard {
            Outcome::Success(client) => client,
            _ => {
                // Outcome::Failure or Outcome::Forward
                error!(
                    "HttpClient not found in Rocket state for auth guard. Service not properly initialized."
                );
                return Outcome::Error((
                    Status::InternalServerError,
                    ApiError::InternalServerError {
                        message: "HttpClient dependency not available for authentication.".to_string(),
                    },
                ));
            }
        };

        // Get the UsersServiceUrl from Rocket's managed state
        let user_service_url_guard = request.guard::<&rocket::State<UsersServiceUrl>>().await;
        let user_service_url = match user_service_url_guard {
            Outcome::Success(url) => &url.0,
            _ => {
                // Outcome::Failure or Outcome::Forward
                error!(
                    "UsersServiceUrl not found in Rocket state for auth guard. Service not properly initialized."
                );
                return Outcome::Error((
                    Status::InternalServerError,
                    ApiError::InternalServerError {
                        message: "User Service URL not configured.".to_string(),
                    },
                ));
            }
        };

        // Construct the User Service API call
        let user_check_url = format!(
            "{}/users/exists?firebase_user_id={}&country_code={}",
            user_service_url,
            urlencoding::encode(&firebase_user_id),
            urlencoding::encode(&country_code_alpha2)
        );

        debug!("Calling User Service to verify user existence: {}", user_check_url);
        let user_service_response_raw = match
            http_client
                .get(&user_check_url)
                .header(X_INTERNAL_API_KEY, &expected_api_key)
                .send().await
        {
            Ok(resp) => resp,
            Err(e) => {
                error!("Failed to call User Service: {}", e);
                return Outcome::Error((
                    Status::InternalServerError,
                    ApiError::InternalServerError {
                        message: "User service unavailable or failed to respond.".to_string(),
                    },
                ));
            }
        };

        // Process User Service Response
        if user_service_response_raw.status().is_success() {
            let user_service_auth_data: UserServiceAuthResponse = match
                user_service_response_raw.json().await
            {
                Ok(data) => data,
                Err(e) => {
                    error!("Failed to parse User Service response (expected UserServiceAuthResponse): {}", e);
                    return Outcome::Error((
                        Status::InternalServerError,
                        ApiError::InternalServerError {
                            message: "User service response parsing error.".to_string(),
                        },
                    ));
                }
            };

            // Now, we have the user_id and roles from the User Service
            info!(
                "User authenticated successfully by microservice via User Service: User ID={}, Roles={:?}",
                user_service_auth_data.user_id,
                user_service_auth_data.roles
            );

            Outcome::Success(GuardUser {
                user_id: user_service_auth_data.user_id, // Use ID from User Service
                roles: user_service_auth_data.roles, // Use roles from User Service
                country_code: country_code_alpha2,
                firebase_user_id: Some(firebase_user_id),
                phone_number: Some(phone_number_str),
                current_client_id: user_service_auth_data.current_client_id,
                current_venue_id: user_service_auth_data.current_venue_id,
                major_id: user_service_auth_data.major_id,
                area_of_interest_ids: user_service_auth_data.area_of_interest_ids,
                default_language: user_service_auth_data.default_language,
                current_venue_type: user_service_auth_data.current_venue_type,
                industry_ids: user_service_auth_data.industry_ids,
                city,
            })
        } else {
            let status = user_service_response_raw.status();
            let text = user_service_response_raw.text().await.unwrap_or_default();
            error!("User Service returned an error status: Status={}, Body={}", status, text);
            Outcome::Error((
                Status::InternalServerError, // Treat User Service errors as internal issues
                ApiError::InternalServerError {
                    message: format!("User service returned an error: Status={status}"),
                },
            ))
        }
    }
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
                name: X_INTERNAL_API_KEY.to_owned(), // The actual header name
                location: "header".to_owned(),
            },
            extensions: Object::default(),
        };

        // --- 2. Define Security Scheme for X-Firebase-UID ---
        let firebase_user_id_scheme_name = "FirebaseUidAuth";
        let _firebase_user_id_scheme = SecurityScheme {
            description: Some(
                "Firebase User ID (UID) of the authenticated user, propagated by the API Gateway.".to_owned()
            ),
            data: SecuritySchemeData::ApiKey {
                name: X_FIREBASE_UID.to_owned(),
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
                name: X_PHONE_NUMBER.to_owned(),
                location: "header".to_owned(),
            },
            extensions: Object::default(),
        };

        // --- 4. Define Security Scheme for X-City ---
        let city_scheme_name = "CityAuth";
        let _city_scheme = SecurityScheme {
            description: Some("User's city, propagated by the API Gateway (optional).".to_owned()),
            data: SecuritySchemeData::ApiKey {
                name: "X-City".to_owned(),
                location: "header".to_owned(),
            },
            extensions: Object::default(),
        };

        // --- Create a Security Requirement that lists ALL of these schemes ---
        // This tells OpenAPI that all three headers are required.
        let mut security_req = SecurityRequirement::new();
        security_req.insert(internal_api_key_scheme_name.to_owned(), Vec::new()); // No scopes for API keys
        security_req.insert(firebase_user_id_scheme_name.to_owned(), Vec::new());
        security_req.insert(phone_number_scheme_name.to_owned(), Vec::new());
        security_req.insert(city_scheme_name.to_owned(), Vec::new());

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

#[rocket::async_trait]
impl<'r> FromRequest<'r> for GuardNewUser {
    // Using your custom ApiError type for consistent error handling
    type Error = ApiError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        debug!("Attempting internal authentication for microservice request.");

        // --- 1. Validate X-Internal-API-Key (Gateway's Secret) ---
        let expected_api_key = match env::var(INTERNAL_API_KEY) {
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

        let provided_api_key: Option<&str> = request.headers().get_one(X_INTERNAL_API_KEY);

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

        let phone_number_str = match request.headers().get_one(X_PHONE_NUMBER) {
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
                        message: format!("Invalid phone number format propagated by gateway: {e}"),
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

        Outcome::Success(GuardNewUser {
            country_code: country_code_alpha2,
        })
    }
}

// OpenAPI configuration for Bearer token (optional)
impl<'a> OpenApiFromRequest<'a> for GuardNewUser {
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
                name: X_INTERNAL_API_KEY.to_owned(), // The actual header name
                location: "header".to_owned(),
            },
            extensions: Object::default(),
        };

        // --- 2. Define Security Scheme for X-Phone-Number ---
        let phone_number_scheme_name = "PhoneNumberAuth";
        let _phone_number_scheme = SecurityScheme {
            description: Some(
                "User's phone number in E.164 format (e.g., '+1234567890'), propagated by the API Gateway.".to_owned()
            ),
            data: SecuritySchemeData::ApiKey {
                name: X_PHONE_NUMBER.to_owned(),
                location: "header".to_owned(),
            },
            extensions: Object::default(),
        };

        // --- Create a Security Requirement that lists ALL of these schemes ---
        // This tells OpenAPI that all three headers are required.
        let mut security_req = SecurityRequirement::new();
        security_req.insert(internal_api_key_scheme_name.to_owned(), Vec::new()); // No scopes for API keys
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

// OpenAPI configuration for Bearer token (optional)
impl<'a> OpenApiFromRequest<'a> for InternalApiKeyGuard {
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
                name: X_INTERNAL_API_KEY.to_owned(), // The actual header name
                location: "header".to_owned(),
            },
            extensions: Object::default(),
        };

        // --- Create a Security Requirement that lists ALL of these schemes ---
        // This tells OpenAPI that all three headers are required.
        let mut security_req = SecurityRequirement::new();
        security_req.insert(internal_api_key_scheme_name.to_owned(), Vec::new()); // No scopes for API keys

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

#[derive(Debug, Clone)]
pub enum GuardUserOrInternal {
    User(GuardUser),
    Internal(DummySystemUser),
}

#[derive(Debug, Clone)]
pub struct DummySystemUser {
    pub user_id: String,
    pub roles: Vec<String>,
}

impl DummySystemUser {
    pub fn new() -> Self {
        Self {
            user_id: "000000000000000000000000".to_string(),
            roles: vec!["system".to_string()],
        }
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for GuardUserOrInternal {
    type Error = ApiError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        debug!("GuardUserOrInternal: Checking authentication type");

        // Check if this looks like a user request (has Firebase UID)
        let has_firebase_uid = request.headers().get_one(X_FIREBASE_UID).is_some();
        let has_phone_number = request.headers().get_one(X_PHONE_NUMBER).is_some();

        if has_firebase_uid && has_phone_number {
            // This looks like a user request, validate full user authentication
            debug!("GuardUserOrInternal: Detected user request, validating full authentication");

            match GuardUser::from_request(request).await {
                Outcome::Success(guard_user) => {
                    debug!("GuardUserOrInternal: User authentication successful");
                    Outcome::Success(GuardUserOrInternal::User(guard_user))
                }
                Outcome::Error((status, error)) => {
                    debug!("GuardUserOrInternal: User authentication failed");
                    Outcome::Error((status, error))
                }
                Outcome::Forward(forward) => Outcome::Forward(forward),
            }
        } else {
            // No user headers, check for internal API key only
            debug!("GuardUserOrInternal: No user headers detected, checking internal API key");

            match InternalApiKeyGuard::from_request(request).await {
                Outcome::Success(_) => {
                    debug!("GuardUserOrInternal: Internal API key validation successful");
                    Outcome::Success(GuardUserOrInternal::Internal(DummySystemUser::new()))
                }
                Outcome::Error((status, error)) => {
                    debug!("GuardUserOrInternal: Internal API key validation failed");
                    Outcome::Error((status, error))
                }
                Outcome::Forward(forward) => Outcome::Forward(forward),
            }
        }
    }
}

impl GuardUserOrInternal {
    /// Get user ID (works for both user and internal)
    pub fn user_id(&self) -> &str {
        match self {
            GuardUserOrInternal::User(guard_user) => &guard_user.user_id,
            GuardUserOrInternal::Internal(dummy_user) => &dummy_user.user_id,
        }
    }

    /// Get country code (None for internal calls)
    pub fn country_code(&self) -> Option<&str> {
        match self {
            GuardUserOrInternal::User(guard_user) => Some(&guard_user.country_code),
            GuardUserOrInternal::Internal(_) => None,
        }
    }

    /// Check if this is an internal call
    pub fn is_internal(&self) -> bool {
        matches!(self, GuardUserOrInternal::Internal(_))
    }

    /// Get GuardUser if this is a user call (for cases where you need full user context)
    pub fn as_guard_user(&self) -> Option<&GuardUser> {
        match self {
            GuardUserOrInternal::User(guard_user) => Some(guard_user),
            GuardUserOrInternal::Internal(_) => None,
        }
    }

    /// Convert to a GuardUser for downstream calls (creates dummy user for internal)
    pub fn to_guard_user_for_downstream(&self) -> GuardUser {
        match self {
            GuardUserOrInternal::User(guard_user) => guard_user.clone(),
            GuardUserOrInternal::Internal(_) => {
                // Create a minimal GuardUser for downstream service calls
                GuardUser {
                    user_id: "000000000000000000000000".to_string(),
                    roles: vec![],
                    country_code: "GLOBAL".to_string(), // Special marker
                    firebase_user_id: None,
                    phone_number: None,
                    current_client_id: None,
                    current_venue_id: None,
                    major_id: None,
                    area_of_interest_ids: None,
                    default_language: None,
                    current_venue_type: None,
                    industry_ids: None,
                    city: None,
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct GuardGuest {
    pub firebase_user_id: String,
    pub roles: Vec<String>, // Will contain ["Guest"]
    pub city: Option<String>,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for GuardGuest {
    type Error = ApiError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        debug!("Attempting guest authentication for microservice request.");

        // --- 1. Validate X-Internal-API-Key (Gateway's Secret) ---
        let expected_api_key = match env::var(INTERNAL_API_KEY) {
            Ok(key) => key,
            Err(e) => {
                error!("INTERNAL_API_KEY environment variable not set in microservice: {}", e);
                return Outcome::Error((
                    Status::InternalServerError,
                    ApiError::InternalServerError {
                        message: "Microservice internal API key not configured.".to_string(),
                    },
                ));
            }
        };

        let provided_api_key: Option<&str> = request.headers().get_one(X_INTERNAL_API_KEY);

        if provided_api_key.is_none() || provided_api_key.unwrap() != expected_api_key {
            warn!("Invalid or missing X-Internal-API-Key from calling service. Request blocked.");
            return Outcome::Error((
                Status::Forbidden,
                ApiError::Unauthorized {
                    message: "Unauthorized internal access. Invalid or missing internal API key.".to_string(),
                },
            ));
        }
        debug!("X-Internal-API-Key validated successfully.");

        // --- 2. Extract Firebase UID from Headers (Required for Guest) ---
        let firebase_user_id = match request.headers().get_one(X_FIREBASE_UID) {
            Some(uid) => uid.to_string(),
            None => {
                error!("Missing X-Firebase-UID header from gateway for guest user.");
                return Outcome::Error((
                    Status::BadRequest,
                    ApiError::BadRequest {
                        message: "Missing X-Firebase-UID header for guest authentication.".to_string(),
                    },
                ));
            }
        };

        // --- 3. Extract City from Headers (Optional) ---
        let city = request
            .headers()
            .get_one("X-City")
            .map(|c| c.to_string());
        debug!("Guest user city from header: {:?}", city);

        debug!("Guest user authenticated with Firebase UID: {}", firebase_user_id);

        Outcome::Success(GuardGuest {
            firebase_user_id,
            roles: vec!["Guest".to_string()],
            city,
        })
    }
}

// OpenAPI configuration for GuardGuest
impl<'a> OpenApiFromRequest<'a> for GuardGuest {
    fn from_request_input(
        _gen: &mut OpenApiGenerator,
        _name: String,
        _required: bool
    ) -> rocket_okapi::Result<RequestHeaderInput> {
        // --- 1. Define Security Scheme for X-Internal-API-Key ---
        let internal_api_key_scheme_name = "InternalApiKeyAuth";
        let internal_api_key_scheme = SecurityScheme {
            description: Some(
                "Internal API key to authenticate the calling service (e.g., API Gateway).".to_owned()
            ),
            data: SecuritySchemeData::ApiKey {
                name: X_INTERNAL_API_KEY.to_owned(),
                location: "header".to_owned(),
            },
            extensions: Object::default(),
        };

        // --- 2. Define Security Scheme for X-Firebase-UID ---
        let firebase_user_id_scheme_name = "FirebaseUidAuth";
        let _firebase_user_id_scheme = SecurityScheme {
            description: Some(
                "Firebase User ID (UID) of the guest user, propagated by the API Gateway.".to_owned()
            ),
            data: SecuritySchemeData::ApiKey {
                name: X_FIREBASE_UID.to_owned(),
                location: "header".to_owned(),
            },
            extensions: Object::default(),
        };

        // --- Create a Security Requirement ---
        let mut security_req = SecurityRequirement::new();
        security_req.insert(internal_api_key_scheme_name.to_owned(), Vec::new());
        security_req.insert(firebase_user_id_scheme_name.to_owned(), Vec::new());

        Ok(
            RequestHeaderInput::Security(
                "InternalMicroserviceHeaders".to_owned(),
                internal_api_key_scheme,
                security_req
            )
        )
    }
}

#[derive(Debug, Clone)]
pub struct GuardNewGuestUser {
    pub firebase_user_id: String,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for GuardNewGuestUser {
    type Error = ApiError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        debug!("Attempting new guest user authentication for microservice request.");

        // --- 1. Validate X-Internal-API-Key (Gateway's Secret) ---
        let expected_api_key = match env::var(INTERNAL_API_KEY) {
            Ok(key) => key,
            Err(e) => {
                error!("INTERNAL_API_KEY environment variable not set in microservice: {}", e);
                return Outcome::Error((
                    Status::InternalServerError,
                    ApiError::InternalServerError {
                        message: "Microservice internal API key not configured.".to_string(),
                    },
                ));
            }
        };

        let provided_api_key: Option<&str> = request.headers().get_one(X_INTERNAL_API_KEY);

        if provided_api_key.is_none() || provided_api_key.unwrap() != expected_api_key {
            warn!("Invalid or missing X-Internal-API-Key from calling service. Request blocked.");
            return Outcome::Error((
                Status::Forbidden,
                ApiError::Unauthorized {
                    message: "Unauthorized internal access. Invalid or missing internal API key.".to_string(),
                },
            ));
        }
        debug!("X-Internal-API-Key validated successfully.");

        // --- 2. Extract Firebase UID from Headers (Required for New Guest User) ---
        let firebase_user_id = match request.headers().get_one(X_FIREBASE_UID) {
            Some(uid) => uid.to_string(),
            None => {
                error!("Missing X-Firebase-UID header from gateway for new guest user.");
                return Outcome::Error((
                    Status::BadRequest,
                    ApiError::BadRequest {
                        message: "Missing X-Firebase-UID header for new guest user authentication.".to_string(),
                    },
                ));
            }
        };

        debug!("New guest user authenticated with Firebase UID: {}", firebase_user_id);

        Outcome::Success(GuardNewGuestUser {
            firebase_user_id,
        })
    }
}

// OpenAPI configuration for GuardNewGuestUser
impl<'a> OpenApiFromRequest<'a> for GuardNewGuestUser {
    fn from_request_input(
        _gen: &mut OpenApiGenerator,
        _name: String,
        _required: bool
    ) -> rocket_okapi::Result<RequestHeaderInput> {
        // --- 1. Define Security Scheme for X-Internal-API-Key ---
        let internal_api_key_scheme_name = "InternalApiKeyAuth";
        let internal_api_key_scheme = SecurityScheme {
            description: Some(
                "Internal API key to authenticate the calling service (e.g., API Gateway).".to_owned()
            ),
            data: SecuritySchemeData::ApiKey {
                name: X_INTERNAL_API_KEY.to_owned(),
                location: "header".to_owned(),
            },
            extensions: Object::default(),
        };

        // --- 2. Define Security Scheme for X-Firebase-UID ---
        let firebase_user_id_scheme_name = "FirebaseUidAuth";
        let _firebase_user_id_scheme = SecurityScheme {
            description: Some(
                "Firebase User ID (UID) of the new guest user, propagated by the API Gateway.".to_owned()
            ),
            data: SecuritySchemeData::ApiKey {
                name: X_FIREBASE_UID.to_owned(),
                location: "header".to_owned(),
            },
            extensions: Object::default(),
        };

        // --- Create a Security Requirement ---
        let mut security_req = SecurityRequirement::new();
        security_req.insert(internal_api_key_scheme_name.to_owned(), Vec::new());
        security_req.insert(firebase_user_id_scheme_name.to_owned(), Vec::new());

        Ok(
            RequestHeaderInput::Security(
                "InternalMicroserviceHeaders".to_owned(),
                internal_api_key_scheme,
                security_req
            )
        )
    }
}
