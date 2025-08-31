use chrono::{ DateTime, Utc };
use common_lib::constants::{
    INTERNAL_API_KEY,
    UNKNOWN,
    X_CITY,
    X_COUNTRY_CODE,
    X_FIREBASE_UID,
    X_INTERNAL_API_KEY,
    X_PHONE_NUMBER,
};
use common_lib::error::ApiError;
use common_lib::utils::get_env_var;
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
use rocket_okapi::request::RequestHeaderInput;
use serde::{ Deserialize, Serialize };
use users_service_domain::users_models::UserRole;
use venues_service_domain::client_models::{ AuthType, Client, ClientAuth };
use venues_service_domain::venue_models::{ Venue, VenueType };
use std::collections::HashSet;
use std::sync::{ Arc };
use tracing::{ debug, error, info, warn };
use crate::permissions::{ ActionContext, Permission, PermissionChecker, UserServiceAuthResponse };
use rocket_okapi::request::{ OpenApiFromRequest };

// Struct to represent the BearerToken
pub struct BearerToken(pub String);

// Assume this is passed as Rocket State or directly obtained by guard
#[derive(Debug, Clone)]
pub struct UsersServiceUrl(pub String);

#[derive(Debug, Clone)]
pub struct GuardAnonymous {
    pub user_id: String,
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
    pub user_role: Option<UserRole>,
    pub roles: HashSet<ClientUserRole>,
    pub verifications: Option<UserVerifications>,
}

#[derive(Debug, Clone)]
pub enum GuardUserOrAnonymous {
    User(GuardUser),
    Anonymous(GuardAnonymous),
}

#[derive(Debug, Clone)]
pub struct GuardInternal;

// === Verification System ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserVerifications {
    pub phone_verified: bool,
    pub phone_verified_at: Option<DateTime<Utc>>,

    // Client-level verifications (University, Company, Organization)
    pub client_verifications: Vec<ClientVerification>,

    // Venue-specific verifications (for special events, conferences, etc.)
    pub venue_verifications: Vec<VenueVerification>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientVerification {
    pub client_id: String, // References Client.id from your venues service
    pub client_name: String, // University name, Company name, etc.
    pub verification_method: ClientVerificationMethod,
    pub verified_email: Option<String>, // For email domain verification
    pub token_used: Option<String>, // For token verification
    pub user_role: ClientUserRole, // Role within this client organization
    pub verified_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub status: VerificationStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VenueVerification {
    pub venue_id: String, // References Venue.id
    pub venue_name: String,
    pub client_id: String, // Parent client of this venue
    pub venue_type: VenueType, // Campus, CoffeeShop, etc.
    pub verification_method: VenueVerificationMethod,
    pub verified_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>, // For temporary access (conferences)
    pub status: VerificationStatus,
}

// === Verification Methods ===

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ClientVerificationMethod {
    EmailDomain {
        domain: String, // @oxford.ac.uk, @google.com
        verified_email: String,
    },
    ClientToken {
        token: String, // Client-provided token
    },
    ManualApproval {
        approved_by: String, // Admin who approved
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum VenueVerificationMethod {
    InheritFromClient, // User has client verification
    VenueSpecificToken {
        token: String, // Event/conference specific token
    },
    QRCodeScan {
        qr_data: String,
    },
    ProximityBasedCheckin, // Location-based check-in
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ClientUserRole {
    // Bondinary admin
    Admin,

    // University roles
    Student,
    Staff,
    Alumni,

    // Coffee shop roles
    CoffeeShopAttendee,
    CoffeeShopManager,

    // Coworking space roles
    CoworkingSpaceAttendee,
    CoworkingSpaceManager,

    // Conference roles
    ConferenceAttendee,
    ConferenceSpeaker,

    // General roles
    Guest,
    Sponsor,
    System,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum VerificationMethod {
    Email,
    Token,
    Manual,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum VerificationStatus {
    Active,
    Expired,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ClientScope {
    AllVenues,
    SpecificVenues(Vec<String>),
    VenueTypes(Vec<VenueType>),
}

// === Flexible User Guard with Permissions ===

impl GuardUser {
    /// Check if user can access a specific client (based on existing Client model)
    pub fn can_access_client(&self, client: &Client) -> bool {
        if let Some(verifications) = &self.verifications {
            // Check if user has verification for this client
            verifications.client_verifications
                .iter()
                .any(
                    |cv|
                        cv.client_id == *client.id.as_ref().unwrap_or(&String::new()) &&
                        cv.status == VerificationStatus::Active &&
                        !self.is_client_verification_expired(cv)
                )
        } else {
            false
        }
    }

    /// Check if user can access a specific venue based on client auth requirements
    pub fn can_access_venue(&self, client: &Client) -> bool {
        // If client doesn't require auth, anyone can access
        if let Some(client_auth) = &client.auth {
            if !client_auth.requires_auth {
                return true;
            }

            match client_auth.auth_type {
                Some(AuthType::None) => true,
                Some(AuthType::EmailDomain) => {
                    self.has_client_email_domain_verification(client, client_auth)
                }
                Some(AuthType::Token) => { self.has_client_token_verification(client, client_auth) }
                None => false,
            }
        } else {
            // No auth config means open access
            true
        }
    }

    /// Check if user has email domain verification for this client
    fn has_client_email_domain_verification(
        &self,
        client: &Client,
        client_auth: &ClientAuth
    ) -> bool {
        if let Some(verifications) = &self.verifications {
            if let Some(allowed_domains) = &client_auth.allowed_email_domains {
                return verifications.client_verifications
                    .iter()
                    .any(|cv| {
                        cv.client_id == *client.id.as_ref().unwrap_or(&String::new()) &&
                            cv.status == VerificationStatus::Active &&
                            matches!(&cv.verification_method, ClientVerificationMethod::EmailDomain { domain, .. } 
                            if allowed_domains.iter().any(|ad| domain.ends_with(ad)))
                    });
            }
        }
        false
    }

    /// Check if user has token verification for this client
    fn has_client_token_verification(&self, client: &Client, client_auth: &ClientAuth) -> bool {
        if let Some(verifications) = &self.verifications {
            if let Some(client_token) = &client_auth.client_token {
                return verifications.client_verifications
                    .iter()
                    .any(|cv| {
                        cv.client_id == *client.id.as_ref().unwrap_or(&String::new()) &&
                            cv.status == VerificationStatus::Active &&
                            matches!(&cv.verification_method, ClientVerificationMethod::ClientToken { token } 
                            if token == client_token)
                    });
            }
        }
        false
    }

    /// Check if user has specific venue verification (for events, conferences)
    pub fn has_venue_specific_verification(&self, venue_id: &str) -> bool {
        if let Some(verifications) = &self.verifications {
            verifications.venue_verifications
                .iter()
                .any(
                    |vv|
                        vv.venue_id == venue_id &&
                        vv.status == VerificationStatus::Active &&
                        !self.is_venue_verification_expired(vv)
                )
        } else {
            false
        }
    }

    /// Get user's role within a specific client organization
    pub fn get_client_role(&self, client_id: &str) -> Option<ClientUserRole> {
        if let Some(verifications) = &self.verifications {
            verifications.client_verifications
                .iter()
                .find(|cv| cv.client_id == client_id && cv.status == VerificationStatus::Active)
                .map(|cv| cv.user_role.clone())
        } else {
            None
        }
    }

    fn is_client_verification_expired(&self, verification: &ClientVerification) -> bool {
        if let Some(expires_at) = verification.expires_at { Utc::now() > expires_at } else { false }
    }

    fn is_venue_verification_expired(&self, verification: &VenueVerification) -> bool {
        if let Some(expires_at) = verification.expires_at { Utc::now() > expires_at } else { false }
    }

    /// Check if user can perform action in specific context
    pub fn can_perform_action_with_checker(
        &self,
        permission: &Permission,
        context: &ActionContext,
        checker: &dyn PermissionChecker
    ) -> bool {
        checker.can_perform_action(self, permission, context)
    }

    /// Require permission or return error using provided permission checker
    pub fn require_permission_with_checker(
        &self,
        permission: &Permission,
        context: &ActionContext,
        checker: &dyn PermissionChecker
    ) -> Result<(), ApiError> {
        if !self.can_perform_action_with_checker(permission, context, checker) {
            return Err(ApiError::Unauthorized {
                message: format!(
                    "User {} lacks permission {:?} in context {:?}. Current state: {:?}, roles: {:?}",
                    self.user_id,
                    permission,
                    context,
                    self.user_role,
                    self.roles
                ),
            });
        }
        Ok(())
    }

    /// Get user's current capabilities using provided permission checker
    pub fn get_capabilities_with_checker(
        &self,
        context: &ActionContext,
        checker: &dyn PermissionChecker
    ) -> HashSet<Permission> {
        checker.get_user_capabilities(self, context)
    }

    // Keep deprecated methods for backward compatibility but warn about usage
    pub fn can_perform_action(&self, _permission: &Permission, _context: &ActionContext) -> bool {
        warn!(
            "Using deprecated can_perform_action without explicit checker. Use can_perform_action_with_checker instead."
        );
        false // Force explicit checker usage
    }

    pub fn require_permission(
        &self,
        _permission: &Permission,
        _context: &ActionContext
    ) -> Result<(), ApiError> {
        Err(ApiError::Unauthorized {
            message: "Permission checking requires explicit checker. Use require_permission_with_checker instead.".to_string(),
        })
    }

    pub fn get_capabilities(&self, _context: &ActionContext) -> HashSet<Permission> {
        warn!(
            "Using deprecated get_capabilities without explicit checker. Use get_capabilities_with_checker instead."
        );
        HashSet::new()
    }

    /// Check if user has specific role
    pub fn has_role(&self, role: &ClientUserRole) -> bool {
        self.roles.contains(role)
    }

    pub fn is_venue_verified(&self, venue_id: &str) -> bool {
        self.verifications
            .as_ref()
            .map(|v|
                v.venue_verifications
                    .iter()
                    .any(|vv| vv.venue_id == venue_id && vv.status == VerificationStatus::Active)
            )
            .unwrap_or(false)
    }

    /// Check if user is phone verified
    pub fn is_phone_verified(&self) -> bool {
        self.verifications
            .as_ref()
            .map(|v| v.phone_verified)
            .unwrap_or(false)
    }
}

impl UserVerifications {
    /// Add client verification using email domain (for universities, companies)
    pub fn add_client_email_verification(
        &mut self,
        client: &Client,
        verified_email: String,
        user_role: ClientUserRole
    ) -> Result<(), String> {
        // Extract domain from email
        let email_domain = verified_email
            .split('@')
            .nth(1)
            .ok_or("Invalid email format")?
            .to_string();

        // Validate against client's allowed domains
        if let Some(client_auth) = &client.auth {
            if let Some(allowed_domains) = &client_auth.allowed_email_domains {
                if !allowed_domains.iter().any(|domain| email_domain.ends_with(domain)) {
                    return Err("Email domain not allowed for this client".to_string());
                }
            }
        }

        let verification = ClientVerification {
            client_id: client.id.clone().unwrap_or_default(),
            client_name: client.name.clone(),
            verification_method: ClientVerificationMethod::EmailDomain {
                domain: format!("@{}", email_domain),
                verified_email: verified_email.clone(),
            },
            verified_email: Some(verified_email),
            token_used: None,
            user_role,
            verified_at: Utc::now(),
            expires_at: None, // Client access typically doesn't expire
            status: VerificationStatus::Active,
        };

        self.client_verifications.push(verification);
        Ok(())
    }

    /// Add client verification using token
    pub fn add_client_token_verification(
        &mut self,
        client: &Client,
        provided_token: String,
        user_role: ClientUserRole
    ) -> Result<(), String> {
        // Validate token against client's token
        if let Some(client_auth) = &client.auth {
            if let Some(client_token) = &client_auth.client_token {
                if provided_token != *client_token {
                    return Err("Invalid token for this client".to_string());
                }
            } else {
                return Err("Client does not support token verification".to_string());
            }
        }

        let verification = ClientVerification {
            client_id: client.id.clone().unwrap_or_default(),
            client_name: client.name.clone(),
            verification_method: ClientVerificationMethod::ClientToken {
                token: provided_token.clone(),
            },
            verified_email: None,
            token_used: Some(provided_token),
            user_role,
            verified_at: Utc::now(),
            expires_at: None,
            status: VerificationStatus::Active,
        };

        self.client_verifications.push(verification);
        Ok(())
    }

    /// Add venue-specific verification (for conferences, special events)
    pub fn add_venue_specific_verification(
        &mut self,
        venue: &Venue,
        method: VenueVerificationMethod,
        expires_at: Option<DateTime<Utc>>
    ) {
        let verification = VenueVerification {
            venue_id: venue.id.clone().unwrap_or_default(),
            venue_name: venue.name.clone(),
            client_id: venue.client_id.clone(),
            venue_type: venue.venue_type.clone(),
            verification_method: method,
            verified_at: Utc::now(),
            expires_at,
            status: VerificationStatus::Active,
        };

        self.venue_verifications.push(verification);
    }
}

// === Guard Implementations ===

#[rocket::async_trait]
impl<'r> FromRequest<'r> for GuardUser {
    type Error = ApiError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        debug!("Attempting user authentication for microservice request.");

        // 1. Validate internal API key
        let expected_api_key = match get_env_var(INTERNAL_API_KEY, None) {
            Ok(key) => key,
            Err(e) => {
                error!("INTERNAL_API_KEY environment variable not set: {}", e);
                return Outcome::Error((
                    Status::InternalServerError,
                    ApiError::InternalServerError {
                        message: "Authentication service misconfigured.".to_string(),
                    },
                ));
            }
        };

        let provided_api_key = request.headers().get_one(X_INTERNAL_API_KEY);
        if provided_api_key != Some(expected_api_key.as_str()) {
            warn!("Invalid or missing X-Internal-API-Key");
            return Outcome::Error((
                Status::Forbidden,
                ApiError::Unauthorized {
                    message: "Unauthorized internal access.".to_string(),
                },
            ));
        }

        // 2. Extract required headers
        let firebase_user_id = match request.headers().get_one(X_FIREBASE_UID) {
            Some(uid) => uid.to_string(),
            None => {
                return Outcome::Error((
                    Status::BadRequest,
                    ApiError::BadRequest {
                        message: "Missing X-Firebase-UID header.".to_string(),
                    },
                ));
            }
        };

        let phone_number_str = request
            .headers()
            .get_one(X_PHONE_NUMBER)
            .map(|p| p.to_string());
        let city = request
            .headers()
            .get_one(X_CITY)
            .map(|c| c.to_string());

        // 3. Parse country code from phone (if provided)
        let country_code = if let Some(ref phone) = phone_number_str {
            let parsed_phone_number_result: Result<PhoneNumber, ParseError> = phonenumber::parse(
                None,
                phone
            );

            let parsed_phone_number: PhoneNumber = match parsed_phone_number_result {
                Ok(pn) => pn,
                Err(e) => {
                    warn!(
                        "Failed to parse phone number '{}' from X-Phone-Number header: {:?}",
                        phone,
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

            let country_id_enum = match country_id_option {
                Some(country_id_enum_variant) => country_id_enum_variant,
                None => {
                    warn!("Could not derive country code from phone number '{}'. Phone number might be invalid or incomplete for country inference.", phone);
                    return Outcome::Error((
                        Status::BadRequest,
                        ApiError::BadRequest {
                            message: "Country code could not be derived from propagated phone number.".to_string(),
                        },
                    ));
                }
            };

            let country_code_alpha2 = format!("{country_id_enum:?}");
            debug!("Country code resolved from phone number: {}", country_code_alpha2);
            country_code_alpha2
        } else {
            UNKNOWN.to_string()
        };

        // 4. Get user data from User Service
        let http_client = match request.guard::<&rocket::State<Arc<reqwest::Client>>>().await {
            Outcome::Success(client) => client,
            _ => {
                error!("HttpClient not available in Rocket state");
                return Outcome::Error((
                    Status::InternalServerError,
                    ApiError::InternalServerError {
                        message: "HTTP client not configured.".to_string(),
                    },
                ));
            }
        };

        let user_service_url = match request.guard::<&rocket::State<UsersServiceUrl>>().await {
            Outcome::Success(url) => &url.0,
            _ => {
                error!("UsersServiceUrl not available in Rocket state");
                return Outcome::Error((
                    Status::InternalServerError,
                    ApiError::InternalServerError {
                        message: "User service URL not configured.".to_string(),
                    },
                ));
            }
        };

        // 5. Call user service for authentication data
        let auth_url = format!(
            "{}/users/exists?firebase_user_id={}&country_code={}",
            user_service_url,
            urlencoding::encode(&firebase_user_id),
            urlencoding::encode(&country_code)
        );

        let response = match
            http_client.get(&auth_url).header(X_INTERNAL_API_KEY, &expected_api_key).send().await
        {
            Ok(resp) => resp,
            Err(e) => {
                error!("Failed to call User Service: {}", e);
                return Outcome::Error((
                    Status::InternalServerError,
                    ApiError::InternalServerError {
                        message: "User service unavailable.".to_string(),
                    },
                ));
            }
        };

        if !response.status().is_success() {
            let status = response.status();
            debug!("User Service returned error: {}", status);
            return Outcome::Error((
                Status::InternalServerError,
                ApiError::InternalServerError {
                    message: format!("User authentication failed: {}", status),
                },
            ));
        }

        let auth_data: UserServiceAuthResponse = match response.json().await {
            Ok(data) => data,
            Err(e) => {
                error!("Failed to parse User Service response: {}", e);
                return Outcome::Error((
                    Status::InternalServerError,
                    ApiError::InternalServerError {
                        message: "Invalid user service response.".to_string(),
                    },
                ));
            }
        };

        // 6. Convert string roles to enum roles
        let roles: HashSet<ClientUserRole> = auth_data.roles
            .iter()
            .filter_map(|role_str| {
                match role_str.as_str() {
                    // University roles
                    "Student" => Some(ClientUserRole::Student),
                    "UniversityStaff" => Some(ClientUserRole::Staff), // Changed from Admin
                    "Alumni" => Some(ClientUserRole::Alumni),

                    // Coffee shop roles
                    "CoffeeShopAttendee" => Some(ClientUserRole::CoffeeShopAttendee),
                    "CoffeeShopManager" => Some(ClientUserRole::CoffeeShopManager),

                    // Coworking space roles
                    "CoworkingSpaceAttendee" => Some(ClientUserRole::CoworkingSpaceAttendee),
                    "CoworkingSpaceManager" => Some(ClientUserRole::CoworkingSpaceManager),

                    // Conference roles
                    "ConferenceAttendee" => Some(ClientUserRole::ConferenceAttendee),
                    "ConferenceSpeaker" => Some(ClientUserRole::ConferenceSpeaker),

                    // General roles
                    "Guest" => Some(ClientUserRole::Guest),
                    "Sponsor" => Some(ClientUserRole::Sponsor),
                    "System" => Some(ClientUserRole::System),

                    // Admin roles
                    "Admin" => Some(ClientUserRole::Admin), // Bondinary admin
                    "ClientAdmin" => Some(ClientUserRole::Admin), // Also maps to Admin (you may want to differentiate)

                    _ => {
                        warn!("Unknown role: {}", role_str);
                        None
                    }
                }
            })
            .collect();

        info!(
            "User authenticated: ID={}, State={:?}, Roles={:?}",
            auth_data.user_id,
            auth_data.user_role,
            roles
        );

        Outcome::Success(GuardUser {
            user_id: auth_data.user_id,
            firebase_user_id,
            phone_number: phone_number_str,
            country_code,
            city,
            user_role: Some(auth_data.user_role),
            roles,
            verifications: Some(auth_data.verifications),
        })
    }
}

// === Anonymous Guard ===

#[rocket::async_trait]
impl<'r> FromRequest<'r> for GuardAnonymous {
    type Error = ApiError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        debug!("Attempting anonymous authentication");

        // 1. Validate internal API key
        let expected_api_key = match get_env_var(INTERNAL_API_KEY, None) {
            Ok(key) => key,
            Err(_) => {
                return Outcome::Error((
                    Status::InternalServerError,
                    ApiError::InternalServerError {
                        message: "Authentication service misconfigured.".to_string(),
                    },
                ));
            }
        };

        if request.headers().get_one(X_INTERNAL_API_KEY) != Some(expected_api_key.as_str()) {
            return Outcome::Error((
                Status::Forbidden,
                ApiError::Unauthorized {
                    message: "Unauthorized internal access.".to_string(),
                },
            ));
        }

        // 2. Extract Firebase UID (required for anonymous)
        let firebase_user_id = match request.headers().get_one(X_FIREBASE_UID) {
            Some(uid) => uid.to_string(),
            None => {
                return Outcome::Error((
                    Status::BadRequest,
                    ApiError::BadRequest {
                        message: "Missing X-Firebase-UID header.".to_string(),
                    },
                ));
            }
        };

        // 4. Get user data from User Service
        let http_client = match request.guard::<&rocket::State<Arc<reqwest::Client>>>().await {
            Outcome::Success(client) => client,
            _ => {
                error!("HttpClient not available in Rocket state");
                return Outcome::Error((
                    Status::InternalServerError,
                    ApiError::InternalServerError {
                        message: "HTTP client not configured.".to_string(),
                    },
                ));
            }
        };

        let user_service_url = match request.guard::<&rocket::State<UsersServiceUrl>>().await {
            Outcome::Success(url) => &url.0,
            _ => {
                error!("UsersServiceUrl not available in Rocket state");
                return Outcome::Error((
                    Status::InternalServerError,
                    ApiError::InternalServerError {
                        message: "User service URL not configured.".to_string(),
                    },
                ));
            }
        };

        let country_code = request
            .headers()
            .get_one(X_COUNTRY_CODE)
            .map(|c| c.to_string())
            .unwrap_or_else(|| UNKNOWN.to_string());

        // 5. Call user service for authentication data
        let auth_url = format!(
            "{}/users/exists?firebase_user_id={}&country_code={}",
            user_service_url,
            urlencoding::encode(&firebase_user_id),
            urlencoding::encode(&country_code)
        );

        let response = match
            http_client.get(&auth_url).header(X_INTERNAL_API_KEY, &expected_api_key).send().await
        {
            Ok(resp) => resp,
            Err(e) => {
                error!("Failed to call User Service: {}", e);
                return Outcome::Error((
                    Status::InternalServerError,
                    ApiError::InternalServerError {
                        message: "User service unavailable.".to_string(),
                    },
                ));
            }
        };

        if !response.status().is_success() {
            let status = response.status();
            debug!("User Service returned error: {}", status);
            return Outcome::Error((
                Status::InternalServerError,
                ApiError::InternalServerError {
                    message: format!("User authentication failed: {}", status),
                },
            ));
        }

        let auth_data: UserServiceAuthResponse = match response.json().await {
            Ok(data) => data,
            Err(e) => {
                error!("Failed to parse User Service response: {}", e);
                return Outcome::Error((
                    Status::InternalServerError,
                    ApiError::InternalServerError {
                        message: "Invalid user service response.".to_string(),
                    },
                ));
            }
        };

        let city = request
            .headers()
            .get_one(X_CITY)
            .map(|c| c.to_string());

        Outcome::Success(GuardAnonymous {
            user_id: auth_data.user_id,
            firebase_user_id,
            city,
        })
    }
}

// === Flexible Guard Union ===

#[rocket::async_trait]
impl<'r> FromRequest<'r> for GuardUserOrAnonymous {
    type Error = ApiError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        // Try user authentication first
        if let Outcome::Success(user) = GuardUser::from_request(request).await {
            return Outcome::Success(GuardUserOrAnonymous::User(user));
        }

        // Fall back to anonymous
        if let Outcome::Success(anonymous) = GuardAnonymous::from_request(request).await {
            return Outcome::Success(GuardUserOrAnonymous::Anonymous(anonymous));
        }

        // Both failed
        Outcome::Error((
            Status::Unauthorized,
            ApiError::Unauthorized {
                message: "Authentication required".to_string(),
            },
        ))
    }
}

impl GuardUserOrAnonymous {
    pub fn can_perform_action_with_checker(
        &self,
        permission: &Permission,
        context: &ActionContext,
        checker: &dyn PermissionChecker
    ) -> bool {
        checker.can_perform_action_user_or_anonymous(self, permission, context)
    }

    pub fn require_permission_with_checker(
        &self,
        permission: &Permission,
        context: &ActionContext,
        checker: &dyn PermissionChecker
    ) -> Result<(), ApiError> {
        if !self.can_perform_action_with_checker(permission, context, checker) {
            return Err(ApiError::Unauthorized {
                message: format!("Permission {:?} required in context {:?}", permission, context),
            });
        }
        Ok(())
    }
}

// === Internal Guard ===

#[rocket::async_trait]
impl<'r> FromRequest<'r> for GuardInternal {
    type Error = ApiError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let expected_api_key = match get_env_var(INTERNAL_API_KEY, None) {
            Ok(key) => key,
            Err(_) => {
                return Outcome::Error((
                    Status::InternalServerError,
                    ApiError::InternalServerError {
                        message: "Internal API key not configured.".to_string(),
                    },
                ));
            }
        };

        if request.headers().get_one(X_INTERNAL_API_KEY) != Some(expected_api_key.as_str()) {
            return Outcome::Error((
                Status::Forbidden,
                ApiError::Unauthorized {
                    message: "Unauthorized internal access.".to_string(),
                },
            ));
        }

        Outcome::Success(GuardInternal)
    }
}

// === OpenAPI Implementations ===

// OpenAPI configuration for GuardUser
impl<'a> OpenApiFromRequest<'a> for GuardUser {
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
                "User's phone number in E.164 format (e.g., '+1234567890'), propagated by the API Gateway (optional).".to_owned()
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
                name: X_CITY.to_owned(),
                location: "header".to_owned(),
            },
            extensions: Object::default(),
        };

        // --- Create a Security Requirement that lists ALL of these schemes ---
        let mut security_req = SecurityRequirement::new();
        security_req.insert(internal_api_key_scheme_name.to_owned(), Vec::new());
        security_req.insert(firebase_user_id_scheme_name.to_owned(), Vec::new());
        security_req.insert(phone_number_scheme_name.to_owned(), Vec::new());
        security_req.insert(city_scheme_name.to_owned(), Vec::new());

        Ok(
            RequestHeaderInput::Security(
                "InternalMicroserviceHeaders".to_owned(),
                internal_api_key_scheme,
                security_req
            )
        )
    }
}

// OpenAPI configuration for GuardAnonymous
impl<'a> OpenApiFromRequest<'a> for GuardAnonymous {
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
                "Firebase User ID (UID) of the anonymous user, propagated by the API Gateway.".to_owned()
            ),
            data: SecuritySchemeData::ApiKey {
                name: X_FIREBASE_UID.to_owned(),
                location: "header".to_owned(),
            },
            extensions: Object::default(),
        };

        // --- 3. Define Security Scheme for X-City ---
        let city_scheme_name = "CityAuth";
        let _city_scheme = SecurityScheme {
            description: Some("User's city, propagated by the API Gateway (optional).".to_owned()),
            data: SecuritySchemeData::ApiKey {
                name: X_CITY.to_owned(),
                location: "header".to_owned(),
            },
            extensions: Object::default(),
        };

        // --- Create a Security Requirement ---
        let mut security_req = SecurityRequirement::new();
        security_req.insert(internal_api_key_scheme_name.to_owned(), Vec::new());
        security_req.insert(firebase_user_id_scheme_name.to_owned(), Vec::new());
        security_req.insert(city_scheme_name.to_owned(), Vec::new());

        Ok(
            RequestHeaderInput::Security(
                "InternalMicroserviceHeaders".to_owned(),
                internal_api_key_scheme,
                security_req
            )
        )
    }
}

// OpenAPI configuration for GuardUserOrAnonymous
impl<'a> OpenApiFromRequest<'a> for GuardUserOrAnonymous {
    fn from_request_input(
        _gen: &mut OpenApiGenerator,
        _name: String,
        _required: bool
    ) -> rocket_okapi::Result<RequestHeaderInput> {
        // This guard accepts either user or anonymous authentication
        // We'll document it as the more complete user authentication scheme

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
                "Firebase User ID (UID) - required for both authenticated and anonymous users.".to_owned()
            ),
            data: SecuritySchemeData::ApiKey {
                name: X_FIREBASE_UID.to_owned(),
                location: "header".to_owned(),
            },
            extensions: Object::default(),
        };

        // --- Create a Security Requirement (only required headers) ---
        let mut security_req = SecurityRequirement::new();
        security_req.insert(internal_api_key_scheme_name.to_owned(), Vec::new());
        security_req.insert(firebase_user_id_scheme_name.to_owned(), Vec::new());

        // Note: Phone and City are optional, so we don't include them as required

        Ok(
            RequestHeaderInput::Security(
                "FlexibleUserOrAnonymousAuth".to_owned(),
                internal_api_key_scheme,
                security_req
            )
        )
    }
}

// OpenAPI configuration for GuardInternal
impl<'a> OpenApiFromRequest<'a> for GuardInternal {
    fn from_request_input(
        _gen: &mut OpenApiGenerator,
        _name: String,
        _required: bool
    ) -> rocket_okapi::Result<RequestHeaderInput> {
        // --- 1. Define Security Scheme for X-Internal-API-Key ---
        let internal_api_key_scheme_name = "InternalApiKeyAuth";
        let internal_api_key_scheme = SecurityScheme {
            description: Some(
                "Internal API key to authenticate internal service calls.".to_owned()
            ),
            data: SecuritySchemeData::ApiKey {
                name: X_INTERNAL_API_KEY.to_owned(),
                location: "header".to_owned(),
            },
            extensions: Object::default(),
        };

        // --- Create a Security Requirement ---
        let mut security_req = SecurityRequirement::new();
        security_req.insert(internal_api_key_scheme_name.to_owned(), Vec::new());

        Ok(
            RequestHeaderInput::Security(
                "InternalServiceAuth".to_owned(),
                internal_api_key_scheme,
                security_req
            )
        )
    }
}
