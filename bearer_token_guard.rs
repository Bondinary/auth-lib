//! # Bearer Token Guard Module
//!
//! This module provides authentication guards for Rocket applications with comprehensive
//! user verification, role-based access control, and OpenAPI documentation support.
//!
//! ## Guard Types
//! - `GuardUser`: Authenticated users with full permissions
//! - `GuardAnonymous`: Anonymous users with limited access
//! - `GuardUserOrAnonymous`: Flexible guard accepting either type
//! - `GuardAnonymousRegistration`: For user registration flows
//! - `GuardPreRegistration`: For pre-registration validation
//! - `GuardInternal`: For internal service-to-service calls
//!
//! ## Verification System
//! Supports multi-level verification including phone, email domain, client tokens,
//! and venue-specific access control.

// ============================================================================
// IMPORTS
// ============================================================================

use backend_domain::UserRole;
use backend_domain::{ Venue, VenueType };
use backend_domain::{ AuthType, Client, ClientAuth, ClientUserRole };
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
use crate::common_lib::country_utils::CountryService;
use crate::common_lib::geolocation::{ GeolocationService, extract_client_ip_from_headers };
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
use std::collections::HashSet;
use std::sync::{ Arc };
use tracing::{ debug, error, info, warn };
use crate::{ common_lib, UserExistsResponse };
use crate::auth_lib::permissions::{ ActionContext, Permission, PermissionChecker };
use rocket_okapi::request::{ OpenApiFromRequest };

// ============================================================================
// CORE TYPES & UTILITIES
// ============================================================================

/// Struct to represent the BearerToken
pub struct BearerToken(pub String);

/// Service URL configuration for internal communication
#[derive(Debug, Clone)]
pub struct UsersServiceUrl(pub String);

// ============================================================================
// SHARED HELPER FUNCTIONS
// ============================================================================

/// Common API key validation logic used by all guards
fn validate_internal_api_key(request: &Request<'_>) -> Result<String, ApiError> {
    let expected_api_key = get_env_var(INTERNAL_API_KEY, None).map_err(|e| {
        error!("INTERNAL_API_KEY environment variable not set: {}", e);
        ApiError::InternalServerError {
            message: "Authentication service misconfigured.".to_string(),
        }
    })?;

    let provided_api_key = request.headers().get_one(X_INTERNAL_API_KEY);
    if provided_api_key != Some(expected_api_key.as_str()) {
        warn!("Invalid or missing X-Internal-API-Key");
        return Err(ApiError::Unauthorized {
            message: "Unauthorized internal access.".to_string(),
        });
    }

    Ok(expected_api_key)
}

/// Extract HTTP client and user service URL from Rocket state
async fn get_http_dependencies<'a>(
    request: &'a Request<'_>
) -> Result<(&'a Arc<reqwest::Client>, &'a str), ApiError> {
    let http_client = request
        .guard::<&rocket::State<Arc<reqwest::Client>>>().await
        .succeeded()
        .ok_or_else(|| {
            error!("HttpClient not available in Rocket state");
            ApiError::InternalServerError {
                message: "HTTP client not configured.".to_string(),
            }
        })?;

    let user_service_url = request
        .guard::<&rocket::State<UsersServiceUrl>>().await
        .succeeded()
        .ok_or_else(|| {
            error!("UsersServiceUrl not available in Rocket state");
            ApiError::InternalServerError {
                message: "User service URL not configured.".to_string(),
            }
        })?;

    Ok((http_client, &user_service_url.0))
}

/// Convert role strings from API to ClientUserRole enums
fn convert_role_strings(role_strings: &[String]) -> HashSet<ClientUserRole> {
    role_strings
        .iter()
        .filter_map(|role_str| {
            match role_str.as_str() {
                // University roles
                "Student" => Some(ClientUserRole::Student),
                "UniversityStaff" => Some(ClientUserRole::Staff),
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
                "Admin" => Some(ClientUserRole::Admin),
                "ClientAdmin" => Some(ClientUserRole::Admin),
                _ => {
                    warn!("Unknown role: {}", role_str);
                    None
                }
            }
        })
        .collect()
}

/// Call user service and handle common response patterns
async fn call_user_service(
    http_client: &reqwest::Client,
    auth_url: &str,
    api_key: &str
) -> Result<UserExistsResponse, ApiError> {
    let response = http_client
        .get(auth_url)
        .header(X_INTERNAL_API_KEY, api_key)
        .send().await
        .map_err(|e| {
            error!("Failed to call User Service: {}", e);
            ApiError::InternalServerError {
                message: "User service unavailable.".to_string(),
            }
        })?;

    if !response.status().is_success() {
        let status = response.status();
        return Err(match status.as_u16() {
            404 =>
                ApiError::BadRequest {
                    message: "User not found".to_string(),
                },
            _ => {
                error!("User Service returned error: {}", status);
                ApiError::InternalServerError {
                    message: format!("User authentication failed: {}", status),
                }
            }
        });
    }

    response.json().await.map_err(|e| {
        error!("Failed to parse User Service response: {}", e);
        ApiError::InternalServerError {
            message: "Invalid user service response.".to_string(),
        }
    })
}

/// Create common OpenAPI security scheme for internal API key
fn create_internal_api_key_scheme() -> SecurityScheme {
    SecurityScheme {
        description: Some(
            "Internal API key to authenticate the calling service (e.g., API Gateway).".to_owned()
        ),
        data: SecuritySchemeData::ApiKey {
            name: X_INTERNAL_API_KEY.to_owned(),
            location: "header".to_owned(),
        },
        extensions: Object::default(),
    }
}

/// Create Firebase UID security scheme
fn create_firebase_uid_scheme(description: &str) -> SecurityScheme {
    SecurityScheme {
        description: Some(description.to_owned()),
        data: SecuritySchemeData::ApiKey {
            name: X_FIREBASE_UID.to_owned(),
            location: "header".to_owned(),
        },
        extensions: Object::default(),
    }
}

// ============================================================================
// GUARD STRUCTS
// ============================================================================

/// Guard for anonymous users with basic identification
#[derive(Debug, Clone)]
pub struct GuardAnonymous {
    pub user_id: String,
    pub firebase_user_id: String,
    pub country_code: String,
    pub city: Option<String>,
}

/// Guard for authenticated users with full access and verification status
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

/// Flexible guard that accepts either authenticated or anonymous users
#[derive(Debug, Clone)]
pub enum GuardUserOrAnonymous {
    User(GuardUser),
    Anonymous(GuardAnonymous),
}

/// Guard for anonymous user registration flows
#[derive(Debug, Clone)]
pub struct GuardAnonymousRegistration {
    pub firebase_user_id: String,
    pub country_code: String,
    pub city: Option<String>,
}

/// Guard for pre-registration validation
#[derive(Debug, Clone)]
pub struct GuardPreRegistration {
    pub user_id: String,
    pub firebase_user_id: String,
    pub phone_number: Option<String>,
    pub country_code: String,
}

/// Guard for internal service-to-service authentication
#[derive(Debug, Clone)]
pub struct GuardInternal;

// ============================================================================
// VERIFICATION SYSTEM
// ============================================================================

/// Comprehensive user verification status including phone, client, and venue verifications
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UserVerifications {
    pub phone_verified: bool,
    pub phone_verified_at: Option<DateTime<Utc>>,
    /// Client-level verifications (University, Company, Organization)
    pub client_verifications: Vec<ClientVerification>,
    /// Venue-specific verifications (for special events, conferences, etc.)
    pub venue_verifications: Vec<VenueVerification>,
}

/// Client-level verification for organizations, universities, companies
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClientVerification {
    pub client_id: String, // References Client.id from venues service
    pub client_name: String, // University name, Company name, etc.
    pub verification_method: ClientVerificationMethod,
    pub verified_email: Option<String>, // For email domain verification
    pub token_used: Option<String>, // For token verification
    pub user_role: ClientUserRole, // Role within this client organization
    pub verified_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub status: VerificationStatus,
}

/// Venue-specific verification for events, conferences, special access
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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

// ============================================================================
// VERIFICATION ENUMS
// ============================================================================

/// Methods for client verification
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

/// Methods for venue-specific verification
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

/// General verification method types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum VerificationMethod {
    Email,
    Token,
    Manual,
}

/// Verification status states
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum VerificationStatus {
    Active,
    Expired,
    Revoked,
}

/// Client access scope configuration
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ClientScope {
    AllVenues,
    SpecificVenues(Vec<String>),
    VenueTypes(Vec<VenueType>),
}

// ============================================================================
// GUARD USER IMPLEMENTATIONS
// ============================================================================

impl GuardUser {
    /// Check if user can access a specific client (based on existing Client model)
    /// Check if user can access a specific client (based on existing Client model)
    /// LOW-LEVEL VERIFICATION CHECK: Direct verification status validation
    /// Use this for: Quick verification status checks, audit trails, debugging
    /// For business logic permissions, use: PolicyEngine.evaluate_permission()
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
    /// LOW-LEVEL VERIFICATION CHECK: Auth requirement validation
    /// Use this for: Venue entry validation, quick auth checks
    /// For business logic permissions, use: PolicyEngine.evaluate_permission()
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
                _ => false,
            }
        } else {
            // No auth config means open access
            true
        }
    }

    /// Check if user has email domain verification for this client
    /// LOW-LEVEL VERIFICATION CHECK: Email domain verification status
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
    /// LOW-LEVEL VERIFICATION CHECK: Token verification status
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
    /// LOW-LEVEL VERIFICATION CHECK: Venue-specific verification status
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
    /// LOW-LEVEL VERIFICATION CHECK: Role lookup within client
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
    /// HIGH-LEVEL BUSINESS LOGIC: Use PolicyEngine for complex permission evaluation
    /// Example: "Can this student create content during exam period?"
    /// For simple verification checks, use: can_access_client(), has_venue_specific_verification()
    pub fn can_perform_action_with_checker(
        &self,
        permission: &Permission,
        context: &ActionContext,
        checker: &dyn PermissionChecker
    ) -> bool {
        checker.can_perform_action(self, permission, context)
    }

    /// Require permission or return error using provided permission checker
    /// HIGH-LEVEL BUSINESS LOGIC: Use PolicyEngine for complex permission validation
    /// Example: Validate "CanCreateSponsorContent" with venue type restrictions
    /// For simple verification checks, use: can_access_client(), has_venue_specific_verification()
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
    /// HIGH-LEVEL BUSINESS LOGIC: Use PolicyEngine to get all available permissions
    /// Example: Get all permissions available to this user in this venue
    /// For simple verification checks, use: get_client_role(), is_phone_verified()
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
        let expected_api_key = match validate_internal_api_key(request) {
            Ok(key) => key,
            Err(e) => {
                return Outcome::Error((
                    Status::from_code(e.status_code()).unwrap_or(Status::InternalServerError),
                    e,
                ));
            }
        };

        // 2. Extract required headers
        let firebase_user_id = match request.headers().get_one(X_FIREBASE_UID) {
            Some(uid) => uid.to_string(),
            _ => {
                return Outcome::Error((
                    Status::BadRequest,
                    ApiError::BadRequest {
                        message: "Missing X-Firebase-UID header.".to_string(),
                    },
                ));
            }
        };

        let phone_number = match request.headers().get_one(X_PHONE_NUMBER) {
            Some(phone) => phone.to_string(),
            _ => {
                return Outcome::Error((
                    Status::BadRequest,
                    ApiError::BadRequest {
                        message: "Missing X-Phone-Number header.".to_string(),
                    },
                ));
            }
        };

        let city = request
            .headers()
            .get_one(X_CITY)
            .map(|c| c.to_string());

        // 3. Parse country code from phone (if provided)
        let country_code = match CountryService::parse_phone_number_to_country(&phone_number) {
            Ok(cc) => cc,
            Err(e) => {
                return Outcome::Error((
                    Status::from_code(e.status_code()).unwrap_or(Status::BadRequest),
                    e,
                ));
            }
        };

        // 4. Get HTTP dependencies
        let (http_client, user_service_url) = match get_http_dependencies(request).await {
            Ok(deps) => deps,
            Err(e) => {
                return Outcome::Error((
                    Status::from_code(e.status_code()).unwrap_or(Status::InternalServerError),
                    e,
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

        let auth_data = match call_user_service(http_client, &auth_url, &expected_api_key).await {
            Ok(data) => data,
            Err(ApiError::BadRequest { .. }) => {
                // User not found - they need to register
                let endpoint_path = request.uri().path().to_string();
                let action_description = Self::get_action_description(&endpoint_path);

                info!(
                    "Unregistered user with firebase_id {} attempted to access endpoint: {}",
                    firebase_user_id,
                    endpoint_path
                );

                return Outcome::Error((
                    Status::PreconditionRequired, // 428
                    ApiError::registration_required(&action_description),
                ));
            }
            Err(e) => {
                return Outcome::Error((
                    Status::from_code(e.status_code()).unwrap_or(Status::InternalServerError),
                    e,
                ));
            }
        };

        // 6. Check if this is an anonymous user trying to access registered-only endpoint
        if auth_data.user_role == UserRole::Anonymous {
            let endpoint_path = request.uri().path().to_string();
            let action_description = Self::get_action_description(&endpoint_path);

            info!(
                "Anonymous user {} attempted to access registered-only endpoint: {}",
                auth_data.user_id,
                endpoint_path
            );

            return Outcome::Error((
                Status::PreconditionRequired, // 428
                ApiError::registration_required(&action_description),
            ));
        }

        // 7. Convert string roles to enum roles
        let roles = convert_role_strings(&auth_data.roles);

        info!(
            "User authenticated: ID={}, State={:?}, Roles={:?}, Country={}",
            auth_data.user_id,
            auth_data.user_role,
            roles,
            auth_data.country_code
        );

        Outcome::Success(GuardUser {
            user_id: auth_data.user_id,
            firebase_user_id,
            phone_number: Some(phone_number),
            country_code,
            city,
            user_role: Some(auth_data.user_role),
            roles,
            verifications: None,
        })
    }
}

impl GuardUser {
    /// Extract action description from endpoint path for better user messaging
    fn get_action_description(endpoint_path: &str) -> String {
        match endpoint_path {
            path if path.contains("comments") => "add comments".to_string(),
            path if path.contains("private-sparks") => "create or manage sparks".to_string(),
            path if path.contains("users/update") => "update your profile".to_string(),
            path if path.contains("users/my-profile") => "view your profile".to_string(),
            path if path.contains("qr-code") => "generate QR codes".to_string(),
            _ => "perform this action".to_string(),
        }
    }
}

// === Anonymous Guard ===

#[rocket::async_trait]
impl<'r> FromRequest<'r> for GuardAnonymous {
    type Error = ApiError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        debug!("Attempting anonymous authentication");

        // 1. Validate internal API key
        let expected_api_key = match validate_internal_api_key(request) {
            Ok(key) => key,
            Err(e) => {
                return Outcome::Error((
                    Status::from_code(e.status_code()).unwrap_or(Status::InternalServerError),
                    e,
                ));
            }
        };

        // 2. Extract Firebase UID (required for anonymous)
        let firebase_user_id = match request.headers().get_one(X_FIREBASE_UID) {
            Some(uid) => uid.to_string(),
            _ => {
                return Outcome::Error((
                    Status::BadRequest,
                    ApiError::BadRequest {
                        message: "Missing X-Firebase-UID header.".to_string(),
                    },
                ));
            }
        };

        // 3. Get HTTP dependencies
        let (http_client, user_service_url) = match get_http_dependencies(request).await {
            Ok(deps) => deps,
            Err(e) => {
                return Outcome::Error((
                    Status::from_code(e.status_code()).unwrap_or(Status::InternalServerError),
                    e,
                ));
            }
        };

        let country_code = request
            .headers()
            .get_one(X_COUNTRY_CODE)
            .map(|c| c.to_string())
            .unwrap_or_else(|| UNKNOWN.to_string());

        // 4. Call user service for authentication data
        let auth_url = format!(
            "{}/users/exists?firebase_user_id={}&country_code={}",
            user_service_url,
            urlencoding::encode(&firebase_user_id),
            urlencoding::encode(&country_code)
        );

        let auth_data = match call_user_service(http_client, &auth_url, &expected_api_key).await {
            Ok(data) => data,
            Err(e) => {
                return Outcome::Error((
                    Status::from_code(e.status_code()).unwrap_or(Status::InternalServerError),
                    e,
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
            country_code,
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
        match validate_internal_api_key(request) {
            Ok(_) => Outcome::Success(GuardInternal),
            Err(e) =>
                Outcome::Error((
                    Status::from_code(e.status_code()).unwrap_or(Status::InternalServerError),
                    e,
                )),
        }
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for GuardPreRegistration {
    type Error = ApiError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        debug!("Attempting user authentication for pre registration request.");

        // 1. Validate internal API key
        let expected_api_key = match validate_internal_api_key(request) {
            Ok(key) => key,
            Err(e) => {
                return Outcome::Error((
                    Status::from_code(e.status_code()).unwrap_or(Status::InternalServerError),
                    e,
                ));
            }
        };

        // 2. Extract required headers
        let firebase_user_id = match request.headers().get_one(X_FIREBASE_UID) {
            Some(uid) => uid.to_string(),
            _ => {
                return Outcome::Error((
                    Status::BadRequest,
                    ApiError::BadRequest {
                        message: "Missing X-Firebase-UID header.".to_string(),
                    },
                ));
            }
        };

        let phone_number = match request.headers().get_one(X_PHONE_NUMBER) {
            Some(phone) => phone.to_string(),
            _ => {
                return Outcome::Error((
                    Status::BadRequest,
                    ApiError::BadRequest {
                        message: "Missing X-Phone-Number header.".to_string(),
                    },
                ));
            }
        };

        // 3. Parse country code from phone
        let country_code_from_phone_number = match
            CountryService::parse_phone_number_to_country(&phone_number)
        {
            Ok(cc) => cc,
            Err(e) => {
                return Outcome::Error((
                    Status::from_code(e.status_code()).unwrap_or(Status::BadRequest),
                    e,
                ));
            }
        };

        // 4. Get HTTP dependencies
        let (http_client, user_service_url) = match get_http_dependencies(request).await {
            Ok(deps) => deps,
            Err(e) => {
                return Outcome::Error((
                    Status::from_code(e.status_code()).unwrap_or(Status::InternalServerError),
                    e,
                ));
            }
        };

        let country_code_from_header = request
            .headers()
            .get_one(X_COUNTRY_CODE)
            .map(|c| c.to_string())
            .unwrap_or_else(|| {
                debug!("No X-Country-Code header found, using UNKNOWN for anonymous registration");
                UNKNOWN.to_string()
            });

        // 5. Call user service for authentication data
        let auth_url = format!(
            "{}/users/exists?firebase_user_id={}&country_code={}",
            user_service_url,
            urlencoding::encode(&firebase_user_id),
            urlencoding::encode(&country_code_from_header)
        );

        let auth_data = match call_user_service(http_client, &auth_url, &expected_api_key).await {
            Ok(data) => data,
            Err(ApiError::BadRequest { .. }) => {
                // User not found - they need to register
                let endpoint_path = request.uri().path().to_string();

                info!(
                    "Unregistered user with firebase_id {} attempted to access endpoint: {}",
                    firebase_user_id,
                    endpoint_path
                );

                return Outcome::Error((
                    Status::PreconditionRequired, // 428
                    ApiError::registration_required(&endpoint_path),
                ));
            }
            Err(e) => {
                return Outcome::Error((
                    Status::from_code(e.status_code()).unwrap_or(Status::InternalServerError),
                    e,
                ));
            }
        };

        Outcome::Success(GuardPreRegistration {
            user_id: auth_data.user_id,
            firebase_user_id,
            phone_number: Some(phone_number),
            country_code: country_code_from_phone_number,
        })
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
        let internal_api_key_scheme = create_internal_api_key_scheme();
        let _firebase_uid_scheme = create_firebase_uid_scheme(
            "Firebase User ID (UID) of the authenticated user, propagated by the API Gateway."
        );

        let mut security_req = SecurityRequirement::new();
        security_req.insert("InternalApiKeyAuth".to_owned(), Vec::new());
        security_req.insert("FirebaseUidAuth".to_owned(), Vec::new());
        security_req.insert("PhoneNumberAuth".to_owned(), Vec::new());
        security_req.insert("CityAuth".to_owned(), Vec::new());

        Ok(
            RequestHeaderInput::Security(
                "InternalMicroserviceHeaders".to_owned(),
                internal_api_key_scheme,
                security_req
            )
        )
    }
}

// OpenAPI configuration for GuardUser
impl<'a> OpenApiFromRequest<'a> for GuardPreRegistration {
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

        // --- Create a Security Requirement that lists ALL of these schemes ---
        let mut security_req = SecurityRequirement::new();
        security_req.insert(internal_api_key_scheme_name.to_owned(), Vec::new());
        security_req.insert(firebase_user_id_scheme_name.to_owned(), Vec::new());
        security_req.insert(phone_number_scheme_name.to_owned(), Vec::new());

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

#[rocket::async_trait]
impl<'r> FromRequest<'r> for GuardAnonymousRegistration {
    type Error = ApiError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        debug!("Attempting anonymous registration authentication");

        // 1. Validate internal API key
        match validate_internal_api_key(request) {
            Ok(_) => {}
            Err(e) => {
                return Outcome::Error((
                    Status::from_code(e.status_code()).unwrap_or(Status::InternalServerError),
                    e,
                ));
            }
        }

        // 2. Extract Firebase UID (required)
        let firebase_user_id = match request.headers().get_one(X_FIREBASE_UID) {
            Some(uid) => uid.to_string(),
            _ => {
                return Outcome::Error((
                    Status::BadRequest,
                    ApiError::BadRequest {
                        message: "Missing X-Firebase-UID header.".to_string(),
                    },
                ));
            }
        };

        // 3. Get country code and city using geolocation if not provided in headers
        let (country_code, city) = match
            (request.headers().get_one(X_COUNTRY_CODE), request.headers().get_one(X_CITY))
        {
            // Both headers provided - use them directly
            (Some(country), Some(city_header)) => {
                debug!("Using country and city from headers: {}, {}", country, city_header);
                (country.to_string(), Some(city_header.to_string()))
            }
            // Only country provided - use it and try to get city from geolocation
            (Some(country), _) => {
                debug!("Country provided in header, attempting to get city from geolocation");
                let city = match extract_client_ip_from_headers(request.headers()) {
                    Some(ip) => {
                        match
                            request.guard::<&rocket::State<GeolocationService>>().await.succeeded()
                        {
                            Some(geo_service) => {
                                match geo_service.get_location(&ip).await {
                                    Ok(location) => {
                                        debug!(
                                            "Geolocation successful for IP {}: city={:?}",
                                            ip,
                                            location.city
                                        );
                                        location.city
                                    }
                                    Err(e) => {
                                        warn!("Geolocation failed for IP {}: {}", ip, e);
                                        None
                                    }
                                }
                            }
                            _ => {
                                warn!("GeolocationService not available in Rocket state");
                                None
                            }
                        }
                    }
                    _ => {
                        debug!("No client IP found in headers for geolocation");
                        None
                    }
                };
                (country.to_string(), city)
            }
            // No country or city headers - use geolocation for both
            _ => {
                debug!("No country/city headers found, using geolocation for both");
                match extract_client_ip_from_headers(request.headers()) {
                    Some(ip) => {
                        match
                            request.guard::<&rocket::State<GeolocationService>>().await.succeeded()
                        {
                            Some(geo_service) => {
                                match geo_service.get_location(&ip).await {
                                    Ok(location) => {
                                        debug!(
                                            "Geolocation successful for IP {}: country={}, city={:?}",
                                            ip,
                                            location.country_code,
                                            location.city
                                        );
                                        (location.country_code, location.city)
                                    }
                                    Err(e) => {
                                        warn!(
                                            "Geolocation failed for IP {}, using default: {}",
                                            ip,
                                            e
                                        );
                                        (UNKNOWN.to_string(), None)
                                    }
                                }
                            }
                            _ => {
                                warn!(
                                    "GeolocationService not available in Rocket state, using default"
                                );
                                (UNKNOWN.to_string(), None)
                            }
                        }
                    }
                    _ => {
                        debug!("No client IP found in headers, using default country");
                        (UNKNOWN.to_string(), None)
                    }
                }
            }
        };

        debug!(
            "Anonymous registration guard created: firebase_user_id={}, country_code={}, city={:?}",
            firebase_user_id,
            country_code,
            city
        );

        // No database lookup - just validate headers for registration
        Outcome::Success(GuardAnonymousRegistration {
            firebase_user_id,
            country_code,
            city,
        })
    }
}

// Add this OpenAPI implementation after the other OpenAPI implementations
impl<'a> OpenApiFromRequest<'a> for GuardAnonymousRegistration {
    fn from_request_input(
        _gen: &mut OpenApiGenerator,
        _name: String,
        _required: bool
    ) -> rocket_okapi::Result<RequestHeaderInput> {
        // --- 1. Define Security Scheme for X-Internal-API-Key ---
        let internal_api_key_scheme_name = "InternalApiKeyAuth";
        let internal_api_key_scheme = SecurityScheme {
            description: Some(
                "Internal API key to authenticate the calling service for anonymous user registration.".to_owned()
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
                "Firebase User ID (UID) of the anonymous user to be registered.".to_owned()
            ),
            data: SecuritySchemeData::ApiKey {
                name: X_FIREBASE_UID.to_owned(),
                location: "header".to_owned(),
            },
            extensions: Object::default(),
        };

        // --- 3. Define Security Scheme for X-Country-Code ---
        let _country_code_scheme_name = "CountryCodeAuth";
        let _country_code_scheme = SecurityScheme {
            description: Some(
                "Country code for anonymous registration (optional, defaults to 'UNKNOWN').".to_owned()
            ),
            data: SecuritySchemeData::ApiKey {
                name: X_COUNTRY_CODE.to_owned(),
                location: "header".to_owned(),
            },
            extensions: Object::default(),
        };

        // --- 4. Define Security Scheme for X-City ---
        let _city_scheme_name = "CityAuth";
        let _city_scheme = SecurityScheme {
            description: Some("User's city for anonymous registration (optional).".to_owned()),
            data: SecuritySchemeData::ApiKey {
                name: X_CITY.to_owned(),
                location: "header".to_owned(),
            },
            extensions: Object::default(),
        };

        // --- Create a Security Requirement (only required headers) ---
        let mut security_req = SecurityRequirement::new();
        security_req.insert(internal_api_key_scheme_name.to_owned(), Vec::new());
        security_req.insert(firebase_user_id_scheme_name.to_owned(), Vec::new());

        Ok(
            RequestHeaderInput::Security(
                "AnonymousRegistrationAuth".to_owned(),
                internal_api_key_scheme,
                security_req
            )
        )
    }
}
