use crate::auth_lib::auth_helper::AuthHelper;
use crate::common_lib::country_utils::CountryService;
use crate::common_lib::error::ApiError;
use backend_domain::UserRole;
use log::{ debug, error, info, warn };
use std::collections::HashMap;
use std::sync::{ Arc, Mutex };
use std::time::{ Duration, Instant };

/// Cached authentication result with timestamp
#[derive(Debug, Clone)]
struct CachedAuthResult {
    user: AuthenticatedUser,
    cached_at: Instant,
}

/// Shared authentication service for both REST (GuardUser) and WebSocket
///
/// This service consolidates authentication logic to eliminate duplication:
/// - REST endpoints: Get pre-validated Firebase UID from headers (via API Gateway)
/// - WebSocket: Get JWT token and validate it here (no API Gateway validation)
///
/// Both paths converge to the same user service lookup with country_code fallback.
///
/// 🔥 CRITICAL PERFORMANCE OPTIMIZATION:
/// Auth results are cached for 5 minutes to prevent MongoDB overload.
/// Without caching: 16 requests/8s = 16 MongoDB queries
/// With caching: 16 requests/8s = 1 MongoDB query (94% reduction)
#[derive(Clone)]
pub struct AuthenticationService {
    auth_helper: Arc<AuthHelper>,
    http_client: Arc<reqwest::Client>,
    users_service_url: String,
    internal_api_key: String,
    /// Auth result cache: key = "firebase_uid:country_code"
    /// TTL: 5 minutes (300 seconds)
    auth_cache: Arc<Mutex<HashMap<String, CachedAuthResult>>>,
    cache_ttl: Duration,
}

impl AuthenticationService {
    pub fn new(
        auth_helper: Arc<AuthHelper>,
        http_client: Arc<reqwest::Client>,
        users_service_url: String,
        internal_api_key: String
    ) -> Self {
        Self {
            auth_helper,
            http_client,
            users_service_url,
            internal_api_key,
            auth_cache: Arc::new(Mutex::new(HashMap::new())),
            cache_ttl: Duration::from_secs(300), // 5 minutes
        }
    }

    /// Cleanup stale cache entries older than TTL
    /// Should be called periodically (e.g., every 5 minutes)
    pub fn cleanup_auth_cache(&self) -> usize {
        let mut cache = self.auth_cache.lock().unwrap();
        let initial_size = cache.len();

        cache.retain(|_, cached_result| { cached_result.cached_at.elapsed() < self.cache_ttl });

        let removed = initial_size - cache.len();
        if removed > 0 {
            debug!(
                "🧹 Cleaned up {} stale auth cache entries (remaining: {})",
                removed,
                cache.len()
            );
        }
        removed
    }

    /// Authenticate user from pre-validated Firebase UID and phone number
    ///
    /// Used by: GuardUser (REST APIs)
    /// - Receives Firebase UID from X-Firebase-UID header (already validated by API Gateway)
    /// - Receives phone number from X-Phone-Number header
    /// - No JWT validation needed
    ///
    /// 🔥 PERFORMANCE: Results cached for 5 minutes
    pub async fn authenticate_from_headers(
        &self,
        firebase_uid: &str,
        phone_number: &str
    ) -> Result<AuthenticatedUser, ApiError> {
        debug!("🔐 Authenticating from headers: firebase_uid={}", firebase_uid);

        // Parse country code from phone number
        let country_code = CountryService::parse_phone_number_to_country(phone_number).map_err(|e| {
            error!("❌ Failed to parse country code from phone: {}", e);
            e
        })?;

        // Check cache first
        let cache_key = format!("{}:{}", firebase_uid, country_code);
        {
            let cache = self.auth_cache.lock().unwrap();
            if let Some(cached_result) = cache.get(&cache_key) {
                if cached_result.cached_at.elapsed() < self.cache_ttl {
                    debug!(
                        "⚡ Auth cache HIT: firebase_uid={}, age={}ms (TTL=300s)",
                        firebase_uid,
                        cached_result.cached_at.elapsed().as_millis()
                    );
                    return Ok(cached_result.user.clone());
                } else {
                    debug!("⏰ Auth cache EXPIRED: firebase_uid={}", firebase_uid);
                }
            }
        }

        debug!("🔍 Auth cache MISS: firebase_uid={} (querying database)", firebase_uid);

        // Cache miss - query database
        let user = self.lookup_user(firebase_uid, &country_code, phone_number).await?;

        // Store in cache
        {
            let mut cache = self.auth_cache.lock().unwrap();
            cache.insert(cache_key, CachedAuthResult {
                user: user.clone(),
                cached_at: Instant::now(),
            });
            debug!(
                "💾 Auth result cached: firebase_uid={} (cache_size={})",
                firebase_uid,
                cache.len()
            );
        }

        Ok(user)
    }

    /// Authenticate user from Firebase JWT token
    ///
    /// Used by: WebSocket handler
    /// - Receives raw JWT token from query parameter
    /// - Validates JWT signature and expiration
    /// - Extracts Firebase UID and phone from claims
    /// - Uses same lookup pattern as REST API (with country_code fallback)
    ///
    /// 🔥 PERFORMANCE: Results cached for 5 minutes
    pub async fn authenticate_from_token(
        &self,
        firebase_token: &str
    ) -> Result<AuthenticatedUser, ApiError> {
        debug!("🔐 Authenticating from JWT token (WebSocket)");

        // 1. Validate Firebase JWT
        let claims = self.auth_helper
            .validate_firebase_access_token(firebase_token).await
            .map_err(|e| {
                error!("❌ JWT validation failed: {}", e);
                ApiError::Unauthorized {
                    message: format!("Invalid Firebase token: {}", e),
                }
            })?;

        // 2. Extract Firebase UID from claims
        let firebase_uid = claims.sub.clone();
        if firebase_uid.is_empty() {
            error!("❌ Firebase UID is empty in token claims");
            return Err(ApiError::Unauthorized {
                message: "Firebase UID not found in token".to_string(),
            });
        }

        info!("🔍 Firebase token validated: firebase_uid={}", firebase_uid);

        // 3. Extract phone number from claims (REQUIRED)
        let phone_number = claims.phone_number.clone();
        if phone_number.is_empty() {
            error!("❌ Phone number missing in token claims - authentication failed");
            return Err(ApiError::Unauthorized {
                message: "Phone number not found in token claims".to_string(),
            });
        }

        info!("🔍 Phone number extracted from token: {}", phone_number);

        // 4. Parse country code from phone (same as REST API)
        let country_code = CountryService::parse_phone_number_to_country(&phone_number).map_err(
            |e| {
                error!("❌ Failed to parse country code from phone: {}", e);
                e
            }
        )?;

        info!("🔍 Country code parsed: {}", country_code);

        // 5. Check cache (same as REST API)
        let cache_key = format!("{}:{}", firebase_uid, country_code);
        {
            let cache = self.auth_cache.lock().unwrap();
            if let Some(cached_result) = cache.get(&cache_key) {
                if cached_result.cached_at.elapsed() < self.cache_ttl {
                    debug!(
                        "⚡ Auth cache HIT (WebSocket): firebase_uid={}, age={}ms",
                        firebase_uid,
                        cached_result.cached_at.elapsed().as_millis()
                    );
                    return Ok(cached_result.user.clone());
                }
            }
        }

        debug!("🔍 Auth cache MISS (WebSocket): firebase_uid={}", firebase_uid);

        // 6. Cache miss - query database with fallback (same as REST API)
        let user = self.lookup_user(&firebase_uid, &country_code, &phone_number).await?;

        // Store in cache
        {
            let mut cache = self.auth_cache.lock().unwrap();
            cache.insert(cache_key, CachedAuthResult {
                user: user.clone(),
                cached_at: Instant::now(),
            });
            debug!("💾 Auth result cached (WebSocket): firebase_uid={}", firebase_uid);
        }

        Ok(user)
    }

    /// Shared user lookup logic with country_code fallback
    ///
    /// Attempts to find user in two stages:
    /// 1. First attempt: Query with country_code (optimal for sharding)
    /// 2. Fallback: Query without country_code (handles mismatches)
    ///
    /// This fallback handles cases where:
    /// - User changed phone number (different country)
    /// - Country code parsing differs from registration
    /// - Database has stale country_code
    async fn lookup_user(
        &self,
        firebase_uid: &str,
        country_code: &str,
        phone_number: &str
    ) -> Result<AuthenticatedUser, ApiError> {
        info!(
            "🔍 Looking up user: firebase_uid={}, country={}, phone={}",
            firebase_uid,
            country_code,
            phone_number
        );

        // === ATTEMPT 1: Query with country_code (optimal) ===
        let url_with_country = format!(
            "{}/users/exists?firebase_user_id={}&country_code={}",
            self.users_service_url,
            urlencoding::encode(firebase_uid),
            urlencoding::encode(country_code)
        );

        debug!("🔍 Attempt 1: Querying with country_code={}", country_code);

        let response = self.http_client
            .get(&url_with_country)
            .header("X-Internal-API-Key", &self.internal_api_key)
            .send().await
            .map_err(|e| {
                error!("❌ User service request failed: {}", e);
                ApiError::InternalServerError {
                    message: format!("User service unavailable: {}", e),
                }
            })?;

        if !response.status().is_success() {
            error!("❌ User service returned error: {}", response.status());
            return Err(ApiError::InternalServerError {
                message: format!("User service error: {}", response.status()),
            });
        }

        // Deserialize to typed UserExistsResponse (handles camelCase automatically)
        let mut user_response = response.json::<crate::UserExistsResponse>().await.map_err(|e| {
            error!("❌ Failed to parse user service response: {}", e);
            ApiError::InternalServerError {
                message: format!("Invalid user service response: {}", e),
            }
        })?;

        // === ATTEMPT 2: Fallback to query without country_code ===
        // If user_id is empty, user not found with this country_code
        if user_response.user_id.is_empty() {
            warn!(
                "🔄 User not found with country_code={}, retrying without country_code (firebase_uid={})",
                country_code,
                firebase_uid
            );

            let url_without_country = format!(
                "{}/users/exists-by-firebase-uid?firebase_user_id={}",
                self.users_service_url,
                urlencoding::encode(firebase_uid)
            );

            debug!("🔍 Attempt 2: Querying without country_code");

            let fallback_response = self.http_client
                .get(&url_without_country)
                .header("X-Internal-API-Key", &self.internal_api_key)
                .send().await
                .map_err(|e| {
                    error!("❌ Fallback user service request failed: {}", e);
                    ApiError::InternalServerError {
                        message: format!("Fallback user service unavailable: {}", e),
                    }
                })?;

            if !fallback_response.status().is_success() {
                error!("❌ Fallback query failed - user not found: {}", firebase_uid);
                return Err(ApiError::Unauthorized {
                    message: "User not found".to_string(),
                });
            }

            user_response = fallback_response
                .json::<crate::UserExistsResponse>().await
                .map_err(|e| {
                    error!("❌ Failed to parse fallback response: {}", e);
                    ApiError::InternalServerError {
                        message: format!("Invalid fallback response: {}", e),
                    }
                })?;
        }

        // === Parse authenticated user data from typed response ===
        let user_id = user_response.user_id;
        if user_id.is_empty() {
            error!("❌ user_id is empty in response");
            return Err(ApiError::Unauthorized {
                message: "User not found".to_string(),
            });
        }

        // Use phone_number and country_code from JWT/parameter (not from response)
        // This ensures we always use the CURRENT phone number and its derived country,
        // not stale data from the database
        let phone_number_final = phone_number.to_string();
        let country_code_final = country_code.to_string();

        let user_role = Some(user_response.user_role);
        let roles = user_response.roles;

        info!(
            "✅ User authenticated: user_id={}, firebase_uid={}, role={:?}, country={}",
            user_id,
            firebase_uid,
            user_role,
            country_code_final
        );

        Ok(AuthenticatedUser {
            user_id,
            firebase_user_id: firebase_uid.to_string(),
            phone_number: phone_number_final,
            user_role,
            roles,
            country_code: country_code_final, // ✅ From parsed phone number, not DB
        })
    }
}

/// Authenticated user data returned by authentication service
///
/// Contains essential user information needed by both REST and WebSocket:
/// - user_id: MongoDB user ID (for database operations)
/// - firebase_user_id: Firebase UID (for cross-service calls)
/// - phone_number: User's phone number
/// - user_role: Primary role (Registered/Anonymous)
/// - roles: Additional role strings
/// - country_code: Parsed country code (for sharding)
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub user_id: String,
    pub firebase_user_id: String,
    pub phone_number: String,
    pub user_role: Option<UserRole>,
    pub roles: Vec<String>,
    pub country_code: String,
}
