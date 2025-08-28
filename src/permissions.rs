use std::{ collections::{ HashMap, HashSet }, fs, path::Path, sync::{ Arc, RwLock } };
use once_cell::sync::Lazy;
use serde::{ Deserialize, Serialize };
use tracing::{ debug, error, warn };
use venues_service_domain::venue_models::VenueType;

use crate::bearer_token_guard::{
    ClientUserRole,
    GuardUser,
    GuardUserOrAnonymous,
    UserState,
    UserVerifications,
    VerificationStatus,
};

// === Policy Data Structures ===

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PolicyFile {
    pub version: String,
    pub policies: Vec<Policy>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Policy {
    pub name: String,
    pub description: String,
    pub conditions: PolicyConditions,
    pub context: PolicyContext,
    pub effect: PolicyEffect,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PolicyConditions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_state: Option<Vec<UserState>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<ClientUserRole>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub permissions: Option<Vec<Permission>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_verifications: Option<ClientVerificationRequirement>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub venue_verifications: Option<VenueVerificationRequirement>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClientVerificationRequirement {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_method: Option<String>, // "EmailDomain", "ClientToken", "ManualApproval"

    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>, // "Active", "Expired", "Revoked"

    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_roles: Option<Vec<ClientUserRole>>, // Roles within the client organization

    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_client_id: Option<bool>, // Whether to match context client_id
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VenueVerificationRequirement {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_method: Option<String>, // "InheritFromClient", "VenueSpecificToken", etc.

    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>, // "Active", "Expired", "Revoked"

    #[serde(skip_serializing_if = "Option::is_none")]
    pub venue_type: Option<VenueType>, // Specific venue types

    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_venue_id: Option<bool>, // Whether to match context venue_id
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum PolicyContext {
    Simple(String), // "Global", "Client", "Venue"
    Typed {
        #[serde(rename = "type")]
        context_type: String,
        
        #[serde(skip_serializing_if = "Option::is_none")]
        venue_type: Option<VenueType>,
        
        #[serde(skip_serializing_if = "Option::is_none")]
        client_types: Option<Vec<String>>,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub enum PolicyEffect {
    Allow,
    Deny,
}

// Updated Permission enum with Client-focused permissions
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, Eq, Hash)]
pub enum Permission {
    // Content permissions
    ViewPublicContent,
    ViewPrivateContent,
    CreateComment,
    CreateSpark,
    LikeContent,

    // User management permissions
    RegisterAsGuest, // Anonymous users can register as guests
    UpdateProfile, // Update user profile
    CreateProfile, // Create new profile

    // Client access permissions (University, Company, etc.)
    AccessClient, // Access any client services
    ViewClientDetails, // View client information

    // Venue permissions
    CheckIn, // Check into venues
    ViewVenueDetails, // View venue information
    ViewVenueUsers, // See other users in venue
    CreateVenueContent, // Create content in venue

    // Admin permissions
    ManageClient, // Manage client settings
    ManageVenue, // Manage specific venues
    ManageUsers, // User management
    ViewAnalytics, // Access analytics
    ModerateContent, // Content moderation

    // Sponsor permissions
    CreateSponsorContent,
    ViewTargetAudience,
}

// Updated ActionContext to reflect Client-Venue architecture
#[derive(Debug, Clone)]
pub enum ActionContext {
    Global,

    // Client context (University, Company, CoffeeShop organization)
    Client {
        client_id: String,
    },

    // Specific venue context (always belongs to a client)
    Venue {
        venue_id: String,
        venue_type: VenueType,
        client_id: String, // Parent client that owns this venue
    },

    // Geographic context for location-based permissions
    Geographic {
        countries: Vec<String>,
        cities: Option<Vec<String>>,
        venue_types: Option<Vec<VenueType>>,
    },
}

// User Service Response structure
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserServiceAuthResponse {
    pub user_id: String,
    pub user_state: UserState,
    pub roles: Vec<String>, // Convert to UserRole enum
    pub verifications: UserVerifications,
}

// === Enhanced Permission Engine ===

pub struct PolicyEngine {
    policies: Vec<Policy>,
    policy_cache: HashMap<String, bool>, // Cache for performance
}

impl PolicyEngine {
    /// Load policies from JSON files
    pub fn load_from_files(policy_dir: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mut all_policies = Vec::new();

        // Read all JSON files in the policies directory
        let policy_files = [
            "anonymous_user_permissions.json",
            "guest_user_permissions.json",
            "phone_verified_user_permissions.json",
            "client_access_permissions.json",
            "venue_specific_permissions.json",
            "admin_permissions.json",
        ];

        for file_name in &policy_files {
            let file_path = Path::new(policy_dir).join(file_name);

            if file_path.exists() {
                let content = fs::read_to_string(&file_path)?;
                let policy_file: PolicyFile = serde_json::from_str(&content)?;

                debug!("Loaded {} policies from {}", policy_file.policies.len(), file_name);
                all_policies.extend(policy_file.policies);
            } else {
                warn!("Policy file not found: {:?}", file_path);
            }
        }

        Ok(PolicyEngine {
            policies: all_policies,
            policy_cache: HashMap::new(),
        })
    }

    /// Load policies from environment/config service
    pub fn load_from_config(config_json: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let policy_file: PolicyFile = serde_json::from_str(config_json)?;

        Ok(PolicyEngine {
            policies: policy_file.policies,
            policy_cache: HashMap::new(),
        })
    }

    /// Evaluate permission using policy engine
    pub fn evaluate_permission(
        &self,
        user: &GuardUser,
        permission: &Permission,
        context: &ActionContext
    ) -> bool {
        // Generate cache key
        let cache_key = format!(
            "{}:{:?}:{:?}:{:?}:{:?}",
            user.user_id,
            user.user_state.clone(),
            permission,
            self.context_cache_key(context),
            user.roles
        );

        // Check cache first
        if let Some(&cached_result) = self.policy_cache.get(&cache_key) {
            return cached_result;
        }

        // Evaluate policies
        let result = self.evaluate_policies(user, permission, context);

        // Cache result (in production, implement proper cache with TTL)
        // self.policy_cache.insert(cache_key, result);

        result
    }

    fn context_cache_key(&self, context: &ActionContext) -> String {
        match context {
            ActionContext::Global => "Global".to_string(),
            ActionContext::Client { client_id } => format!("Client:{}", client_id),
            ActionContext::Venue { venue_id, venue_type, client_id } => {
                format!("Venue:{}:{}:{:?}", venue_id, client_id, venue_type)
            }
            ActionContext::Geographic { countries, cities, venue_types } => {
                format!("Geo:{:?}:{:?}:{:?}", countries, cities, venue_types)
            }
        }
    }

    fn evaluate_policies(
        &self,
        user: &GuardUser,
        permission: &Permission,
        context: &ActionContext
    ) -> bool {
        for policy in &self.policies {
            if self.policy_matches(policy, user, permission, context) {
                debug!("Policy '{}' matched for user {}", policy.name, user.user_id);
                return policy.effect == PolicyEffect::Allow;
            }
        }

        // Default deny if no policy matches
        false
    }

    fn policy_matches(
        &self,
        policy: &Policy,
        user: &GuardUser,
        permission: &Permission,
        context: &ActionContext
    ) -> bool {
        let conditions = &policy.conditions;

        // Check user state
        if let Some(ref required_states) = conditions.user_state {
            if let Some(ref user_state) = user.user_state {
                if !required_states.contains(user_state) {
                    return false;
                }
            } else {
                return false;
            }
        }

        // Check roles
        if let Some(ref required_roles) = conditions.roles {
            if !required_roles.iter().any(|role| user.has_role(role)) {
                return false;
            }
        }

        // Check permissions
        if let Some(ref required_permissions) = conditions.permissions {
            if !required_permissions.contains(permission) {
                return false;
            }
        }

        // Check client verifications
        if let Some(ref client_verification_req) = conditions.client_verifications {
            if !self.check_client_verification_requirement(user, client_verification_req, context) {
                return false;
            }
        }

        // Check venue verifications
        if let Some(ref venue_verification_req) = conditions.venue_verifications {
            if !self.check_venue_verification_requirement(user, venue_verification_req, context) {
                return false;
            }
        }

        // Check context
        if !self.check_context_match(&policy.context, context) {
            return false;
        }

        true
    }

    fn check_client_verification_requirement(
        &self,
        user: &GuardUser,
        client_verification_req: &ClientVerificationRequirement,
        context: &ActionContext
    ) -> bool {
        let verifications = match &user.verifications {
            Some(v) => v,
            None => {
                return false;
            }
        };

        // Get the client_id from context if needed
        let target_client_id = match context {
            ActionContext::Client { client_id } => Some(client_id.clone()),
            ActionContext::Venue { client_id, .. } => Some(client_id.clone()),
            _ => None,
        };

        // Filter client verifications based on requirements
        let matching_verifications = verifications.client_verifications.iter().filter(|cv| {
            // Check status
            if let Some(ref required_status) = client_verification_req.status {
                match required_status.as_str() {
                    "Active" => cv.status != VerificationStatus::Active,
                    "Expired" => cv.status != VerificationStatus::Expired,
                    "Revoked" => cv.status != VerificationStatus::Revoked,
                    _ => {
                        return false;
                    }
                };
            }

            // Check verification method
            if let Some(ref required_method) = client_verification_req.verification_method {
                // Implementation would check cv.verification_method against required_method
                // This is a simplified version
            }

            // Check user roles within client
            if let Some(ref required_user_roles) = client_verification_req.user_roles {
                if !required_user_roles.contains(&cv.user_role) {
                    return false;
                }
            }

            // Check client_id match if required
            if client_verification_req.match_client_id.unwrap_or(false) {
                if let Some(ref target_id) = target_client_id {
                    if cv.client_id != *target_id {
                        return false;
                    }
                }
            }

            true
        });

        matching_verifications.count() > 0
    }

    fn check_venue_verification_requirement(
        &self,
        user: &GuardUser,
        venue_verification_req: &VenueVerificationRequirement,
        context: &ActionContext
    ) -> bool {
        let verifications = match &user.verifications {
            Some(v) => v,
            None => {
                return false;
            }
        };

        // Get venue info from context if needed
        let (target_venue_id, target_venue_type) = match context {
            ActionContext::Venue { venue_id, venue_type, .. } => {
                (Some(venue_id.clone()), Some(venue_type.clone()))
            }
            _ => (None, None),
        };

        // Filter venue verifications based on requirements
        let matching_verifications = verifications.venue_verifications.iter().filter(|vv| {
            // Check status
            if let Some(ref required_status) = venue_verification_req.status {
                match required_status.as_str() {
                    "Active" => vv.status != VerificationStatus::Active,
                    "Expired" => vv.status != VerificationStatus::Expired,
                    "Revoked" => vv.status != VerificationStatus::Revoked,
                    _ => {
                        return false;
                    }
                };
            }

            // Check venue type
            if let Some(ref required_venue_type) = venue_verification_req.venue_type {
                if vv.venue_type != *required_venue_type {
                    return false;
                }
            }

            // Check venue_id match if required
            if venue_verification_req.match_venue_id.unwrap_or(false) {
                if let Some(ref target_id) = target_venue_id {
                    if vv.venue_id != *target_id {
                        return false;
                    }
                }
            }

            true
        });

        matching_verifications.count() > 0
    }

    fn check_context_match(
        &self,
        policy_context: &PolicyContext,
        actual_context: &ActionContext
    ) -> bool {
        match (policy_context, actual_context) {
            // Handle simple string format
            (PolicyContext::Simple(context_str), ActionContext::Global) => {
                context_str == "Global"
            }
            
            // Handle typed format
            (PolicyContext::Typed { context_type, .. }, ActionContext::Global) => {
                context_type == "Global"
            }

            (PolicyContext::Simple(context_str), ActionContext::Client { .. }) => {
                context_str == "Client"
            }

            (PolicyContext::Typed { context_type, .. }, ActionContext::Client { .. }) => {
                context_type == "Client"
            }

            (PolicyContext::Simple(context_str), ActionContext::Venue { .. }) => {
                context_str == "Venue"
            }

            (
                PolicyContext::Typed { context_type, venue_type, .. },
                ActionContext::Venue { venue_type: actual_venue_type, .. },
            ) => {
                context_type == "Venue" &&
                    (venue_type.is_none() || venue_type == &Some(actual_venue_type.clone()))
            }

            _ => false,
        }
    }

    /// Get all capabilities for a user in a context
    pub fn get_user_capabilities(
        &self,
        user: &GuardUser,
        context: &ActionContext
    ) -> HashSet<Permission> {
        let mut capabilities = HashSet::new();

        // Check all permissions
        for permission in [
            Permission::ViewPublicContent,
            Permission::ViewPrivateContent,
            Permission::CreateComment,
            Permission::CreateSpark,
            Permission::LikeContent,
            Permission::RegisterAsGuest,
            Permission::UpdateProfile,
            Permission::AccessClient,
            Permission::CheckIn,
            Permission::ViewVenueDetails,
            Permission::ManageClient,
            Permission::ManageVenue,
            Permission::CreateSponsorContent,
        ] {
            if self.evaluate_permission(user, &permission, context) {
                capabilities.insert(permission);
            }
        }

        capabilities
    }

    /// Reload policies (for hot-reloading)
    pub fn reload_policies(&mut self, policy_dir: &str) -> Result<(), Box<dyn std::error::Error>> {
        let new_engine = PolicyEngine::load_from_files(policy_dir)?;
        self.policies = new_engine.policies;
        self.policy_cache.clear(); // Clear cache after reload
        debug!("Policies reloaded successfully");
        Ok(())
    }
}

// === Updated PermissionEngine as Singleton ===

static POLICY_ENGINE: Lazy<Arc<RwLock<PolicyEngine>>> = Lazy::new(|| {
    let engine = PolicyEngine::load_from_files("policies/").unwrap_or_else(|e| {
        error!("Failed to load policies: {}", e);
        PolicyEngine {
            policies: Vec::new(),
            policy_cache: HashMap::new(),
        }
    });
    Arc::new(RwLock::new(engine))
});

pub struct PermissionEngine;

impl PermissionEngine {
    pub fn evaluate_permission(
        user_or_anonymous: &GuardUserOrAnonymous,
        permission: &Permission,
        context: &ActionContext
    ) -> bool {
        match user_or_anonymous {
            GuardUserOrAnonymous::User(user) => {
                let engine = POLICY_ENGINE.read().unwrap();
                engine.evaluate_permission(user, permission, context)
            }
            GuardUserOrAnonymous::Anonymous(anonymous) => {
                // Create a minimal user representation for policy evaluation
                let minimal_user = GuardUser {
                    user_id: anonymous.firebase_user_id.clone(),
                    firebase_user_id: anonymous.firebase_user_id.clone(),
                    phone_number: None,
                    country_code: "UNKNOWN".to_string(),
                    city: anonymous.city.clone(),
                    user_state: Some(UserState::Anonymous),
                    roles: HashSet::new(),
                    verifications: None,
                };

                let engine = POLICY_ENGINE.read().unwrap();
                engine.evaluate_permission(&minimal_user, permission, context)
            }
        }
    }

    pub fn evaluate_user_permission(
        user: &GuardUser,
        permission: &Permission,
        context: &ActionContext
    ) -> bool {
        let engine = POLICY_ENGINE.read().unwrap();
        engine.evaluate_permission(user, permission, context)
    }

    pub fn get_user_capabilities(user: &GuardUser, context: &ActionContext) -> HashSet<Permission> {
        let engine = POLICY_ENGINE.read().unwrap();
        engine.get_user_capabilities(user, context)
    }

    /// Reload policies at runtime
    pub fn reload_policies(policy_dir: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut engine = POLICY_ENGINE.write().unwrap();
        engine.reload_policies(policy_dir)
    }
}
