use std::collections::HashSet;
use serde::{ Deserialize, Serialize };
use users_service_domain::{ users_models::UserRole };
use venues_service_domain::venue_models::VenueType;
use crate::bearer_token_guard::{ GuardUser, GuardUserOrAnonymous, UserVerifications };

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
    pub user_role: UserRole,
    pub roles: Vec<String>, // Convert to UserRole enum
    pub verifications: UserVerifications,
}

// === Abstract Permission Checker Trait ===

pub trait PermissionChecker: Send + Sync {
    fn can_perform_action(
        &self,
        user: &GuardUser,
        permission: &Permission,
        context: &ActionContext
    ) -> bool;
    fn can_perform_action_user_or_anonymous(
        &self,
        user_or_anonymous: &GuardUserOrAnonymous,
        permission: &Permission,
        context: &ActionContext
    ) -> bool;
    fn get_user_capabilities(
        &self,
        user: &GuardUser,
        context: &ActionContext
    ) -> HashSet<Permission>;
}

// === Default Empty Implementation (for services without policy engine) ===

pub struct NoOpPermissionChecker;

impl PermissionChecker for NoOpPermissionChecker {
    fn can_perform_action(
        &self,
        _user: &GuardUser,
        _permission: &Permission,
        _context: &ActionContext
    ) -> bool {
        false // Default deny for safety
    }

    fn can_perform_action_user_or_anonymous(
        &self,
        _user_or_anonymous: &GuardUserOrAnonymous,
        _permission: &Permission,
        _context: &ActionContext
    ) -> bool {
        false // Default deny for safety
    }

    fn get_user_capabilities(
        &self,
        _user: &GuardUser,
        _context: &ActionContext
    ) -> HashSet<Permission> {
        HashSet::new()
    }
}
