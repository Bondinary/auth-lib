use std::collections::HashSet;
// use backend_domain::{ clients::venue_models::VenueType }; // REMOVED: Venues replaced by contexts
use serde::{ Deserialize, Serialize };

use crate::auth_lib::bearer_token_guard::{ GuardUser, GuardUserOrAnonymous };

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

    // Context permissions (replacement for venues)
    CheckIn, // Check into contexts
    ViewContextDetails, // View context information
    ViewContextUsers, // See other users in context
    CreateContextContent, // Create content in context

    // Admin permissions
    ManageClient, // Manage client settings
    ManageContext, // Manage specific contexts
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

    // Specific context (replacement for venues - always belongs to a client)
    Context {
        context_id: String,
        client_id: String, // Parent client that owns this context
    },
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
