use serde::{ Deserialize, Serialize };
use std::fmt;

/// Capability represents a specific action that can be performed.
/// Capabilities are strings for flexibility, but we define constants for type safety.
pub type Capability = &'static str;

/// CapabilityConstraint defines how a capability is enforced for a specific actor.
/// This prevents hardcoding special cases like "users can only delete own content".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CapabilityConstraint {
    /// Unconditional permission - actor can perform action on any resource
    Allow,

    /// Explicit denial - actor cannot perform this action
    Deny,

    /// Actor can only perform action on resources they own
    /// Requires resource ownership check: resource.author_user_id == user.user_id
    OwnOnly,

    /// Actor can only perform action on resources belonging to same client
    /// Requires client match: resource.client_id == context.client_id
    SameClientOnly,

    /// Actor can only perform action on resources belonging to same sponsor
    /// Requires sponsor match: resource.sponsor_id == user.sponsor_id
    SameSponsorOnly,

    /// Action is scoped to context (most common - default scope)
    /// No additional constraints beyond context membership
    ContextOnly,
}

impl fmt::Display for CapabilityConstraint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CapabilityConstraint::Allow => write!(f, "Allow"),
            CapabilityConstraint::Deny => write!(f, "Deny"),
            CapabilityConstraint::OwnOnly => write!(f, "OwnOnly"),
            CapabilityConstraint::SameClientOnly => write!(f, "SameClientOnly"),
            CapabilityConstraint::SameSponsorOnly => write!(f, "SameSponsorOnly"),
            CapabilityConstraint::ContextOnly => write!(f, "ContextOnly"),
        }
    }
}

// ============================================================================
// CAPABILITY CONSTANTS (Hierarchical Organization)
// ============================================================================

// Content capabilities
pub const SPARK_CREATE: Capability = "spark:create";
pub const SPARK_DELETE: Capability = "spark:delete";
pub const SPARK_MODERATE: Capability = "spark:moderate";
pub const SPARK_EDIT: Capability = "spark:edit";

// Private intent capabilities
pub const PRIVATE_SPARK_CREATE: Capability = "private_spark:create";
pub const PRIVATE_SPARK_UPDATE: Capability = "private_spark:update";
pub const PRIVATE_SPARK_DELETE: Capability = "private_spark:delete";
pub const PRIVATE_SPARK_DEACTIVATE: Capability = "private_spark:deactivate";
pub const MATCH_RUN: Capability = "match:run";
pub const MATCH_VIEW: Capability = "match:view";

// Check-in capabilities
pub const CHECKIN_CREATE: Capability = "checkin:create";
pub const CHECKIN_EXPIRE: Capability = "checkin:expire";
pub const CHECKIN_VERIFY: Capability = "checkin:verify";

// Membership capabilities
pub const MEMBERSHIP_JOIN: Capability = "membership:join";
pub const MEMBERSHIP_LEAVE: Capability = "membership:leave";
pub const MEMBERSHIP_GRANT: Capability = "membership:grant";
pub const MEMBERSHIP_REVOKE: Capability = "membership:revoke";
pub const MEMBERSHIP_VERIFY: Capability = "membership:verify";

// Email/Verification capabilities
pub const EMAIL_SEND_VERIFICATION: Capability = "email:send_verification";

// Context capabilities
pub const CONTEXT_CREATE: Capability = "context:create";
pub const CONTEXT_CONFIGURE: Capability = "context:configure";
pub const CONTEXT_SUSPEND: Capability = "context:suspend";
pub const CONTEXT_ARCHIVE: Capability = "context:archive";
pub const CONTEXT_DELETE: Capability = "context:delete";
pub const CONTEXT_VIEW: Capability = "context:view";
pub const CONTEXT_CONFIGURE_CAPABILITIES: Capability = "context:configure_capabilities";

// Role management capabilities
pub const ROLES_GRANT: Capability = "roles:grant";
pub const ROLES_REVOKE: Capability = "roles:revoke";
pub const ROLES_VIEW: Capability = "roles:view";

// Analytics capabilities
pub const ANALYTICS_VIEW: Capability = "analytics:view";
pub const ANALYTICS_EXPORT: Capability = "analytics:export";

// Moderation capabilities
pub const CONTENT_MODERATE: Capability = "content:moderate";
pub const USER_SUSPEND: Capability = "user:suspend";
pub const USER_BAN: Capability = "user:ban";
pub const REPORT_VIEW: Capability = "report:view";
pub const REPORT_RESOLVE: Capability = "report:resolve";

// Legacy capability for unmigrated endpoints
pub const LEGACY_ALLOW: Capability = "legacy:allow";

/// Get all defined capabilities (for introspection/admin UI)
pub fn all_capabilities() -> Vec<Capability> {
    vec![
        // Content
        SPARK_CREATE,
        SPARK_DELETE,
        SPARK_MODERATE,
        SPARK_EDIT,
        // Private intents
        PRIVATE_SPARK_CREATE,
        PRIVATE_SPARK_UPDATE,
        PRIVATE_SPARK_DELETE,
        PRIVATE_SPARK_DEACTIVATE,
        MATCH_RUN,
        MATCH_VIEW,
        // Check-in
        CHECKIN_CREATE,
        CHECKIN_EXPIRE,
        CHECKIN_VERIFY,
        // Membership
        MEMBERSHIP_JOIN,
        MEMBERSHIP_LEAVE,
        MEMBERSHIP_GRANT,
        MEMBERSHIP_REVOKE,
        MEMBERSHIP_VERIFY,
        // Email/Verification
        EMAIL_SEND_VERIFICATION,
        // Context
        CONTEXT_CREATE,
        CONTEXT_CONFIGURE,
        CONTEXT_SUSPEND,
        CONTEXT_ARCHIVE,
        CONTEXT_DELETE,
        CONTEXT_VIEW,
        CONTEXT_CONFIGURE_CAPABILITIES,
        // Roles
        ROLES_GRANT,
        ROLES_REVOKE,
        ROLES_VIEW,
        // Analytics
        ANALYTICS_VIEW,
        ANALYTICS_EXPORT,
        // Moderation
        CONTENT_MODERATE,
        USER_SUSPEND,
        USER_BAN,
        REPORT_VIEW,
        REPORT_RESOLVE,
        // Legacy
        LEGACY_ALLOW
    ]
}

/// Capability category for organizing capabilities in UI
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityCategory {
    Content,
    PrivateIntents,
    CheckIn,
    Membership,
    Context,
    Roles,
    Analytics,
    Moderation,
    Legacy,
}

impl CapabilityCategory {
    pub fn from_capability(capability: Capability) -> Option<Self> {
        match capability {
            cap if cap.starts_with("spark:") => Some(CapabilityCategory::Content),
            cap if cap.starts_with("private_spark:") || cap.starts_with("match:") => {
                Some(CapabilityCategory::PrivateIntents)
            }
            cap if cap.starts_with("checkin:") => Some(CapabilityCategory::CheckIn),
            cap if cap.starts_with("membership:") => Some(CapabilityCategory::Membership),
            cap if cap.starts_with("context:") => Some(CapabilityCategory::Context),
            cap if cap.starts_with("roles:") => Some(CapabilityCategory::Roles),
            cap if cap.starts_with("analytics:") => Some(CapabilityCategory::Analytics),
            cap if cap.starts_with("content:") || cap.starts_with("user:") => {
                Some(CapabilityCategory::Moderation)
            }
            "legacy:allow" => Some(CapabilityCategory::Legacy),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability_category() {
        assert_eq!(
            CapabilityCategory::from_capability(SPARK_CREATE),
            Some(CapabilityCategory::Content)
        );
        assert_eq!(
            CapabilityCategory::from_capability(MATCH_RUN),
            Some(CapabilityCategory::PrivateIntents)
        );
        assert_eq!(
            CapabilityCategory::from_capability(ROLES_GRANT),
            Some(CapabilityCategory::Roles)
        );
    }

    #[test]
    fn test_all_capabilities_count() {
        let caps = all_capabilities();
        assert!(caps.len() >= 30, "Should have at least 30 capabilities defined");
    }
}
