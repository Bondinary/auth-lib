use serde::{ Deserialize, Serialize };
use std::fmt;

/// ActorType represents WHO a user is acting as in a given request.
/// This is NOT a role - it's a projection enabled by context-scoped roles.
///
/// Authorization flow:
/// 1. User has roles in DB (e.g., "client_admin" in context X)
/// 2. Role enables ActorType projection (client_admin → CLIENT actor)
/// 3. ActorType determines capabilities via static matrix
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ActorType {
    /// Default projection - any authenticated user
    /// Always available, no special role required
    User,

    /// Acting on behalf of client organization
    /// Requires: client_admin OR client_owner role in context
    Client,

    /// Acting as sponsor representative
    /// Requires: sponsor_rep role + active sponsorship linkage
    Sponsor,

    /// System/AI-generated actions
    /// Requires: ai_publisher role OR SystemPrincipal identity
    AI,

    /// Background/scheduled system operations
    /// Requires: SystemPrincipal identity only
    System,
}

impl ActorType {
    /// Get all possible actor types (for UI enumeration)
    pub fn all() -> &'static [ActorType] {
        &[ActorType::User, ActorType::Client, ActorType::Sponsor, ActorType::AI, ActorType::System]
    }

    /// Check if this actor type requires special roles
    pub fn requires_role(&self) -> bool {
        !matches!(self, ActorType::User)
    }

    /// Get required roles for this actor projection
    /// Returns empty vec for User (always allowed)
    /// CONTRACT \u00a78.2.1: Role names use PascalCase
    pub fn required_roles(&self) -> Vec<&'static str> {
        match self {
            ActorType::User => vec![],
            ActorType::Client => vec!["ClientAdmin", "ClientOwner"],
            ActorType::Sponsor => vec!["SponsorRep"],
            ActorType::AI => vec!["AiPublisher"],
            ActorType::System => vec![], // Requires SystemPrincipal, not role
        }
    }
}

impl fmt::Display for ActorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ActorType::User => write!(f, "User"),
            ActorType::Client => write!(f, "Client"),
            ActorType::Sponsor => write!(f, "Sponsor"),
            ActorType::AI => write!(f, "AI"),
            ActorType::System => write!(f, "System"),
        }
    }
}

impl std::str::FromStr for ActorType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "user" => Ok(ActorType::User),
            "client" => Ok(ActorType::Client),
            "sponsor" => Ok(ActorType::Sponsor),
            "ai" => Ok(ActorType::AI),
            "system" => Ok(ActorType::System),
            _ => Err(format!("Invalid actor type: {}", s)),
        }
    }
}

impl Default for ActorType {
    fn default() -> Self {
        ActorType::User
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_actor_type_from_str() {
        assert_eq!("user".parse::<ActorType>().unwrap(), ActorType::User);
        assert_eq!("CLIENT".parse::<ActorType>().unwrap(), ActorType::Client);
        assert_eq!("Sponsor".parse::<ActorType>().unwrap(), ActorType::Sponsor);
        assert!("invalid".parse::<ActorType>().is_err());
    }

    #[test]
    fn test_required_roles() {
        assert_eq!(ActorType::User.required_roles(), Vec::<&str>::new());
        assert!(ActorType::Client.required_roles().contains(&"ClientAdmin"));
        assert!(ActorType::Sponsor.required_roles().contains(&"SponsorRep"));
    }

    #[test]
    fn test_default_is_user() {
        assert_eq!(ActorType::default(), ActorType::User);
    }
}
