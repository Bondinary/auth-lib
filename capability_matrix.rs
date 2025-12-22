use super::actor::ActorType;
use super::capabilities::*;
use std::collections::HashMap;

/// Represents the authorization rule for a specific capability
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityRule {
    pub actor_type: ActorType,
    pub constraint: CapabilityConstraint,
}

impl CapabilityRule {
    pub fn new(actor_type: ActorType, constraint: CapabilityConstraint) -> Self {
        Self {
            actor_type,
            constraint,
        }
    }
}

/// Static capability matrix mapping capabilities to actor permissions
///
/// This is the core authorization matrix that defines what each actor type can do.
/// Changes to this matrix require code deployment (architectural decisions).
///
/// Design principles:
/// - Explicit is better than implicit: all capabilities must be defined
/// - Deny by default: if an (actor, capability) pair is not listed, it's denied
/// - Constraints are first-class: use CapabilityConstraint variants instead of hardcoding logic
pub struct CapabilityMatrix;

impl CapabilityMatrix {
    /// Get the capability rules for a specific capability
    ///
    /// Returns a vector of (ActorType, CapabilityConstraint) pairs.
    /// If an actor type is not listed, access is implicitly denied.
    pub fn get_rules(capability: &str) -> Vec<CapabilityRule> {
        Self::build_matrix().get(capability).cloned().unwrap_or_default()
    }

    /// Check if a specific actor type has access to a capability
    ///
    /// Returns Some(CapabilityConstraint) if the actor has access, None otherwise
    pub fn get_constraint(actor_type: ActorType, capability: &str) -> Option<CapabilityConstraint> {
        Self::get_rules(capability)
            .into_iter()
            .find(|rule| rule.actor_type == actor_type)
            .map(|rule| rule.constraint)
    }

    /// Build the complete capability matrix
    ///
    /// This is the single source of truth for all authorization rules.
    ///
    /// Key patterns:
    /// - Content creation: Users create OwnOnly, Clients/Sponsors create anything in their scope
    /// - Moderation: Moderators have broad Allow, context_moderators have ContextOnly
    /// - Role management: Only clients can grant roles, scoped to their context
    /// - System operations: Only System actor (internal services)
    fn build_matrix() -> HashMap<&'static str, Vec<CapabilityRule>> {
        let mut matrix = HashMap::new();

        // CONTENT - Sparks
        matrix.insert(
            SPARK_CREATE,
            vec![
                CapabilityRule::new(ActorType::User, CapabilityConstraint::Allow),
                CapabilityRule::new(ActorType::Client, CapabilityConstraint::Allow),
                CapabilityRule::new(ActorType::Sponsor, CapabilityConstraint::Allow),
                CapabilityRule::new(ActorType::AI, CapabilityConstraint::Allow)
            ]
        );

        matrix.insert(
            SPARK_DELETE,
            vec![
                CapabilityRule::new(ActorType::User, CapabilityConstraint::OwnOnly),
                CapabilityRule::new(ActorType::Client, CapabilityConstraint::Allow),
                CapabilityRule::new(ActorType::Sponsor, CapabilityConstraint::Allow),
                CapabilityRule::new(ActorType::System, CapabilityConstraint::Allow)
            ]
        );

        matrix.insert(
            SPARK_EDIT,
            vec![
                CapabilityRule::new(ActorType::User, CapabilityConstraint::OwnOnly),
                CapabilityRule::new(ActorType::Client, CapabilityConstraint::Allow),
                CapabilityRule::new(ActorType::Sponsor, CapabilityConstraint::Allow)
            ]
        );

        matrix.insert(
            SPARK_MODERATE,
            vec![
                CapabilityRule::new(ActorType::Client, CapabilityConstraint::Allow),
                CapabilityRule::new(ActorType::System, CapabilityConstraint::Allow)
            ]
        );

        // PRIVATE INTENTS - Private Sparks and Matching
        matrix.insert(
            PRIVATE_SPARK_CREATE,
            vec![CapabilityRule::new(ActorType::User, CapabilityConstraint::Allow)]
        );

        matrix.insert(
            PRIVATE_SPARK_UPDATE,
            vec![CapabilityRule::new(ActorType::User, CapabilityConstraint::OwnOnly)]
        );

        matrix.insert(
            PRIVATE_SPARK_DELETE,
            vec![
                CapabilityRule::new(ActorType::User, CapabilityConstraint::OwnOnly),
                CapabilityRule::new(ActorType::System, CapabilityConstraint::Allow)
            ]
        );

        matrix.insert(
            PRIVATE_SPARK_DEACTIVATE,
            vec![
                CapabilityRule::new(ActorType::User, CapabilityConstraint::Allow),
                CapabilityRule::new(ActorType::System, CapabilityConstraint::Allow)
            ]
        );

        matrix.insert(
            MATCH_RUN,
            vec![
                CapabilityRule::new(ActorType::Client, CapabilityConstraint::Allow),
                CapabilityRule::new(ActorType::System, CapabilityConstraint::Allow)
            ]
        );

        matrix.insert(
            MATCH_VIEW,
            vec![
                CapabilityRule::new(ActorType::User, CapabilityConstraint::OwnOnly),
                CapabilityRule::new(ActorType::Client, CapabilityConstraint::Allow)
            ]
        );

        // CHECK-IN
        matrix.insert(
            CHECKIN_CREATE,
            vec![CapabilityRule::new(ActorType::User, CapabilityConstraint::Allow)]
        );

        matrix.insert(
            CHECKIN_EXPIRE,
            vec![
                CapabilityRule::new(ActorType::User, CapabilityConstraint::OwnOnly),
                CapabilityRule::new(ActorType::System, CapabilityConstraint::Allow)
            ]
        );

        matrix.insert(
            CHECKIN_VERIFY,
            vec![
                CapabilityRule::new(ActorType::Client, CapabilityConstraint::Allow),
                CapabilityRule::new(ActorType::System, CapabilityConstraint::Allow)
            ]
        );

        // EMAIL
        // Email verification happens during join flow, before users have roles in context
        // Therefore User actor needs Allow (not ContextOnly) permission
        matrix.insert(
            EMAIL_SEND_VERIFICATION,
            vec![
                CapabilityRule::new(ActorType::User, CapabilityConstraint::Allow),
                CapabilityRule::new(ActorType::Client, CapabilityConstraint::Allow),
                CapabilityRule::new(ActorType::System, CapabilityConstraint::Allow)
            ]
        );

        // MEMBERSHIP
        matrix.insert(
            MEMBERSHIP_JOIN,
            vec![CapabilityRule::new(ActorType::User, CapabilityConstraint::Allow)]
        );

        matrix.insert(
            MEMBERSHIP_LEAVE,
            vec![CapabilityRule::new(ActorType::User, CapabilityConstraint::OwnOnly)]
        );

        matrix.insert(
            MEMBERSHIP_GRANT,
            vec![CapabilityRule::new(ActorType::Client, CapabilityConstraint::SameClientOnly)]
        );

        matrix.insert(
            MEMBERSHIP_REVOKE,
            vec![CapabilityRule::new(ActorType::Client, CapabilityConstraint::SameClientOnly)]
        );

        // CONTEXT MANAGEMENT
        matrix.insert(
            CONTEXT_CREATE,
            vec![
                CapabilityRule::new(ActorType::Client, CapabilityConstraint::Allow),
                CapabilityRule::new(ActorType::System, CapabilityConstraint::Allow)
            ]
        );

        matrix.insert(
            CONTEXT_CONFIGURE,
            vec![CapabilityRule::new(ActorType::Client, CapabilityConstraint::SameClientOnly)]
        );

        matrix.insert(
            CONTEXT_CONFIGURE_CAPABILITIES,
            vec![CapabilityRule::new(ActorType::Client, CapabilityConstraint::SameClientOnly)]
        );

        matrix.insert(
            CONTEXT_DELETE,
            vec![
                CapabilityRule::new(ActorType::Client, CapabilityConstraint::SameClientOnly),
                CapabilityRule::new(ActorType::System, CapabilityConstraint::Allow)
            ]
        );

        // ROLE MANAGEMENT
        matrix.insert(
            ROLES_GRANT,
            vec![CapabilityRule::new(ActorType::Client, CapabilityConstraint::SameClientOnly)]
        );

        matrix.insert(
            ROLES_REVOKE,
            vec![CapabilityRule::new(ActorType::Client, CapabilityConstraint::SameClientOnly)]
        );

        matrix.insert(
            ROLES_VIEW,
            vec![
                CapabilityRule::new(ActorType::User, CapabilityConstraint::Allow),
                CapabilityRule::new(ActorType::Client, CapabilityConstraint::Allow)
            ]
        );

        // ANALYTICS
        matrix.insert(
            ANALYTICS_VIEW,
            vec![
                CapabilityRule::new(ActorType::Client, CapabilityConstraint::SameClientOnly),
                CapabilityRule::new(ActorType::Sponsor, CapabilityConstraint::SameSponsorOnly)
            ]
        );

        matrix.insert(
            ANALYTICS_EXPORT,
            vec![CapabilityRule::new(ActorType::Client, CapabilityConstraint::SameClientOnly)]
        );

        // MODERATION
        matrix.insert(
            CONTENT_MODERATE,
            vec![
                CapabilityRule::new(ActorType::Client, CapabilityConstraint::ContextOnly),
                CapabilityRule::new(ActorType::System, CapabilityConstraint::Allow)
            ]
        );

        matrix.insert(
            USER_SUSPEND,
            vec![
                CapabilityRule::new(ActorType::Client, CapabilityConstraint::ContextOnly),
                CapabilityRule::new(ActorType::System, CapabilityConstraint::Allow)
            ]
        );

        matrix.insert(
            USER_BAN,
            vec![
                CapabilityRule::new(ActorType::Client, CapabilityConstraint::ContextOnly),
                CapabilityRule::new(ActorType::System, CapabilityConstraint::Allow)
            ]
        );

        matrix.insert(
            REPORT_VIEW,
            vec![CapabilityRule::new(ActorType::Client, CapabilityConstraint::ContextOnly)]
        );

        matrix.insert(
            REPORT_RESOLVE,
            vec![CapabilityRule::new(ActorType::Client, CapabilityConstraint::ContextOnly)]
        );

        // LEGACY - For gradual migration
        matrix.insert(
            LEGACY_ALLOW,
            vec![
                CapabilityRule::new(ActorType::User, CapabilityConstraint::Allow),
                CapabilityRule::new(ActorType::Client, CapabilityConstraint::Allow),
                CapabilityRule::new(ActorType::Sponsor, CapabilityConstraint::Allow),
                CapabilityRule::new(ActorType::AI, CapabilityConstraint::Allow),
                CapabilityRule::new(ActorType::System, CapabilityConstraint::Allow)
            ]
        );

        matrix
    }

    /// Get all defined capabilities in the matrix
    pub fn all_capabilities() -> Vec<&'static str> {
        all_capabilities()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_rules_spark_create() {
        let rules = CapabilityMatrix::get_rules(SPARK_CREATE);
        assert_eq!(rules.len(), 4);

        // All actors should have Allow constraint
        for rule in rules {
            assert_eq!(rule.constraint, CapabilityConstraint::Allow);
        }
    }

    #[test]
    fn test_get_rules_spark_delete() {
        let rules = CapabilityMatrix::get_rules(SPARK_DELETE);
        assert_eq!(rules.len(), 4);

        // User has OwnOnly, others have Allow
        let user_rule = rules
            .iter()
            .find(|r| r.actor_type == ActorType::User)
            .unwrap();
        assert_eq!(user_rule.constraint, CapabilityConstraint::OwnOnly);

        let client_rule = rules
            .iter()
            .find(|r| r.actor_type == ActorType::Client)
            .unwrap();
        assert_eq!(client_rule.constraint, CapabilityConstraint::Allow);
    }

    #[test]
    fn test_get_constraint() {
        // User can create sparks
        assert_eq!(
            CapabilityMatrix::get_constraint(ActorType::User, SPARK_CREATE),
            Some(CapabilityConstraint::Allow)
        );

        // User can only delete own sparks
        assert_eq!(
            CapabilityMatrix::get_constraint(ActorType::User, SPARK_DELETE),
            Some(CapabilityConstraint::OwnOnly)
        );

        // User cannot run matches (not in matrix)
        assert_eq!(CapabilityMatrix::get_constraint(ActorType::User, MATCH_RUN), None);

        // Client can run matches
        assert_eq!(
            CapabilityMatrix::get_constraint(ActorType::Client, MATCH_RUN),
            Some(CapabilityConstraint::Allow)
        );
    }

    #[test]
    fn test_roles_grant_scoped_to_client() {
        let rules = CapabilityMatrix::get_rules(ROLES_GRANT);
        assert_eq!(rules.len(), 1);

        let client_rule = &rules[0];
        assert_eq!(client_rule.actor_type, ActorType::Client);
        assert_eq!(client_rule.constraint, CapabilityConstraint::SameClientOnly);
    }

    #[test]
    fn test_legacy_allow_all_actors() {
        let rules = CapabilityMatrix::get_rules(LEGACY_ALLOW);
        assert_eq!(rules.len(), 5); // All 5 actor types

        for rule in rules {
            assert_eq!(rule.constraint, CapabilityConstraint::Allow);
        }
    }

    #[test]
    fn test_undefined_capability_returns_empty() {
        let rules = CapabilityMatrix::get_rules("undefined:capability");
        assert!(rules.is_empty());
    }

    #[test]
    fn test_analytics_scoping() {
        // Client can view analytics for their own contexts
        assert_eq!(
            CapabilityMatrix::get_constraint(ActorType::Client, ANALYTICS_VIEW),
            Some(CapabilityConstraint::SameClientOnly)
        );

        // Sponsor can view analytics for their sponsorships
        assert_eq!(
            CapabilityMatrix::get_constraint(ActorType::Sponsor, ANALYTICS_VIEW),
            Some(CapabilityConstraint::SameSponsorOnly)
        );

        // User cannot view analytics (not in matrix)
        assert_eq!(CapabilityMatrix::get_constraint(ActorType::User, ANALYTICS_VIEW), None);
    }
}
