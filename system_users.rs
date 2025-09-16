use std::collections::HashSet;
use backend_domain::ClientUserRole;
use common_lib::{
    constants::{
        SYSTEM_USER_COUNTRY_CODE,
        SYSTEM_USER_FIREBASE_ID,
        SYSTEM_USER_ID,
        SYSTEM_USER_PHONE_NUMBER,
    },
    utils::get_env_var,
};
use crate::{ auth_lib::bearer_token_guard::GuardUser, common_lib };

#[derive(Debug, Clone)]
pub struct SystemUserConfig {
    pub user_id: String,
    pub firebase_user_id: String,
    pub phone_number: String,
    pub country_code: String,
    pub service_name: Option<String>,
}

impl SystemUserConfig {
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let country_code = get_env_var(SYSTEM_USER_COUNTRY_CODE, None)?;
        let service_name = get_env_var("SERVICE_NAME", None)?;

        // Generate contextual IDs
        let firebase_user_id = Self::generate_firebase_id(
            &country_code,
            &Some(service_name.clone())
        )?;
        let phone_number = Self::get_country_phone_number(&country_code)?;
        let user_id = Self::generate_user_id(&country_code, &Some(service_name.clone()));

        Ok(SystemUserConfig {
            user_id,
            firebase_user_id,
            phone_number,
            country_code,
            service_name: Some(service_name),
        })
    }

    /// Convert SystemUserConfig to GuardUser for service initialization
    pub fn to_guard_user(&self) -> GuardUser {
        let mut roles = HashSet::new();
        roles.insert(ClientUserRole::System);

        GuardUser {
            user_id: self.user_id.clone(),
            roles,
            country_code: self.country_code.clone(),
            firebase_user_id: self.firebase_user_id.clone(),
            phone_number: Some(self.phone_number.clone()),
            city: None, // System users don't have city typically
            user_role: None,
            verifications: None,
        }
    }

    fn generate_firebase_id(
        country_code: &str,
        service_name: &Option<String>
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        // Try explicit env var first
        if let Ok(explicit_id) = get_env_var(SYSTEM_USER_FIREBASE_ID, None) {
            return Ok(explicit_id);
        }

        // Generate contextual ID
        let service_part = service_name.as_deref().unwrap_or("system");
        let firebase_id = format!(
            "system_{}_{}",
            service_part.to_lowercase(),
            country_code.to_lowercase()
        );

        Ok(firebase_id)
    }

    fn get_country_phone_number(
        country_code: &str
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        // Try explicit env var first
        if let Ok(explicit_phone) = get_env_var(SYSTEM_USER_PHONE_NUMBER, None) {
            return Ok(explicit_phone);
        }

        // Generate valid phone number for country
        let phone = match country_code {
            "GB" => "+447700900123",
            "SA" => "+966500000123",
            "US" => "+15551234567",
            "FR" => "+33123456789",
            "DE" => "+491234567890",
            _ => "+447700900123", // Default to UK
        };

        Ok(phone.to_string())
    }

    fn generate_user_id(country_code: &str, service_name: &Option<String>) -> String {
        // Try explicit env var first
        if let Ok(explicit_id) = get_env_var(SYSTEM_USER_ID, None) {
            return explicit_id;
        }

        let service_part = service_name.as_deref().unwrap_or("system");
        format!("system_{}_{}", service_part.to_lowercase(), country_code.to_lowercase())
    }
}
