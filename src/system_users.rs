#[derive(Debug, Clone)]
pub struct SystemUserConfig {
    pub user_id: String,
    pub firebase_user_id: String,
    pub phone_number: String,
    pub country_code: String,
    pub service_name: Option<String>,
}

impl SystemUserConfig {
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        let country_code = std::env::var("SYSTEM_USER_COUNTRY_CODE")?;
        let service_name = std::env::var("SERVICE_NAME").ok();

        // Generate contextual IDs
        let firebase_user_id = Self::generate_firebase_id(&country_code, &service_name)?;
        let phone_number = Self::get_country_phone_number(&country_code)?;
        let user_id = Self::generate_user_id(&country_code, &service_name);

        Ok(SystemUserConfig {
            user_id,
            firebase_user_id,
            phone_number,
            country_code,
            service_name,
        })
    }

    fn generate_firebase_id(
        country_code: &str,
        service_name: &Option<String>
    ) -> Result<String, Box<dyn std::error::Error>> {
        // Try explicit env var first
        if let Ok(explicit_id) = std::env::var("SYSTEM_USER_FIREBASE_ID") {
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

    fn get_country_phone_number(country_code: &str) -> Result<String, Box<dyn std::error::Error>> {
        // Try explicit env var first
        if let Ok(explicit_phone) = std::env::var("SYSTEM_USER_PHONE_NUMBER") {
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
        if let Ok(explicit_id) = std::env::var("SYSTEM_USER_ID") {
            return explicit_id;
        }

        let service_part = service_name.as_deref().unwrap_or("system");
        format!("system_{}_{}", service_part.to_lowercase(), country_code.to_lowercase())
    }
}
