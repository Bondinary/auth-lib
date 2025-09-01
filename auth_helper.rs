use base64::{ Engine as _, engine::general_purpose };
use common_lib::constants::{
    FIREBASE_CREDENTIALS_BASE64,
    FIREBASE_PROJECT_ID,
    GOOGLE_API_KEYS_URL,
    LOCAL_FIREBASE_ACCOUNT_SERVICE_JSON_PATH,
    X_FIREBASE_UID,
    X_INTERNAL_API_KEY,
    X_PHONE_NUMBER,
};
use common_lib::utils::get_env_var;
use jsonwebtoken::{
    decode,
    decode_header,
    encode,
    Algorithm,
    DecodingKey,
    EncodingKey,
    Header,
    Validation,
};
use once_cell::sync::Lazy;
use openssl::error::ErrorStack;
use openssl::x509::X509;
use reqwest::{ self, Client, RequestBuilder };
use serde::{ Deserialize, Serialize };
use serde_json::json;
use std::error::Error;
use std::fs::File;
use std::io::ErrorKind::{ InvalidData, NotFound };
use std::sync::Mutex;
use std::time::UNIX_EPOCH;
use std::{ collections::{ HashMap, HashSet }, time::SystemTime };
use tracing::{ debug, error, info, warn };
use crate::{common_lib, GuardUser, GuardUserOrAnonymous};

static KEYS: Lazy<Mutex<HashMap<String, Vec<u8>>>> = Lazy::new(|| Mutex::new(HashMap::new()));

#[derive(Default)]
pub struct AuthHelper {}

impl AuthHelper {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn fetch_firebase_keys(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let url = get_env_var(GOOGLE_API_KEYS_URL, None)?;
        let res: HashMap<String, String> = reqwest::get(url).await?.json().await?;

        let mut keys = KEYS.lock().unwrap();
        keys.clear();

        for (k, v) in res {
            let pem_bytes = v.into_bytes();
            keys.insert(k, pem_bytes);
        }

        Ok(())
    }

    pub async fn validate_firebase_access_token(
        &self,
        token: &str
    ) -> Result<Claims, Box<dyn Error + Send + Sync>> {
        debug!("Starting Firebase access token validation");
        let keys = KEYS.lock().unwrap();
        let header = decode_header(token).map_err(|e| {
            error!("Failed to decode JWT header: {:?}", e);
            Box::new(e) as Box<dyn Error + Send + Sync>
        })?;

        let kid = header.kid.ok_or_else(|| {
            error!("Missing 'kid' in JWT header");
            Box::new(std::io::Error::new(NotFound, "Missing header key")) as Box<
                dyn Error + Send + Sync
            >
        })?;

        debug!("Extracted key ID from header: {}", kid);

        let pem_bytes = keys.get(&kid).ok_or_else(|| {
            error!("No matching key found for kid: {}", kid);
            Box::new(std::io::Error::new(NotFound, format!("No key found for kid {kid}"))) as Box<
                dyn Error + Send + Sync
            >
        })?;

        let pub_key_pem = self.extract_public_key_from_certificate(pem_bytes).map_err(|e| {
            error!("Failed to extract public key for kid {}: {}", kid, e);
            Box::new(
                std::io::Error::new(InvalidData, format!("Failed to extract public key: {e}"))
            ) as Box<dyn Error + Send + Sync>
        })?;

        debug!("Public key extracted for kid: {}", kid);
        let decoding_key = DecodingKey::from_rsa_pem(&pub_key_pem).map_err(|e| {
            error!("Invalid PEM format for key ID {}: {}", kid, e);
            Box::new(
                std::io::Error::new(
                    InvalidData,
                    format!("Invalid PEM format for key ID {kid}: {e}")
                )
            ) as Box<dyn Error + Send + Sync>
        })?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = true;
        let project_id = get_env_var(FIREBASE_PROJECT_ID, None)?;
        let stripped_id = project_id;
        validation.set_audience(std::slice::from_ref(&stripped_id));

        let mut iss_set = HashSet::new();
        iss_set.insert(format!("https://securetoken.google.com/{stripped_id}"));
        validation.iss = Some(iss_set.clone());

        debug!("JWT validation rules set with audience: {}", stripped_id);
        let token_data = decode::<Claims>(token, &decoding_key, &validation).map_err(|e| {
            error!("Error decoding JWT: {:?}", e);
            Box::new(e) as Box<dyn Error + Send + Sync>
        })?;

        Ok(token_data.claims)
    }

    pub fn extract_public_key_from_certificate(&self, pem: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        let certificate = X509::from_pem(pem)?;
        let public_key = certificate.public_key()?;
        public_key.public_key_to_pem()
    }

    pub async fn load_service_account(
        &self
    ) -> Result<FirebaseServiceAccount, Box<dyn Error + Send + Sync>> {
        let firebase_service_account_path = get_env_var(
            LOCAL_FIREBASE_ACCOUNT_SERVICE_JSON_PATH,
            None
        )?;

        // Load service account credentials for making authorized requests
        let mut file = File::open(firebase_service_account_path)?;
        let mut contents = String::new();
        std::io::Read::read_to_string(&mut file, &mut contents)?;

        let service_account: FirebaseServiceAccount = serde_json::from_str(&contents)?;
        Ok(service_account)
    }

    pub async fn create_custom_token(
        &self,
        service_account: &FirebaseServiceAccount,
        email: &str
    ) -> Result<String, Box<dyn Error + Send + Sync>> {
        let iat = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as usize;
        let exp = iat + 3600; // Token valid for 1 hour

        let claims = Claims {
            iss: service_account.client_email.clone(),
            sub: service_account.client_email.clone(),
            aud: "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit".to_string(),
            iat,
            exp,
            uid: Some(email.to_string().clone()),
            phone_number: String::new(),
        };

        let key = EncodingKey::from_rsa_pem(service_account.private_key.as_bytes())?;
        let token = encode(&Header::new(Algorithm::RS256), &claims, &key)?;

        Ok(token)
    }

    pub async fn get_oauth2_access_token(&self) -> Result<String, Box<dyn Error + Send + Sync>> {
        let service_account = self.load_service_account().await?;
        let iat = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as usize;
        let exp = iat + 3600; // Token valid for 1 hour

        let claims = Claims {
            iss: service_account.client_email.clone(),
            sub: service_account.client_email.clone(),
            aud: "https://oauth2.googleapis.com/token".to_string(),
            iat,
            exp,
            uid: None,
            phone_number: String::new(),
        };

        let key = EncodingKey::from_rsa_pem(service_account.private_key.as_bytes())?;
        let jwt = encode(&Header::new(Algorithm::RS256), &claims, &key)?;

        let client = Client::new();
        let response = client
            .post("https://oauth2.googleapis.com/token")
            .form(
                &[
                    ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                    ("assertion", &jwt),
                ]
            )
            .send().await?;

        let token_response: serde_json::Value = response.json().await?;
        let access_token = token_response["access_token"]
            .as_str()
            .ok_or("Failed to get access token")?
            .to_string();

        Ok(access_token)
    }

    pub async fn get_firebase_admin_access_token(
        &self,
        email: &str
    ) -> Result<String, Box<dyn Error + Send + Sync>> {
        let service_account = self.load_service_account().await?;

        // Get OAuth2 access token
        let oauth2_access_token = self.get_oauth2_access_token().await?;

        // Create a custom token for the user
        let custom_token = self.create_custom_token(&service_account, email).await?;

        // Exchange the custom token for an ID token
        let client = Client::new();
        let res = client
            .post("https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken")
            .bearer_auth(&oauth2_access_token)
            .json(
                &json!({
                "token": custom_token,
                "returnSecureToken": true
            })
            )
            .send().await?;

        let res_json: serde_json::Value = res.json().await?;
        let id_token = res_json["idToken"].as_str().ok_or("Failed to get ID token")?.to_string();

        Ok(id_token)
    }

    pub fn add_auth_headers(
        mut request_builder: RequestBuilder,
        guard_user_or_anonymous: &GuardUserOrAnonymous, // Take GuardUserOrAnonymous by reference
        internal_api_key: &str // Take internal API key by reference
    ) -> RequestBuilder {
        request_builder = request_builder.header(X_INTERNAL_API_KEY, internal_api_key);

        match guard_user_or_anonymous {
            GuardUserOrAnonymous::User(guard_user) => {
                // For authenticated users, add both Firebase UID and phone number
                request_builder = request_builder.header(
                    X_FIREBASE_UID,
                    &guard_user.firebase_user_id
                );

                if let Some(phone_number) = &guard_user.phone_number {
                    request_builder = request_builder.header(X_PHONE_NUMBER, phone_number);
                } else {
                    warn!("add_auth_headers: X-Phone-Number not available in GuardUser.");
                }
            }
            GuardUserOrAnonymous::Anonymous(guard_anonymous) => {
                // For anonymous users, only add Firebase UID (no phone number)
                request_builder = request_builder.header(
                    X_FIREBASE_UID,
                    &guard_anonymous.firebase_user_id
                );
                debug!("add_auth_headers: Anonymous user - Firebase UID added, no phone number");
            }
        }

        request_builder
    }

    pub fn add_auth_headers_for_user(
        mut request_builder: RequestBuilder,
        guard_user: &GuardUser,
        internal_api_key: &str // Take internal API key by reference
    ) -> RequestBuilder {
        request_builder = request_builder.header(X_INTERNAL_API_KEY, internal_api_key);

        // For authenticated users, add both Firebase UID and phone number
        request_builder = request_builder.header(X_FIREBASE_UID, &guard_user.firebase_user_id);

        if let Some(phone_number) = &guard_user.phone_number {
            request_builder = request_builder.header(X_PHONE_NUMBER, phone_number);
        } else {
            warn!("add_auth_headers: X-Phone-Number not available in GuardUser.");
        }

        request_builder
    }

    pub fn add_internal_auth_headers(
        request_builder: RequestBuilder,
        internal_api_key: &str
    ) -> RequestBuilder {
        request_builder.header(X_INTERNAL_API_KEY, internal_api_key)
    }

    pub async fn load_service_account_from_encoded_base64(
        &self
    ) -> Result<FirebaseServiceAccount, Box<dyn Error + Send + Sync>> {
        // Try base64 environment variable first (for production/AWS deployment)
        if let Ok(base64_credentials) = get_env_var(FIREBASE_CREDENTIALS_BASE64, None) {
            debug!("Loading Firebase service account from base64 environment variable");
            // Decode base64 to get JSON string
            let decoded_bytes = general_purpose::STANDARD.decode(&base64_credentials).map_err(|e| {
                error!("Failed to decode base64 Firebase credentials: {}", e);
                Box::new(
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Invalid base64 Firebase credentials: {}", e)
                    )
                ) as Box<dyn Error + Send + Sync>
            })?;

            let json_string = String::from_utf8(decoded_bytes).map_err(|e| {
                error!("Failed to convert decoded bytes to UTF-8: {}", e);
                Box::new(
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Invalid UTF-8 in Firebase credentials: {}", e)
                    )
                ) as Box<dyn Error + Send + Sync>
            })?;

            let service_account: FirebaseServiceAccount = serde_json
                ::from_str(&json_string)
                .map_err(|e| {
                    error!("Failed to parse Firebase service account JSON: {}", e);
                    Box::new(
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("Invalid Firebase service account JSON: {}", e)
                        )
                    ) as Box<dyn Error + Send + Sync>
                })?;

            info!("Successfully loaded Firebase service account from environment variable");
            return Ok(service_account);
        }

        // Fallback to local file (for local development)
        if
            let Ok(firebase_service_account_path) = get_env_var(
                LOCAL_FIREBASE_ACCOUNT_SERVICE_JSON_PATH,
                None
            )
        {
            debug!("Loading Firebase service account from local file: {}", firebase_service_account_path);

            let mut file = File::open(&firebase_service_account_path).map_err(|e| {
                error!(
                    "Failed to open Firebase service account file '{}': {}",
                    firebase_service_account_path,
                    e
                );
                Box::new(e) as Box<dyn Error + Send + Sync>
            })?;

            let mut contents = String::new();
            std::io::Read::read_to_string(&mut file, &mut contents).map_err(|e| {
                error!("Failed to read Firebase service account file: {}", e);
                Box::new(e) as Box<dyn Error + Send + Sync>
            })?;

            let service_account: FirebaseServiceAccount = serde_json
                ::from_str(&contents)
                .map_err(|e| {
                    error!("Failed to parse Firebase service account JSON from file: {}", e);
                    Box::new(e) as Box<dyn Error + Send + Sync>
                })?;

            info!("Successfully loaded Firebase service account from local file");
            return Ok(service_account);
        }

        // Neither environment variable nor file path available
        let error_msg = format!(
            "Firebase service account not found. Set either {} (base64) or {} (file path) environment variable",
            FIREBASE_CREDENTIALS_BASE64,
            LOCAL_FIREBASE_ACCOUNT_SERVICE_JSON_PATH
        );
        error!("{}", error_msg);
        Err(
            Box::new(std::io::Error::new(std::io::ErrorKind::NotFound, error_msg)) as Box<
                dyn Error + Send + Sync
            >
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Claims {
    pub aud: String,
    pub exp: usize,
    pub iat: usize,
    pub iss: String,
    pub sub: String,
    pub uid: Option<String>,
    pub phone_number: String,
}

#[derive(Serialize, Deserialize)]
pub struct FirebaseServiceAccount {
    #[serde(rename = "type")]
    type_: String,
    project_id: String,
    private_key_id: String,
    private_key: String,
    client_email: String,
    client_id: String,
    auth_uri: String,
    token_uri: String,
    auth_provider_x509_cert_url: String,
    client_x509_cert_url: String,
}
