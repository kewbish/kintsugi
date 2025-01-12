use derive_more::Display;

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq, Display)]
pub enum KintsugiError {
    RegistrationError,
    CryptoError(String),
    SerializationError(String),
    FileError(String),
}

impl std::error::Error for KintsugiError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}
