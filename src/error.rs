use axum::response::{IntoResponse, Response};
use axum::http::StatusCode;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Configuration Error: {0}")]
    ConfigLoadError(String),

    #[error("External API Error: {0}")]
    ExternalApi(String),

    #[error("PAGI Core Error: {0}")]
    Core(String),

    #[error("Serialization Error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Internal Server Error: {0}")]
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match &self {
            AppError::ConfigLoadError(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            AppError::ExternalApi(_) => (StatusCode::SERVICE_UNAVAILABLE, self.to_string()),
            AppError::Core(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            AppError::Json(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            AppError::Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "An internal error occurred.".to_string(),
            ),
        };

        (status, error_message).into_response()
    }
}

pub type Result<T> = std::result::Result<T, AppError>;

