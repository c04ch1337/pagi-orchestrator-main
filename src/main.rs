use std::net::SocketAddr;
use std::sync::Arc;

use axum::{http::StatusCode, routing::{get, post}, Router};
use pagi_orchestrator_main::error::{AppError, Result};
use pagi_orchestrator_main::orchestrator::{handle_task, ready_handler, PAGIOrchestrator};

use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

fn initialize_tracing() -> WorkerGuard {
    // Ensure the logs directory exists for rolling file output.
    let _ = std::fs::create_dir_all("logs");

    // Prefer `RUST_LOG` when set; otherwise default to `info` for visibility.
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    // Non-blocking, daily-rolled file appender (high-perf best practice).
    let file_appender = tracing_appender::rolling::daily("logs", "pagi.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    let console_layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .with_target(true);

    let file_layer = tracing_subscriber::fmt::layer()
        .with_writer(non_blocking)
        .with_ansi(false)
        .with_target(true);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(console_layer)
        .with(file_layer)
        .init();

    guard
}

async fn health_handler() -> StatusCode {
    StatusCode::OK
}

#[tokio::main]
async fn main() -> Result<()> {
    let _tracing_guard = initialize_tracing();

    let orchestrator = Arc::new(PAGIOrchestrator::new()?);
    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/ready", get(ready_handler))
        .route("/api/v1/task", post(handle_task))
        .with_state(orchestrator);

    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    tracing::info!("PAGI Orchestrator listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to bind {addr}: {e}")))?;

    axum::serve(listener, app)
        .await
        .map_err(|e| AppError::Internal(format!("Axum server failed: {e}")))?;

    Ok(())
}
