use std::collections::HashMap;
use std::io::Read;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{extract::State, http::StatusCode, Json};
use futures::future::join_all;
use pagi_core_lib::{
    AgentFact, AgentIdentity, AuthScope, BaseAgent, PAGICoreModel, Task, KNOWLEDGE_BASE_PATH,
};
use pagi_external_api_lib::llm_provider::LLMProvider;

use crate::agents::{CalendarAgent, CybersecurityAgent, ReflectiveAgent, SearchAgent};
use crate::error::{AppError, Result};

#[derive(Clone)]
pub struct PAGIOrchestrator {
    llm_provider: Arc<LLMProvider>,
    /// Prevent concurrent executions that would contend for shared global resources
    /// (e.g. fixed IPC name / listener).
    execution_lock: Arc<tokio::sync::Mutex<()>>,
}

impl PAGIOrchestrator {
    pub fn new() -> Result<Self> {
        // Initialize external config + provider dependencies up-front.
        // This ensures missing env/config errors fail fast at orchestrator startup.
        if std::env::var("OPENROUTER_API_KEY").is_err() {
            std::env::set_var("OPENROUTER_API_KEY", "DUMMY");
        }
        if std::env::var("JIRA_API_TOKEN").is_err() {
            // Integration-test default so the simulated Jira call can succeed.
            std::env::set_var("JIRA_API_TOKEN", "DUMMY_JIRA_TOKEN");
        }

        let _config = pagi_external_api_lib::config::PAGIConfig::load();
        let llm_provider = Arc::new(LLMProvider::new());

        Ok(Self {
            llm_provider,
            execution_lock: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    pub async fn execute_prompt(&self, user_prompt: &str) -> Result<serde_json::Value> {
        // Ensure single-flight execution while the core uses a fixed IPC name.
        let _guard = self.execution_lock.lock().await;

        let start_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| AppError::Internal(e.to_string()))?
            .as_secs();

        let db = pagi_core_lib::sled::open(KNOWLEDGE_BASE_PATH)
            .map_err(|e| AppError::Internal(format!("Failed to open knowledge base: {e}")))?;

        let mut core = PAGICoreModel::from_db(db);
        core.init_ipc_server()
            .map_err(|e| AppError::Core(format!("Failed to init IPC server: {e}")))?;

        // Extract IPC listener before wrapping core in Arc.
        let ipc_name = core.ipc_name().to_string();
        let listener = core
            .take_ipc_listener()
            .ok_or_else(|| AppError::Core("IPC server was not initialized".to_string()))?;

        let core = Arc::new(core);

        // Dynamic agent lookup (shared across tasks).
        let mut agents: HashMap<String, Arc<dyn BaseAgent + Send + Sync>> = HashMap::new();
        agents.insert("SearchAgent".to_string(), Arc::new(SearchAgent));
        agents.insert("CalendarAgent".to_string(), Arc::new(CalendarAgent));
        agents.insert("ReflectiveAgent".to_string(), Arc::new(ReflectiveAgent));
        agents.insert(
            "CybersecurityAgent".to_string(),
            Arc::new(CybersecurityAgent::new()),
        );

        // Agent identities (PoLP).
        let mut identities: HashMap<String, AgentIdentity> = HashMap::new();
        identities.insert(
            "SearchAgent".to_string(),
            AgentIdentity {
                id: "SearchAgent".to_string(),
                scopes: vec![AuthScope::ReadFacts, AuthScope::WriteFacts],
            },
        );
        identities.insert(
            "CalendarAgent".to_string(),
            AgentIdentity {
                id: "CalendarAgent".to_string(),
                scopes: vec![AuthScope::WriteFacts],
            },
        );
        identities.insert(
            "ReflectiveAgent".to_string(),
            AgentIdentity {
                id: "ReflectiveAgent".to_string(),
                scopes: vec![AuthScope::ReadFacts, AuthScope::WriteFacts],
            },
        );
        identities.insert(
            "CybersecurityAgent".to_string(),
            AgentIdentity {
                id: "CybersecurityAgent".to_string(),
                scopes: vec![
                    AuthScope::ReadFacts,
                    AuthScope::WriteFacts,
                    AuthScope::WritePolicy,
                    AuthScope::ExternalAPI,
                ],
            },
        );

        // Run the reflective agent once before planning/execution (RSI/reflection loop).
        let reflector = agents
            .get("ReflectiveAgent")
            .ok_or_else(|| AppError::Internal("ReflectiveAgent not registered".to_string()))?
            .clone();
        let reflector_id = identities
            .get("ReflectiveAgent")
            .ok_or_else(|| AppError::Internal("ReflectiveAgent identity missing".to_string()))?
            .clone();
        let reflection_status = reflector
            .run(&reflector_id, core.clone(), "{}")
            .await;
        tracing::info!("[ReflectiveAgent] {reflection_status}");

        // --- Dependency inversion boundary ---
        // The microkernel (`pagi-core-lib`) no longer depends on external API / LLM crates.
        // The orchestrator owns the LLM provider lifecycle and passes the raw JSON response
        // into the core for parsing.
        // Provide KB context to the LLM (optional but improves planning quality).
        let planner_identity = AgentIdentity {
            id: "OrchestratorPlanner".to_string(),
            scopes: vec![AuthScope::ReadFacts],
        };
        let facts = match core.retrieve_facts_by_timestamp(&planner_identity, 0) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!("Failed to retrieve facts for planner context: {e}");
                Vec::new()
            }
        };
        let facts_json = serde_json::to_string(&facts)?;

        let system_prompt = format!(
            "You are a PAGI AGI planner. Output ONLY valid JSON: an array of tasks. Each task must have keys: \
             agent_type (string) and input_data (object or string). \
             The orchestrator will execute these tasks concurrently.\n\n\
             Known agents include: SearchAgent, CalendarAgent, CybersecurityAgent, ReflectiveAgent.\n\n\
             Recent facts (JSON): {facts_json}"
        );

        let llm_response = if self.llm_provider.config.openrouter_api_key == "DUMMY"
            || std::env::var("PAGI_DISABLE_LLM").ok().as_deref() == Some("1")
        {
            String::new()
        } else {
            match self
                .llm_provider
                .generate_response(user_prompt, &system_prompt, None)
                .await
            {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(
                        "LLM call failed; falling back to core stub planner: {e}"
                    );
                    String::new()
                }
            }
        };

        let plan: Vec<Task> = core
            .general_reasoning(user_prompt, &llm_response)
            .await
            .map_err(|e| AppError::Core(e))?;
        let expected_status_messages = plan.len();
        let planned_agents: Vec<String> = plan.iter().map(|t| t.agent_type.clone()).collect();

        // Spawn a dedicated listener that prints real-time agent status messages.
        let ipc_handle = tokio::task::spawn_blocking(move || -> std::result::Result<(), String> {
            tracing::info!("[IPC] Listening on {ipc_name}");

            let listener = listener;
            for _ in 0..expected_status_messages {
                let mut conn = listener.accept().map_err(|e| e.to_string())?;
                let mut msg = String::new();
                conn.read_to_string(&mut msg).map_err(|e| e.to_string())?;
                tracing::info!("[IPC] {msg}");
            }

            Ok(())
        });

        // Spawn each task concurrently.
        let mut handles = Vec::with_capacity(plan.len());
        for task in plan {
            let agent = agents
                .get(&task.agent_type)
                .ok_or_else(|| {
                    AppError::Internal(format!(
                        "No agent registered for type: {}",
                        task.agent_type
                    ))
                })?
                .clone();

            let identity = identities
                .get(&task.agent_type)
                .ok_or_else(|| {
                    AppError::Internal(format!(
                        "No identity registered for type: {}",
                        task.agent_type
                    ))
                })?
                .clone();

            let input_data = task.input_data;
            let core = core.clone();
            let handle = tokio::spawn(async move {
                agent.run(&identity, core, &input_data).await
            });
            handles.push(handle);
        }

        let results: Vec<String> = join_all(handles)
            .await
            .into_iter()
            .map(|r| r.map_err(|e| AppError::Internal(e.to_string())))
            .collect::<Result<Vec<String>>>()?;

        tracing::info!("=== PAGI Orchestrator Output ===");
        for result in &results {
            tracing::info!("{result}");
        }

        // Final step: retrieve structured facts from the shared knowledge base.
        let orchestrator_identity = AgentIdentity {
            id: "Orchestrator".to_string(),
            scopes: vec![AuthScope::ReadFacts],
        };

        let new_facts = match core.retrieve_facts_by_timestamp(&orchestrator_identity, start_ts as u128) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!("Failed to read facts: {e}");
                Vec::new()
            }
        };
        let new_facts_debug: Vec<String> = new_facts.iter().map(|f| format!("{f:?}")).collect();

        // Ensure the IPC listener finishes (after receiving the expected number of messages).
        ipc_handle
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?
            .map_err(|e| AppError::Internal(format!("IPC listener error: {e}")))?;

        Ok(serde_json::json!({
            "prompt": user_prompt,
            "planned_agents": planned_agents,
            "start_ts": start_ts,
            "results": results,
            "facts": new_facts_debug,
        }))
    }

    pub async fn check_readiness(&self) -> Result<()> {
        // --- Core connectivity check (KB read + write) ---
        let db = pagi_core_lib::sled::open(KNOWLEDGE_BASE_PATH)
            .map_err(|e| AppError::Internal(format!("Failed to open knowledge base: {e}")))?;
        let core = PAGICoreModel::from_db(db);

        let probe_identity = AgentIdentity {
            id: "ReadinessProbe".to_string(),
            scopes: vec![AuthScope::ReadFacts, AuthScope::WriteFacts],
        };

        // Read
        core.retrieve_facts_by_timestamp(&probe_identity, 0)
            .map_err(AppError::Core)?;

        // Write (best-effort but should succeed if KB is writable)
        let now_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| AppError::Internal(e.to_string()))?
            .as_secs();

        let fact = AgentFact {
            agent_id: "ReadinessProbe".to_string(),
            timestamp: now_ts,
            fact_type: "ReadinessProbe".to_string(),
            content: "ready".to_string(),
        };

        core.record_fact(&probe_identity, fact)
            .map_err(AppError::Core)?;

        // --- External API / LLM configuration check ---
        let openrouter_key = std::env::var("OPENROUTER_API_KEY")
            .map_err(|e| AppError::ConfigLoadError(e.to_string()))?;
        if openrouter_key.trim().is_empty() || openrouter_key == "DUMMY" {
            return Err(AppError::ConfigLoadError(
                "OPENROUTER_API_KEY is missing (or still set to DUMMY)".to_string(),
            ));
        }
        if self.llm_provider.config.openrouter_api_key.trim().is_empty()
            || self.llm_provider.config.openrouter_api_key == "DUMMY"
        {
            return Err(AppError::ConfigLoadError(
                "LLM provider is not configured with a valid OpenRouter API key".to_string(),
            ));
        }

        let jira_token = std::env::var("JIRA_API_TOKEN")
            .map_err(|e| AppError::ConfigLoadError(e.to_string()))?;
        if jira_token.trim().is_empty() || jira_token == "DUMMY_JIRA_TOKEN" {
            return Err(AppError::ConfigLoadError(
                "JIRA_API_TOKEN is missing (or still set to DUMMY_JIRA_TOKEN)".to_string(),
            ));
        }

        Ok(())
    }
}

#[derive(serde::Deserialize)]
pub struct TaskRequest {
    pub prompt: String,
    pub domain: Option<String>,
}

pub async fn handle_task(
    State(orchestrator): State<Arc<PAGIOrchestrator>>,
    Json(request): Json<TaskRequest>,
) -> Result<Json<serde_json::Value>> {
    let mut response = orchestrator
        .execute_prompt(&request.prompt)
        .await?;

    if let Some(domain) = request.domain {
        if let Some(obj) = response.as_object_mut() {
            obj.insert("domain".to_string(), serde_json::Value::String(domain));
        }
    }

    Ok(Json(response))
}

pub async fn ready_handler(State(orchestrator): State<Arc<PAGIOrchestrator>>) -> Result<StatusCode> {
    orchestrator.check_readiness().await?;
    Ok(StatusCode::OK)
}
