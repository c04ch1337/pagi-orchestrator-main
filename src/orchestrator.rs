use std::collections::HashMap;
use std::io::Read;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use futures::future::join_all;
use pagi_core_lib::{AgentIdentity, AuthScope, BaseAgent, PAGICoreModel, Task, KNOWLEDGE_BASE_PATH};

use crate::agents::{CalendarAgent, CybersecurityAgent, ReflectiveAgent, SearchAgent};

pub struct PAGIOrchestrator;

impl PAGIOrchestrator {
    pub async fn execute_prompt(user_prompt: &str) -> Result<(), String> {
        let start_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_secs();

        let db = pagi_core_lib::sled::open(KNOWLEDGE_BASE_PATH)
            .map_err(|e| format!("Failed to open knowledge base: {e}"))?;

        let mut core = PAGICoreModel::from_db(db);
        core.init_ipc_server()?;

        // Extract IPC listener before wrapping core in Arc.
        let ipc_name = core.ipc_name().to_string();
        let listener = core
            .take_ipc_listener()
            .ok_or_else(|| "IPC server was not initialized".to_string())?;

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
            .ok_or_else(|| "ReflectiveAgent not registered".to_string())?
            .clone();
        let reflector_id = identities
            .get("ReflectiveAgent")
            .ok_or_else(|| "ReflectiveAgent identity missing".to_string())?
            .clone();
        let reflection_status = reflector
            .run(&reflector_id, core.clone(), "{}")
            .await;
        println!("[ReflectiveAgent] {reflection_status}");

        let plan: Vec<Task> = core.general_reasoning(user_prompt).await?;
        let expected_status_messages = plan.len();

        // Spawn a dedicated listener that prints real-time agent status messages.
        let ipc_handle = tokio::task::spawn_blocking(move || -> Result<(), String> {
            println!("[IPC] Listening on {ipc_name}");

            let listener = listener;
            for _ in 0..expected_status_messages {
                let mut conn = listener.accept().map_err(|e| e.to_string())?;
                let mut msg = String::new();
                conn.read_to_string(&mut msg).map_err(|e| e.to_string())?;
                println!("[IPC] {msg}");
            }

            Ok(())
        });

        // Spawn each task concurrently.
        let mut handles = Vec::with_capacity(plan.len());
        for task in plan {
            let agent = agents
                .get(&task.agent_type)
                .ok_or_else(|| format!("No agent registered for type: {}", task.agent_type))?
                .clone();

            let identity = identities
                .get(&task.agent_type)
                .ok_or_else(|| format!("No identity registered for type: {}", task.agent_type))?
                .clone();

            let input_data = task.input_data;
            let core = core.clone();
            let handle = tokio::spawn(async move {
                agent.run(&identity, core, &input_data).await
            });
            handles.push(handle);
        }

        let results = join_all(handles)
            .await
            .into_iter()
            .map(|r| r.map_err(|e| e.to_string()))
            .collect::<Result<Vec<String>, String>>()?;

        println!("\n=== PAGI Orchestrator Output ===");
        for result in results {
            println!("{result}");
        }

        // Final step: retrieve structured facts from the shared knowledge base.
        let orchestrator_identity = AgentIdentity {
            id: "Orchestrator".to_string(),
            scopes: vec![AuthScope::ReadFacts],
        };

        let facts = core
            .retrieve_facts_by_timestamp(&orchestrator_identity, start_ts as u128)
            .unwrap_or_else(|e| {
                eprintln!("Failed to read facts: {e}");
                Vec::new()
            });
        println!("\n=== Knowledge Base Facts (since start_ts={start_ts}) ===");
        for fact in facts {
            println!("{fact:?}");
        }

        // Ensure the IPC listener finishes (after receiving the expected number of messages).
        ipc_handle
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| format!("IPC listener error: {e}"))?;

        Ok(())
    }
}
