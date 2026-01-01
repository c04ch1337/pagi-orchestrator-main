use async_trait::async_trait;
use interprocess::local_socket::LocalSocketStream;
use pagi_core_lib::{AgentFact, AgentIdentity, BaseAgent, PAGICoreModel};
use std::io::Write;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

fn send_ipc_status(message: &str) {
    // Best-effort: if the IPC channel isn't available, continue without failing the agent.
    if let Ok(mut conn) = LocalSocketStream::connect(pagi_core_lib::PAGI_IPC_NAME) {
        let _ = conn.write_all(message.as_bytes());
    }
}

/// Agent responsible for web / document research.
pub struct SearchAgent;

#[async_trait]
impl BaseAgent for SearchAgent {
    async fn run(
        &self,
        identity: &AgentIdentity,
        core: Arc<PAGICoreModel>,
        task_input: &str,
    ) -> String {
        send_ipc_status("SearchAgent: I'm starting research");
        println!("[SearchAgent] Starting research with input: {task_input}");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_secs();

        let fact = AgentFact {
            agent_id: "SearchAgent".to_string(),
            timestamp,
            fact_type: "ResearchResult".to_string(),
            content: format!(
                "Simulated research completed. Input was: {task_input}. Output: top compounds summary placeholder."
            ),
        };

        match core.record_fact(identity, fact) {
            Ok(()) => "Fact recorded successfully".to_string(),
            Err(e) => format!("Failed to record fact: {e}"),
        }
    }
}

/// Agent responsible for scheduling / calendar operations.
pub struct CalendarAgent;

#[async_trait]
impl BaseAgent for CalendarAgent {
    async fn run(
        &self,
        identity: &AgentIdentity,
        core: Arc<PAGICoreModel>,
        task_input: &str,
    ) -> String {
        send_ipc_status("CalendarAgent: I'm starting scheduling");
        println!("[CalendarAgent] Starting scheduling with input: {task_input}");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_secs();

        let fact = AgentFact {
            agent_id: "CalendarAgent".to_string(),
            timestamp,
            fact_type: "SchedulingResult".to_string(),
            content: format!(
                "Simulated scheduling completed. Input was: {task_input}. Output: meeting created placeholder."
            ),
        };

        match core.record_fact(identity, fact) {
            Ok(()) => "Fact recorded successfully".to_string(),
            Err(e) => format!("Failed to record fact: {e}"),
        }
    }
}

/// Agent responsible for security alert triage (shim implementation for integration testing).
pub struct CybersecurityAgent;

impl CybersecurityAgent {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl BaseAgent for CybersecurityAgent {
    async fn run(
        &self,
        identity: &AgentIdentity,
        core: Arc<PAGICoreModel>,
        task_input: &str,
    ) -> String {
        send_ipc_status("CybersecurityAgent: starting triage");
        println!("[CybersecurityAgent] Triage requested with input: {task_input}");
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_secs();

        let fact = AgentFact {
            agent_id: "CybersecurityAgent".to_string(),
            timestamp,
            fact_type: "CyberTriageResult".to_string(),
            content: format!(
                "Simulated cyber triage completed successfully. Input was: {task_input}."
            ),
        };

        match core.record_fact(identity, fact) {
            Ok(()) => "Cyber triage fact recorded successfully".to_string(),
            Err(e) => format!("Cyber triage failed to record fact: {e}"),
        }
    }
}

/// Low-priority reflective agent that generates self-improvement directives.
pub struct ReflectiveAgent;

#[async_trait]
impl BaseAgent for ReflectiveAgent {
    async fn run(
        &self,
        identity: &AgentIdentity,
        core: Arc<PAGICoreModel>,
        _task_input: &str,
    ) -> String {
        let facts = match core.retrieve_facts_by_timestamp(identity, 0) {
            Ok(f) => f,
            Err(e) => {
                return format!("ReflectiveAgent cannot read facts: {e}");
            }
        };
        println!("[ReflectiveAgent] Reflecting on {} past tasks...", facts.len());

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_secs();

        let fact = AgentFact {
            agent_id: "ReflectiveAgent".to_string(),
            timestamp,
            fact_type: "AnalysisResult".to_string(),
            // This is the key phrase for the symbolic rule engine.
            content: "Failure: SearchAgent performance below threshold (symbolic directive ready)"
                .to_string(),
        };

        match core.record_fact(identity, fact) {
            Ok(()) => "Analysis fact recorded successfully".to_string(),
            Err(e) => format!("Failed to record analysis fact: {e}"),
        }
    }
}
