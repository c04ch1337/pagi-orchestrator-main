mod agents;
mod orchestrator;

use orchestrator::PAGIOrchestrator;

#[tokio::main]
async fn main() {
    let prompt = "I have a critical SIEM alert in Rapid7. Please initiate triage.";

    if let Err(e) = PAGIOrchestrator::execute_prompt(prompt).await {
        eprintln!("Orchestrator error: {e}");
        std::process::exit(1);
    }
}
