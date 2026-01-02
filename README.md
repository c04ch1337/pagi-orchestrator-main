# PAGI Orchestrator (HTTP Service)

This repository runs the PAGI orchestrator as an **Axum**-based HTTP service. It exposes a small REST API for submitting operator prompts to the AGI core and retrieving results.

## Run

```bash
cargo run
```

The server binds to `127.0.0.1:8080`.

## Endpoints

### Liveness

`GET /health`

Returns `200 OK` when the server process/event loop is running.

```bash
curl -i http://127.0.0.1:8080/health
```

### Readiness

`GET /ready`

Returns `200 OK` only when:

- The knowledge base (sled DB) can be opened and a small read/write probe succeeds.
- Required external configuration is present.

```bash
curl -i http://127.0.0.1:8080/ready
```

### Submit a Task

`POST /api/v1/task`

Request body:

```json
{
  "prompt": "I have a critical SIEM alert in Rapid7. Please initiate triage.",
  "domain": "siem"
}
```

Example:

```bash
curl -sS \
  -X POST http://127.0.0.1:8080/api/v1/task \
  -H 'content-type: application/json' \
  -d '{"prompt":"I have a critical SIEM alert in Rapid7. Please initiate triage.","domain":"siem"}'
```

Response (shape):

```json
{
  "prompt": "...",
  "domain": "...",
  "planned_agents": ["SearchAgent", "CybersecurityAgent"],
  "start_ts": 1700000000,
  "results": ["..."],
  "facts": ["..."]
}
```

## Configuration

Environment variables:

- `OPENROUTER_API_KEY` (required for readiness; used by the LLM provider)
- `JIRA_API_TOKEN` (required for readiness; used by external API integrations)
- `PAGI_DISABLE_LLM=1` (optional: disable live LLM calls and fall back to the core stub planner)

## Notes

- Runtime artifacts (`/logs/` and `/pagi_knowledge_base/`) are intentionally ignored by git.

