# IaC DriftWatch

IaC DriftWatch is a centralized Infrastructure-as-Code drift
detection and monitoring platform.

## Current Technology Stack

- Python
- FastAPI
- PostgreSQL
- Terraform
- Docker
- Jenkins

## Current Status

Day 1 - Project foundation

## Scheduled Drift Email Configuration

Copy these placeholders into the application environment and replace them with deployment values. `SMTP_PASSWORD` must be supplied through a secret manager in production.

```dotenv
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=alerts@example.com
SMTP_PASSWORD=replace-with-smtp-password
SMTP_FROM=driftwatch@example.com
SMTP_RECIPIENTS=you@example.com
DRIFT_SCAN_INTERVAL_MINUTES=15
SESSION_IDLE_TTL_SECONDS=28800
```

The session idle TTL is clamped to at least the configured access-token lifetime; the default access-token lifetime is 480 minutes.

## Session Presence

Presence and email throttle state are in-process; the root Dockerfile starts one Uvicorn worker, while the alternate Gunicorn entrypoint defaults to two, so multi-worker deployments maintain separate state per worker.

## Planned Capabilities

- Terraform drift detection
- Drift history
- Severity classification
- Dashboard visualization
- Automated scanning
- Alert generation# IaC DriftWatch 
