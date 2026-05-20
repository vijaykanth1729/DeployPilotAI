# InfraAudit AI — by DeployPilot AI

AI-Powered Infrastructure Security & Compliance Scanner

## What It Does

InfraAudit AI automatically scans your infrastructure-as-code files for security
misconfigurations, compliance violations, and best practice deviations.

**Supported file types:**
- Kubernetes YAML (Deployments, Services, RBAC, NetworkPolicies)
- Terraform (.tf) — AWS resources, state management, provider config
- Dockerfiles — Image security, build best practices
- CI/CD Pipelines — GitHub Actions, Jenkins

**40+ real security checks** mapped to industry frameworks:
- CIS Kubernetes Benchmark 1.8
- AWS Well-Architected Framework (Security, Reliability, Cost)
- Docker CIS Benchmark
- CI/CD Security Best Practices

## Features

- GitHub repo scanning via Personal Access Token
- Manual code paste analysis
- Risk scoring (0-100) with severity breakdown
- Compliance framework mapping
- Scan history with trend charts
- JSON report export
- Dark theme dashboard with Chart.js visualizations

## Quick Start

### Prerequisites
- Python 3.12+
- Git (for repo scanning)

### Local Development

```bash
# Clone the repository
cd deploypilot-ai

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt

# Copy environment file
cp .env.example .env

# Run the application
python app.py
```

Visit http://localhost:5000

### Docker Deployment

```bash
# Build and run with Docker Compose
docker compose up --build -d

# View logs
docker compose logs -f web
```

## Production Deployment

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SECRET_KEY` | Flask secret key for sessions | (required) |
| `DATABASE_URL` | Database connection string | `sqlite:///infraaudit.db` |
| `GITHUB_TOKEN` | Default GitHub PAT (optional) | None |

### With PostgreSQL (Production)

```bash
export DATABASE_URL=postgresql://user:pass@host:5432/infraaudit
export SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
gunicorn --bind 0.0.0.0:5000 --workers 3 --timeout 120 app:app
```

## Tech Stack

- **Backend:** Python 3.12, Flask 3.0, SQLAlchemy
- **Auth:** Flask-Login + bcrypt
- **Database:** SQLite (dev) / PostgreSQL (prod)
- **Frontend:** Tailwind CSS, Chart.js, Bootstrap Icons
- **Deployment:** Docker, Gunicorn

## Risk Score Calculation

```
Score = max(0, 100 - total_points)

Critical finding = 10 points
High finding     = 5 points
Medium finding   = 2 points
Low finding      = 1 point
```

## Contact

- **Email:** deploypilotai@gmail.com
- **Founder:** Vijaykanth Anugu

---

© 2026 DeployPilot AI · InfraAudit
