# DeployPilot AI — Infrastructure Security Scanner

AI-Powered Infrastructure Security & Compliance Scanner for DevOps Teams.

**Live:** https://deploypilotai.automationvijay.site

## What It Does

DeployPilot AI scans your infrastructure-as-code files for security misconfigurations, compliance violations, and best practice deviations — with automated fix suggestions.

**Supported file types:**
- Kubernetes YAML (Deployments, Services, RBAC, NetworkPolicies)
- Terraform (.tf) — AWS resources, state management, provider config
- AWS CloudFormation (JSON/YAML)
- Azure ARM Templates (JSON)
- GCP Deployment Manager (YAML)
- Dockerfiles — Image security, build best practices
- CI/CD Pipelines — GitHub Actions, Jenkins, GitLab CI

**100+ security checks** mapped to industry frameworks:
- CIS Kubernetes Benchmark 1.8
- AWS Well-Architected Framework
- Azure Security Benchmark
- GCP Security Best Practices
- Docker CIS Benchmark
- CI/CD Security Best Practices

## Features

- Multi-provider repo scanning (GitHub, GitLab, Bitbucket, Azure DevOps)
- Manual code paste analysis with full syntax validation
- Risk scoring (0-100) with severity breakdown
- Compliance framework mapping
- Suggested fix code snippets for every finding
- `# deploypilot-ignore` comment support
- PDF report export
- 7-day Pro trial on signup
- Razorpay payment integration
- Google & GitHub OAuth login
- Admin dashboard with user/review management
- Newsletter subscription
- User review system with admin approval

## Tech Stack

- **Backend:** Python 3.12, Flask 3.0, SQLAlchemy, PyYAML, python-hcl2
- **Auth:** Flask-Login + bcrypt + Google OAuth + GitHub OAuth
- **Database:** SQLite
- **Frontend:** Tailwind CSS, Chart.js, Bootstrap Icons
- **Deployment:** Docker, Gunicorn, Nginx, Certbot SSL
- **Infrastructure:** AWS EC2, Elastic IP, Route 53

---

## Local Development

### Prerequisites
- Python 3.12+
- Git

### Setup

```bash
# Clone
git clone https://github.com/vijaykanth1729/DeployPilotAI.git
cd DeployPilotAI/deploypilot-ai

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt

# Create .env file
cp .env.example .env
# Edit .env with your values

# Run
python app.py
```

Visit http://localhost:5000

### Docker (Local)

```bash
cd deploypilot-ai
cp .env.example .env
# Edit .env with your values
docker compose up --build -d
```

---

## Production Deployment (AWS EC2)

### First-Time Setup

**1. Launch EC2 instance (Amazon Linux 2 / Ubuntu)**

```bash
# Install Docker
sudo yum install -y docker git
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker $USER

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

**2. Clone the repo**

```bash
cd /root
git clone https://github.com/vijaykanth1729/DeployPilotAI.git
cd DeployPilotAI/deploypilot-ai
```

**3. Create `.env` file on EC2 (secrets stay on server, never in git)**

```bash
cat > .env << 'EOF'
SECRET_KEY=your-random-secret-key-here
FLASK_ENV=production
DATABASE_URL=sqlite:///infraaudit.db
ADMIN_EMAIL=deploypilotai@gmail.com
SMTP_USER=deploypilotai@gmail.com
SMTP_PASS=your-gmail-app-password
RAZORPAY_KEY_ID=your-razorpay-key
RAZORPAY_KEY_SECRET=your-razorpay-secret
GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=https://yourdomain.com/auth/google/callback
GITHUB_OAUTH_CLIENT_ID=your-github-client-id
GITHUB_OAUTH_CLIENT_SECRET=your-github-client-secret
GITHUB_OAUTH_REDIRECT_URI=https://yourdomain.com/auth/github/callback
EOF
```

**4. Build and run**

```bash
docker compose up -d --build
```

**5. Setup Nginx + SSL (one-time)**

```bash
sudo yum install -y nginx
sudo certbot --nginx -d yourdomain.com
```

Nginx config (`/etc/nginx/conf.d/deploypilot.conf`):
```nginx
server {
    listen 443 ssl;
    server_name deploypilotai.automationvijay.site;

    ssl_certificate /etc/letsencrypt/live/deploypilotai.automationvijay.site/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/deploypilotai.automationvijay.site/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 120s;
    }
}

server {
    listen 80;
    server_name deploypilotai.automationvijay.site;
    return 301 https://$host$request_uri;
}
```

---

### Deploying Updates

Every time you push code changes:

```bash
cd /root/DeployPilotAI
git pull origin main
cd deploypilot-ai
docker compose down
docker compose up -d --build
```

That's it — 4 commands. The `.env` file persists on EC2.

### Useful Commands

```bash
# View logs
docker compose logs -f

# Restart without rebuilding
docker compose restart

# Stop the app
docker compose down

# Check status
docker compose ps

# Enter container shell
docker compose exec web bash

# Backup database
docker compose cp web:/app/instance/infraaudit.db ./backup.db
```

---

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `SECRET_KEY` | Flask session secret | Yes |
| `FLASK_ENV` | `production` or `development` | Yes |
| `DATABASE_URL` | DB connection string | No (defaults to SQLite) |
| `ADMIN_EMAIL` | Admin user email | Yes |
| `SMTP_USER` | Gmail address for sending emails | Yes |
| `SMTP_PASS` | Gmail app password | Yes |
| `RAZORPAY_KEY_ID` | Razorpay API key | Yes |
| `RAZORPAY_KEY_SECRET` | Razorpay secret | Yes |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID | Yes |
| `GOOGLE_CLIENT_SECRET` | Google OAuth secret | Yes |
| `GOOGLE_REDIRECT_URI` | Google OAuth callback URL | Yes |
| `GITHUB_OAUTH_CLIENT_ID` | GitHub OAuth client ID | Yes |
| `GITHUB_OAUTH_CLIENT_SECRET` | GitHub OAuth secret | Yes |
| `GITHUB_OAUTH_REDIRECT_URI` | GitHub OAuth callback URL | Yes |

---

## Risk Score Calculation

```
Score = max(0, 100 - total_points)

Critical finding = 10 points
High finding     = 5 points
Medium finding   = 2 points
Low finding      = 1 point
```

## Pricing

| Plan | Price | Limits |
|------|-------|--------|
| Free | ₹0 | 2 projects, 5 scans/month, paste only |
| Pro | ₹999/mo | 50 projects, unlimited scans, repo scanning, PDF export |
| Team | ₹4,999/mo | 200 projects, unlimited everything |

All new signups get a 7-day Pro trial.

---

## Contact

- **Website:** https://deploypilotai.automationvijay.site
- **Email:** deploypilotai@gmail.com
- **Founder:** Vijaykanth Anugu
- **LinkedIn:** https://linkedin.com/in/vijaykanth-devops
- **GitHub:** https://github.com/vijaykanth1729

---

© 2026 DeployPilot AI
