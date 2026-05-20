# DeployPilot AI

**AI-Powered DevOps Assistant** — Analyze Kubernetes YAML, Terraform, Dockerfiles, CI/CD pipelines, and logs for issues, security risks, and optimizations.

![Python](https://img.shields.io/badge/Python-3.12-blue) ![Flask](https://img.shields.io/badge/Flask-3.0-green) ![Docker](https://img.shields.io/badge/Docker-Ready-blue) ![AWS](https://img.shields.io/badge/AWS-Deployed-orange)

## Features

- **Kubernetes YAML Analysis** — Missing probes, resource limits, security contexts
- **Terraform Code Review** — Backend config, encryption, provider pinning, tagging
- **Dockerfile Scanning** — Root user, layer optimization, health checks
- **CI/CD Pipeline Audit** — Hardcoded secrets, missing caches, no tests
- **Log Analysis** — OOMKilled, CrashLoopBackOff, connection failures
- **User Authentication** — Signup/Login with bcrypt password hashing
- **Analysis History** — All past analyses stored and retrievable
- **Modern UI** — Tailwind CSS, dark mode, responsive design

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.12, Flask 3.0, SQLAlchemy |
| Database | SQLite (dev) / PostgreSQL (prod) |
| Auth | Flask-Login + bcrypt |
| Frontend | Jinja2 + Tailwind CSS (CDN) |
| Deployment | Docker, Gunicorn |
| Cloud | AWS EC2, S3, CloudFront, RDS |

## Quick Start (Local Development)

```bash
# Clone the repo
git clone https://github.com/yourusername/deploypilot-ai.git
cd deploypilot-ai

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt

# Copy environment file
cp .env.example .env

# Run the app
python app.py
```

Open http://localhost:5000 in your browser.

## Docker Deployment (Recommended)

```bash
# Build and run
docker-compose up --build -d

# Check logs
docker-compose logs -f

# Stop
docker-compose down
```

App runs at http://localhost:5000

## AWS EC2 Deployment Guide

### 1. Launch EC2 Instance
- AMI: Amazon Linux 2023 or Ubuntu 22.04
- Instance type: t3.small (2 vCPU, 2GB RAM)
- Security Group: Allow ports 22 (SSH), 80 (HTTP), 443 (HTTPS)
- Storage: 20GB gp3

### 2. SSH into instance and install Docker
```bash
# Amazon Linux 2023
sudo yum update -y
sudo yum install -y docker git
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker ec2-user

# Install docker-compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

### 3. Deploy the app
```bash
git clone https://github.com/yourusername/deploypilot-ai.git
cd deploypilot-ai
cp .env.example .env
# Edit .env with a strong SECRET_KEY

docker-compose up --build -d
```

### 4. Set up Nginx reverse proxy (optional, for domain)
```bash
sudo yum install -y nginx
# Configure nginx to proxy port 80 → localhost:5000
sudo systemctl start nginx
```

### 5. Point your domain
- Create an A record pointing deploypilot.automationvijay.site → EC2 public IP
- Install certbot for free SSL: `sudo certbot --nginx`

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| SECRET_KEY | Flask session secret | dev-secret-key |
| DATABASE_URL | Database connection string | sqlite:///deploypilot.db |
| OPENAI_API_KEY | OpenAI API key (optional, for real AI) | None |
| FLASK_ENV | production or development | production |

## Project Structure

```
deploypilot-ai/
├── app.py              # Flask app (routes, models, AI engine)
├── templates/
│   ├── base.html       # Base layout (nav, footer)
│   ├── index.html      # Landing page
│   ├── auth.html       # Login / Register
│   ├── dashboard.html  # Main analysis dashboard
│   ├── pricing.html    # Pricing page
│   └── about.html      # About page
├── static/             # Static assets
├── Dockerfile          # Container build
├── docker-compose.yml  # Local orchestration
├── requirements.txt    # Python dependencies
├── .env.example        # Environment template
└── README.md           # This file
```

---

## AWS Activate Credits Application Guide

### What is AWS Activate?
AWS Activate provides startups with free AWS credits ($1,000 to $100,000) to build on AWS.

### How to Apply (Founders Tier — $1,000 credits)

1. **Go to**: https://aws.amazon.com/activate/
2. **Click**: "Apply for AWS Activate"
3. **Select**: Founders tier (self-funded startups)

### What to Fill in the Application:

**Company Name:** DeployPilot AI (or your registered business name)

**Website:** deploypilot.automationvijay.site (your deployed URL)

**Describe your startup:**
> DeployPilot AI is a cloud-native SaaS platform that helps DevOps engineers analyze infrastructure-as-code (Kubernetes YAML, Terraform, Dockerfiles, CI/CD pipelines) for security issues, misconfigurations, and optimization opportunities using AI. The platform is built entirely on AWS — EC2 for compute, RDS for data persistence, S3 for asset storage, CloudFront for delivery, and we plan to integrate AWS Bedrock for AI analysis at scale.

**How will you use AWS credits:**
> We will use credits for: (1) EC2/ECS compute for our application servers, (2) RDS PostgreSQL for production database, (3) S3 for user file storage, (4) CloudFront CDN for global delivery, (5) AWS Bedrock/SageMaker for AI model inference, (6) CloudWatch for monitoring and observability. We are currently in Beta with 50+ users and need credits to scale infrastructure as we onboard our first 500 paying customers.

**Stage:** Pre-seed / Bootstrapped

**Funding:** Self-funded

### Tips for Approval:
- ✅ Have the product DEPLOYED on AWS before applying (even on a t3.micro)
- ✅ Have real users signed up (even 5-10 is fine)
- ✅ Show AWS services in use (EC2, S3, RDS — even basic usage)
- ✅ Register a business (Udyam/MSME registration is free and instant in India)
- ✅ Use a professional email (not gmail — use your domain email if possible)
- ✅ Mention specific AWS services you plan to use with the credits
- ✅ Mention AI/ML (AWS loves Bedrock/SageMaker usage)

### For Higher Credits ($5,000–$25,000):
Apply through an AWS Activate Portfolio partner:
- Join an accelerator (T-Hub Hyderabad, NASSCOM 10K Startups)
- Apply through AWS Startup Loft
- Get accepted into AWS EdStart (education technology program — perfect for DeployPilot)

---

## Roadmap

- [x] MVP with mock AI analysis
- [x] User authentication
- [x] Analysis history
- [x] Docker deployment
- [ ] OpenAI/Bedrock integration for real AI analysis
- [ ] PDF report export
- [ ] REST API for CI/CD integration
- [ ] GitHub App (analyze on PR)
- [ ] Team workspaces
- [ ] Slack/Discord notifications

---

## License

MIT License — © 2026 DeployPilot AI Inc.

## Contact

- **Founder:** Vijaykanth Anugu
- **Email:** deploypilotai@gmail.com
- **Location:** Hyderabad, India
