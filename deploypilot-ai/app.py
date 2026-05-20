import os
import json
import re
from datetime import datetime
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import bcrypt
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-prod')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///deploypilot.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB max upload

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ─── MODELS ───────────────────────────────────────────────────────────────────

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(80), nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    analyses = db.relationship('Analysis', backref='user', lazy=True)

class Analysis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    file_type = db.Column(db.String(30), nullable=False)
    input_code = db.Column(db.Text, nullable=False)
    result = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ─── AI ANALYSIS ENGINE (Mock + Real) ─────────────────────────────────────────

def analyze_code(code, file_type):
    """Analyze code and return structured findings. Uses mock AI for MVP."""
    findings = []

    if file_type == 'kubernetes':
        findings = analyze_kubernetes(code)
    elif file_type == 'terraform':
        findings = analyze_terraform(code)
    elif file_type == 'dockerfile':
        findings = analyze_dockerfile(code)
    elif file_type == 'cicd':
        findings = analyze_cicd(code)
    elif file_type == 'logs':
        findings = analyze_logs(code)
    else:
        findings = [{"severity": "info", "title": "Unknown file type", "description": "Could not determine file type. Please select the correct type.", "recommendation": "Choose the appropriate file type from the dropdown."}]

    if not findings:
        findings = [{"severity": "success", "title": "No issues detected", "description": "Your configuration looks good! No critical issues found.", "recommendation": "Continue following best practices."}]

    return findings


def analyze_kubernetes(code):
    findings = []
    if 'resources' not in code:
        findings.append({"severity": "high", "title": "Missing Resource Limits", "description": "No CPU/memory resource requests or limits defined. This can lead to resource contention and OOM kills in production.", "recommendation": "Add resources.requests and resources.limits to all containers. Example: cpu: 100m, memory: 128Mi"})
    if 'livenessProbe' not in code and 'readinessProbe' not in code:
        findings.append({"severity": "high", "title": "Missing Health Probes", "description": "No liveness or readiness probes configured. Kubernetes cannot detect unhealthy pods or route traffic correctly.", "recommendation": "Add livenessProbe and readinessProbe with appropriate httpGet or tcpSocket checks."})
    if 'latest' in code:
        findings.append({"severity": "medium", "title": "Using :latest Tag", "description": "Image tag ':latest' is mutable and non-deterministic. Deployments may pull different images on different nodes.", "recommendation": "Use immutable tags like semantic versions (v1.2.3) or SHA digests for reproducible deployments."})
    if 'securityContext' not in code:
        findings.append({"severity": "medium", "title": "Missing Security Context", "description": "No securityContext defined. Containers may run as root, increasing attack surface.", "recommendation": "Add securityContext with runAsNonRoot: true, readOnlyRootFilesystem: true, and drop ALL capabilities."})
    if 'namespace' not in code:
        findings.append({"severity": "low", "title": "No Namespace Specified", "description": "Resources will deploy to the 'default' namespace. This makes multi-tenant management difficult.", "recommendation": "Always specify a namespace explicitly in metadata or use kubectl -n flag."})
    if 'replicas' in code:
        match = re.search(r'replicas:\s*(\d+)', code)
        if match and int(match.group(1)) < 2:
            findings.append({"severity": "medium", "title": "Single Replica Deployment", "description": "Only 1 replica configured. No high availability — a single pod failure causes downtime.", "recommendation": "Set replicas to at least 2 for production workloads. Consider HPA for auto-scaling."})
    return findings


def analyze_terraform(code):
    findings = []
    if 'backend' not in code:
        findings.append({"severity": "high", "title": "No Remote Backend Configured", "description": "Terraform state is stored locally. This prevents team collaboration and risks state loss.", "recommendation": "Configure an S3 backend with DynamoDB locking: backend \"s3\" { bucket, key, region, dynamodb_table }"})
    if 'encrypt' not in code and 's3' in code:
        findings.append({"severity": "high", "title": "S3 Bucket Not Encrypted", "description": "S3 bucket resource found without server-side encryption. Data at rest is unprotected.", "recommendation": "Add server_side_encryption_configuration with AES256 or aws:kms algorithm."})
    if 'versioning' not in code and 'aws_s3_bucket' in code:
        findings.append({"severity": "medium", "title": "S3 Versioning Disabled", "description": "Bucket versioning not enabled. Accidental deletions or overwrites cannot be recovered.", "recommendation": "Enable versioning: versioning { enabled = true }"})
    if 'tags' not in code:
        findings.append({"severity": "low", "title": "Missing Resource Tags", "description": "No tags defined on resources. This makes cost allocation and resource tracking difficult.", "recommendation": "Add tags block with at minimum: Environment, Project, Owner, ManagedBy=terraform"})
    if 'variable' in code and 'default' in code:
        findings.append({"severity": "info", "title": "Variables Have Defaults", "description": "Some variables have default values. Ensure sensitive values like passwords don't have defaults.", "recommendation": "Remove defaults from sensitive variables and use terraform.tfvars or environment variables."})
    if 'provider' in code and 'version' not in code and 'required_providers' not in code:
        findings.append({"severity": "medium", "title": "Provider Version Not Pinned", "description": "Provider version not constrained. Terraform may download breaking changes on next init.", "recommendation": "Pin provider versions in required_providers block: version = \"~> 5.0\""})
    return findings


def analyze_dockerfile(code):
    findings = []
    if 'FROM' in code and 'latest' in code:
        findings.append({"severity": "high", "title": "Using :latest Base Image", "description": "Base image uses :latest tag. Builds are non-reproducible and may break unexpectedly.", "recommendation": "Pin to a specific version: FROM node:20-alpine or FROM python:3.12-slim"})
    if 'ROOT' in code.upper() or ('USER' not in code and 'FROM' in code):
        findings.append({"severity": "high", "title": "Running as Root", "description": "Container runs as root user. If compromised, attacker has full container access.", "recommendation": "Add USER directive: RUN adduser -D appuser && USER appuser"})
    if 'COPY . .' in code or 'ADD . .' in code:
        findings.append({"severity": "medium", "title": "Copying Entire Context", "description": "COPY . . includes unnecessary files (node_modules, .git, secrets). Increases image size and attack surface.", "recommendation": "Use .dockerignore file and copy only needed files. Use multi-stage builds."})
    if code.count('RUN') > 5:
        findings.append({"severity": "medium", "title": "Too Many RUN Layers", "description": f"Found {code.count('RUN')} RUN instructions. Each creates a layer, increasing image size.", "recommendation": "Chain commands with && in a single RUN instruction to reduce layers."})
    if 'HEALTHCHECK' not in code:
        findings.append({"severity": "low", "title": "No HEALTHCHECK Defined", "description": "Docker cannot determine if the application inside the container is healthy.", "recommendation": "Add HEALTHCHECK --interval=30s CMD curl -f http://localhost:PORT/health || exit 1"})
    if 'multi-stage' not in code.lower() and code.count('FROM') < 2:
        findings.append({"severity": "info", "title": "Consider Multi-Stage Build", "description": "Single-stage build detected. Build tools and dependencies remain in the final image.", "recommendation": "Use multi-stage builds: separate build stage from runtime stage to reduce final image size by 60-80%."})
    return findings


def analyze_cicd(code):
    findings = []
    if 'secrets' not in code.lower() and ('password' in code.lower() or 'token' in code.lower() or 'key' in code.lower()):
        findings.append({"severity": "critical", "title": "Hardcoded Secrets Detected", "description": "Potential secrets (passwords, tokens, keys) found in pipeline code. These will be exposed in logs and version control.", "recommendation": "Use GitHub Secrets, AWS Secrets Manager, or HashiCorp Vault. Reference via ${{ secrets.MY_SECRET }}"})
    if 'cache' not in code.lower():
        findings.append({"severity": "medium", "title": "No Caching Configured", "description": "Pipeline doesn't use dependency caching. Every run downloads all dependencies from scratch.", "recommendation": "Add cache step for node_modules, pip cache, or Docker layer caching to reduce build time by 40-60%."})
    if 'timeout' not in code.lower():
        findings.append({"severity": "low", "title": "No Timeout Set", "description": "No job timeout configured. Hung jobs will consume runner minutes indefinitely.", "recommendation": "Add timeout-minutes: 15 (or appropriate value) to prevent runaway jobs."})
    if 'test' not in code.lower() and 'lint' not in code.lower():
        findings.append({"severity": "high", "title": "No Testing Step", "description": "Pipeline has no test or lint step. Code ships to production without quality gates.", "recommendation": "Add lint and test steps before build/deploy. Fail the pipeline on test failures."})
    if 'main' in code or 'master' in code:
        if 'pull_request' not in code:
            findings.append({"severity": "medium", "title": "No PR Trigger", "description": "Pipeline only triggers on push to main. PRs don't get validated before merge.", "recommendation": "Add pull_request trigger to validate changes before they reach the main branch."})
    return findings


def analyze_logs(code):
    findings = []
    if 'OOMKilled' in code:
        findings.append({"severity": "critical", "title": "OOMKilled Events Detected", "description": "Pods are being killed due to memory exhaustion. Application is exceeding memory limits.", "recommendation": "Increase memory limits, fix memory leaks, or optimize application memory usage. Check for unbounded caches or connection pools."})
    if 'CrashLoopBackOff' in code:
        findings.append({"severity": "critical", "title": "CrashLoopBackOff Detected", "description": "Pod is repeatedly crashing and restarting. The application fails to start or crashes immediately after starting.", "recommendation": "Check application logs with kubectl logs <pod>. Common causes: missing env vars, failed DB connections, port conflicts."})
    if 'ImagePullBackOff' in code:
        findings.append({"severity": "high", "title": "Image Pull Failure", "description": "Kubernetes cannot pull the container image. The image doesn't exist or credentials are wrong.", "recommendation": "Verify image name/tag exists in registry. Check imagePullSecrets if using private registry. Ensure ECR login is configured."})
    if 'connection refused' in code.lower() or 'connection timed out' in code.lower():
        findings.append({"severity": "high", "title": "Connection Failures", "description": "Services are failing to connect to dependencies. Network policies, DNS, or target services may be down.", "recommendation": "Check target service health, verify NetworkPolicies allow traffic, confirm DNS resolution with nslookup."})
    if 'error' in code.lower() or 'exception' in code.lower():
        error_count = code.lower().count('error') + code.lower().count('exception')
        findings.append({"severity": "medium", "title": f"Multiple Errors Detected ({error_count})", "description": f"Found {error_count} error/exception occurrences in logs. Investigate root causes.", "recommendation": "Correlate timestamps with deployments. Check if errors started after a specific release. Set up alerting on error rate spikes."})
    if not findings:
        findings.append({"severity": "success", "title": "Logs Look Healthy", "description": "No critical patterns detected in the provided logs.", "recommendation": "Continue monitoring. Set up Prometheus alerts for error rate > 1% and latency p99 > 500ms."})
    return findings

# ─── ROUTES ───────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        if not name or not email or not password:
            flash('All fields are required.', 'error')
            return redirect(url_for('register'))
        if len(password) < 6:
            flash('Password must be at least 6 characters.', 'error')
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash('Email already registered. Please login.', 'error')
            return redirect(url_for('login'))
        pw_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        user = User(name=name, email=email, password_hash=pw_hash)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for('dashboard'))
    return render_template('auth.html', mode='register')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid email or password.', 'error')
        return redirect(url_for('login'))
    return render_template('auth.html', mode='login')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    analyses = Analysis.query.filter_by(user_id=current_user.id).order_by(Analysis.created_at.desc()).limit(20).all()
    return render_template('dashboard.html', analyses=analyses)

@app.route('/analyze', methods=['POST'])
@login_required
def analyze():
    code = request.form.get('code', '').strip()
    file_type = request.form.get('file_type', 'kubernetes')
    if not code:
        return jsonify({'error': 'No code provided'}), 400
    if len(code) > 50000:
        return jsonify({'error': 'Input too large. Max 50KB.'}), 400
    findings = analyze_code(code, file_type)
    result_json = json.dumps(findings)
    analysis = Analysis(user_id=current_user.id, file_type=file_type, input_code=code[:5000], result=result_json)
    db.session.add(analysis)
    db.session.commit()
    return jsonify({'findings': findings, 'id': analysis.id})

@app.route('/analysis/<int:analysis_id>')
@login_required
def view_analysis(analysis_id):
    analysis = Analysis.query.filter_by(id=analysis_id, user_id=current_user.id).first_or_404()
    return jsonify({'findings': json.loads(analysis.result), 'file_type': analysis.file_type, 'created_at': analysis.created_at.isoformat()})

@app.route('/pricing')
def pricing():
    return render_template('pricing.html')

@app.route('/about')
def about():
    return render_template('about.html')

# ─── INIT DB ──────────────────────────────────────────────────────────────────

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=os.getenv('FLASK_ENV') != 'production')
