import os
import re
import uuid
import json
import shutil
import subprocess
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone, timedelta
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, jsonify, session, abort
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
import bcrypt
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'infraaudit-dev-secret-key-change-in-prod')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///infraaudit.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# ============================================================
# MODELS
# ============================================================

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    name = db.Column(db.String(255), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    github_token = db.Column(db.String(500), nullable=True)
    plan = db.Column(db.String(20), default='free')  # free, pro, team
    plan_expires_at = db.Column(db.DateTime, nullable=True)
    reset_token = db.Column(db.String(100), nullable=True)
    reset_token_expires = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    projects = db.relationship('Project', backref='owner', lazy=True, cascade='all, delete-orphan')
    payments = db.relationship('Payment', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

    def get_plan_limit(self, key):
        # Check if trial/plan has expired
        if self.plan != 'free' and self.plan_expires_at:
            if self.plan_expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
                # Plan expired — treat as free
                return PLAN_LIMITS.get('free', {}).get(key, 0)
        return PLAN_LIMITS.get(self.plan, PLAN_LIMITS['free']).get(key, 0)

    def can_create_project(self):
        current_count = Project.query.filter_by(user_id=self.id).count()
        return current_count < self.get_plan_limit('projects')

    def is_plan_active(self):
        """Check if paid plan/trial is still active."""
        if self.plan == 'free':
            return False
        if not self.plan_expires_at:
            return True
        return self.plan_expires_at.replace(tzinfo=timezone.utc) >= datetime.now(timezone.utc)

    def days_left_in_trial(self):
        """Return days left in trial/plan, or 0 if expired."""
        if not self.plan_expires_at:
            return 0
        delta = self.plan_expires_at.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)
        return max(0, delta.days)

    def generate_reset_token(self):
        from datetime import timedelta
        self.reset_token = uuid.uuid4().hex
        self.reset_token_expires = datetime.now(timezone.utc) + timedelta(hours=1)
        return self.reset_token


class Payment(db.Model):
    __tablename__ = 'payments'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    razorpay_order_id = db.Column(db.String(100), nullable=True)
    razorpay_payment_id = db.Column(db.String(100), nullable=True)
    razorpay_signature = db.Column(db.String(255), nullable=True)
    amount = db.Column(db.Integer, nullable=False)  # in paise
    plan = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, completed, failed
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class Project(db.Model):
    __tablename__ = 'projects'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    repo_url = db.Column(db.String(500), nullable=True)
    last_scan_at = db.Column(db.DateTime, nullable=True)
    risk_score = db.Column(db.Integer, default=100)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    scans = db.relationship('Scan', backref='project', lazy=True, cascade='all, delete-orphan')


class Scan(db.Model):
    __tablename__ = 'scans'
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False)
    status = db.Column(db.String(50), default='completed')
    risk_score = db.Column(db.Integer, default=100)
    findings_count = db.Column(db.Integer, default=0)
    critical_count = db.Column(db.Integer, default=0)
    high_count = db.Column(db.Integer, default=0)
    medium_count = db.Column(db.Integer, default=0)
    low_count = db.Column(db.Integer, default=0)
    info_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    findings = db.relationship('Finding', backref='scan', lazy=True, cascade='all, delete-orphan')


class Finding(db.Model):
    __tablename__ = 'findings'
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    title = db.Column(db.String(500), nullable=False)
    description = db.Column(db.Text, nullable=False)
    recommendation = db.Column(db.Text, nullable=False)
    file_path = db.Column(db.String(500), nullable=True)
    line_number = db.Column(db.Integer, nullable=True)
    framework = db.Column(db.String(50), nullable=True)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Plan limits
PLAN_LIMITS = {
    'free': {'projects': 2, 'scans_per_month': 5},
    'pro': {'projects': 50, 'scans_per_month': 9999},
    'team': {'projects': 200, 'scans_per_month': 9999},
}

PLAN_PRICES = {
    'pro_monthly': {'amount': 99900, 'label': 'Pro Monthly', 'razorpay_amount': 99900},  # ₹999 in paise
    'pro_yearly': {'amount': 799900, 'label': 'Pro Yearly', 'razorpay_amount': 799900},  # ₹7,999 in paise
    'team_monthly': {'amount': 499900, 'label': 'Team Monthly', 'razorpay_amount': 499900},  # ₹4,999 in paise
}

RAZORPAY_KEY_ID = os.getenv('RAZORPAY_KEY_ID', 'rzp_test_XXXXXXXXXXXXXX')
RAZORPAY_KEY_SECRET = os.getenv('RAZORPAY_KEY_SECRET', '')

# Email config (Gmail SMTP or AWS SES)
SMTP_HOST = os.getenv('SMTP_HOST', 'smtp.gmail.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', '587'))
SMTP_USER = os.getenv('SMTP_USER', '')  # your email
SMTP_PASS = os.getenv('SMTP_PASS', '')  # app password (not regular password)
SMTP_FROM = os.getenv('SMTP_FROM', 'DeployPilot AI <deploypilotai@gmail.com>')

# Admin config
ADMIN_EMAIL = os.getenv('ADMIN_EMAIL', 'deploypilotai@gmail.com')


def send_email(to_email, subject, html_body):
    """Send email via SMTP. Returns True on success, False on failure."""
    if not SMTP_USER or not SMTP_PASS:
        app.logger.warning(f'Email not configured. Would send to {to_email}: {subject}')
        return False
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = SMTP_FROM
        msg['To'] = to_email
        msg.attach(MIMEText(html_body, 'html'))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, to_email, msg.as_string())
        return True
    except Exception as e:
        app.logger.error(f'Failed to send email to {to_email}: {e}')
        return False


@app.context_processor
def inject_config():
    """Make config available in all templates."""
    return {'config': {'ADMIN_EMAIL': ADMIN_EMAIL}}


@app.template_filter('ist')
def to_ist(dt):
    """Convert UTC datetime to IST (UTC+5:30) for display."""
    if dt is None:
        return ''
    ist_offset = timedelta(hours=5, minutes=30)
    ist_time = dt + ist_offset
    return ist_time


# ============================================================
# ANALYSIS ENGINE
# ============================================================

def analyze_kubernetes(content, file_path='unknown'):
    """Analyze Kubernetes YAML files for security issues."""
    findings = []
    lines = content.split('\n')

    # Check 1: Missing resource limits
    has_resources = bool(re.search(r'resources:\s*\n\s+(limits|requests):', content))
    if 'containers:' in content or 'container:' in content:
        if not has_resources:
            line_num = next((i+1 for i, l in enumerate(lines) if 'containers:' in l or 'container:' in l), 1)
            findings.append({
                'severity': 'high',
                'category': 'reliability',
                'title': 'Missing Resource Limits',
                'description': 'Container does not define CPU/memory resource limits. This can lead to resource exhaustion and noisy neighbor issues.',
                'recommendation': 'Add resources.limits and resources.requests with appropriate CPU and memory values.',
                'file_path': file_path,
                'line_number': line_num,
                'framework': 'CIS-K8S-1.8'
            })

    # Check 2: Missing liveness/readiness probes
    if 'containers:' in content:
        if not re.search(r'livenessProbe:', content):
            line_num = next((i+1 for i, l in enumerate(lines) if 'containers:' in l), 1)
            findings.append({
                'severity': 'medium',
                'category': 'reliability',
                'title': 'Missing Liveness Probe',
                'description': 'No liveness probe configured. Kubernetes cannot detect if the application is in a broken state.',
                'recommendation': 'Add a livenessProbe with appropriate httpGet, tcpSocket, or exec check.',
                'file_path': file_path,
                'line_number': line_num,
                'framework': 'CIS-K8S-1.8'
            })
        if not re.search(r'readinessProbe:', content):
            line_num = next((i+1 for i, l in enumerate(lines) if 'containers:' in l), 1)
            findings.append({
                'severity': 'medium',
                'category': 'reliability',
                'title': 'Missing Readiness Probe',
                'description': 'No readiness probe configured. Traffic may be sent to pods that are not ready to serve.',
                'recommendation': 'Add a readinessProbe to ensure traffic is only routed to healthy pods.',
                'file_path': file_path,
                'line_number': line_num,
                'framework': 'CIS-K8S-1.8'
            })

    # Check 3: Security context - runAsNonRoot
    if 'containers:' in content:
        if not re.search(r'runAsNonRoot:\s*true', content):
            line_num = next((i+1 for i, l in enumerate(lines) if 'containers:' in l), 1)
            findings.append({
                'severity': 'critical',
                'category': 'security',
                'title': 'Container Running as Root',
                'description': 'securityContext.runAsNonRoot is not set to true. Containers running as root pose a significant security risk.',
                'recommendation': 'Add securityContext.runAsNonRoot: true to the pod or container spec.',
                'file_path': file_path,
                'line_number': line_num,
                'framework': 'CIS-K8S-1.8'
            })

    # Check 4: Privileged container
    if re.search(r'privileged:\s*true', content):
        line_num = next((i+1 for i, l in enumerate(lines) if 'privileged:' in l and 'true' in l), 1)
        findings.append({
            'severity': 'critical',
            'category': 'security',
            'title': 'Privileged Container Detected',
            'description': 'Container is running in privileged mode, granting full access to the host system.',
            'recommendation': 'Remove privileged: true unless absolutely necessary. Use specific capabilities instead.',
            'file_path': file_path,
            'line_number': line_num,
            'framework': 'CIS-K8S-1.8'
        })

    # Check 5: Using latest tag
    latest_matches = re.finditer(r'image:\s*\S+:latest', content)
    for match in latest_matches:
        line_num = content[:match.start()].count('\n') + 1
        findings.append({
            'severity': 'medium',
            'category': 'reliability',
            'title': 'Using :latest Image Tag',
            'description': 'Image uses :latest tag which is mutable and can lead to unexpected deployments.',
            'recommendation': 'Pin images to specific versions or SHA digests for reproducible deployments.',
            'file_path': file_path,
            'line_number': line_num,
            'framework': 'CIS-K8S-1.8'
        })

    # Check 6: No image tag at all
    no_tag_matches = re.finditer(r'image:\s*([^\s:]+)\s*$', content, re.MULTILINE)
    for match in no_tag_matches:
        if ':' not in match.group(1):
            line_num = content[:match.start()].count('\n') + 1
            findings.append({
                'severity': 'medium',
                'category': 'reliability',
                'title': 'Image Without Tag',
                'description': 'Image reference has no tag specified, defaulting to :latest.',
                'recommendation': 'Always specify an explicit image tag or SHA digest.',
                'file_path': file_path,
                'line_number': line_num,
                'framework': 'CIS-K8S-1.8'
            })

    # Check 7: Missing namespace
    if re.search(r'kind:\s*(Deployment|StatefulSet|DaemonSet|Pod|Service)', content):
        if not re.search(r'namespace:', content):
            findings.append({
                'severity': 'low',
                'category': 'best-practice',
                'title': 'No Namespace Specified',
                'description': 'Resource does not specify a namespace, will be deployed to the default namespace.',
                'recommendation': 'Specify a namespace in metadata to organize resources and apply RBAC policies.',
                'file_path': file_path,
                'line_number': 1,
                'framework': 'CIS-K8S-1.8'
            })

    # Check 8: RBAC - ClusterRoleBinding with cluster-admin
    if re.search(r'kind:\s*ClusterRoleBinding', content):
        if re.search(r'name:\s*cluster-admin', content):
            line_num = next((i+1 for i, l in enumerate(lines) if 'cluster-admin' in l), 1)
            findings.append({
                'severity': 'critical',
                'category': 'security',
                'title': 'ClusterRoleBinding to cluster-admin',
                'description': 'Binding grants cluster-admin privileges which provides unrestricted access to the cluster.',
                'recommendation': 'Use least-privilege RBAC roles. Create custom ClusterRoles with only necessary permissions.',
                'file_path': file_path,
                'line_number': line_num,
                'framework': 'CIS-K8S-1.8'
            })

    # Check 9: Missing NetworkPolicy
    if re.search(r'kind:\s*(Deployment|StatefulSet|Pod)', content):
        if not re.search(r'kind:\s*NetworkPolicy', content):
            findings.append({
                'severity': 'medium',
                'category': 'security',
                'title': 'No NetworkPolicy Defined',
                'description': 'No NetworkPolicy found. All pods can communicate freely without network segmentation.',
                'recommendation': 'Define NetworkPolicy resources to restrict pod-to-pod communication.',
                'file_path': file_path,
                'line_number': 1,
                'framework': 'CIS-K8S-1.8'
            })

    # Check 10: hostNetwork enabled
    if re.search(r'hostNetwork:\s*true', content):
        line_num = next((i+1 for i, l in enumerate(lines) if 'hostNetwork:' in l and 'true' in l), 1)
        findings.append({
            'severity': 'high',
            'category': 'security',
            'title': 'Host Network Enabled',
            'description': 'Pod uses host network namespace, bypassing network isolation.',
            'recommendation': 'Remove hostNetwork: true unless the pod specifically needs host network access.',
            'file_path': file_path,
            'line_number': line_num,
            'framework': 'CIS-K8S-1.8'
        })

    # Check 11: hostPID enabled
    if re.search(r'hostPID:\s*true', content):
        line_num = next((i+1 for i, l in enumerate(lines) if 'hostPID:' in l and 'true' in l), 1)
        findings.append({
            'severity': 'high',
            'category': 'security',
            'title': 'Host PID Namespace Shared',
            'description': 'Pod shares the host PID namespace, allowing visibility into host processes.',
            'recommendation': 'Remove hostPID: true to maintain process isolation.',
            'file_path': file_path,
            'line_number': line_num,
            'framework': 'CIS-K8S-1.8'
        })

    # Check 12: Secrets in environment variables
    env_secret_patterns = re.finditer(r'(PASSWORD|SECRET|API_KEY|TOKEN|CREDENTIALS)\s*[:=]', content, re.IGNORECASE)
    for match in env_secret_patterns:
        if not re.search(r'secretKeyRef|valueFrom', content[max(0, match.start()-100):match.start()+200]):
            line_num = content[:match.start()].count('\n') + 1
            findings.append({
                'severity': 'high',
                'category': 'security',
                'title': 'Potential Secret in Plain Text',
                'description': f'Sensitive value ({match.group(1)}) may be hardcoded instead of using Kubernetes Secrets.',
                'recommendation': 'Use Kubernetes Secrets with secretKeyRef or external secret management (Vault, AWS Secrets Manager).',
                'file_path': file_path,
                'line_number': line_num,
                'framework': 'CIS-K8S-1.8'
            })

    # Check 13: Missing PodDisruptionBudget reference
    if re.search(r'kind:\s*Deployment', content):
        if re.search(r'replicas:\s*[2-9]', content) and not re.search(r'PodDisruptionBudget', content):
            findings.append({
                'severity': 'low',
                'category': 'reliability',
                'title': 'No PodDisruptionBudget',
                'description': 'Multi-replica deployment without PodDisruptionBudget. Voluntary disruptions may take down all pods.',
                'recommendation': 'Create a PodDisruptionBudget to ensure minimum availability during disruptions.',
                'file_path': file_path,
                'line_number': 1,
                'framework': 'CIS-K8S-1.8'
            })

    # Check 14: allowPrivilegeEscalation not set to false
    if 'containers:' in content:
        if not re.search(r'allowPrivilegeEscalation:\s*false', content):
            findings.append({
                'severity': 'high',
                'category': 'security',
                'title': 'Privilege Escalation Not Disabled',
                'description': 'allowPrivilegeEscalation is not explicitly set to false, allowing potential privilege escalation.',
                'recommendation': 'Set securityContext.allowPrivilegeEscalation: false on all containers.',
                'file_path': file_path,
                'line_number': 1,
                'framework': 'CIS-K8S-1.8'
            })

    # Check 15: readOnlyRootFilesystem not set
    if 'containers:' in content:
        if not re.search(r'readOnlyRootFilesystem:\s*true', content):
            findings.append({
                'severity': 'medium',
                'category': 'security',
                'title': 'Writable Root Filesystem',
                'description': 'Root filesystem is not set to read-only, allowing potential file system modifications by attackers.',
                'recommendation': 'Set securityContext.readOnlyRootFilesystem: true and use emptyDir volumes for writable paths.',
                'file_path': file_path,
                'line_number': 1,
                'framework': 'CIS-K8S-1.8'
            })

    return findings


def analyze_terraform(content, file_path='unknown'):
    """Analyze Terraform files for security and best practice issues."""
    findings = []
    lines = content.split('\n')

    # Check 1: No remote backend
    if re.search(r'terraform\s*{', content):
        if not re.search(r'backend\s+"(s3|azurerm|gcs|remote|consul)"', content):
            findings.append({
                'severity': 'high',
                'category': 'security',
                'title': 'No Remote Backend Configured',
                'description': 'Terraform state is stored locally. This prevents team collaboration and risks state loss.',
                'recommendation': 'Configure a remote backend (S3, Azure Blob, GCS) with state locking enabled.',
                'file_path': file_path,
                'line_number': 1,
                'framework': 'AWS-WA-SEC'
            })

    # Check 2: S3 bucket without encryption
    s3_blocks = re.finditer(r'resource\s+"aws_s3_bucket"\s+"(\w+)"', content)
    for match in s3_blocks:
        bucket_name = match.group(1)
        block_start = match.start()
        # Look for encryption configuration in the next 500 chars or separate resource
        nearby = content[block_start:block_start+1000]
        if not re.search(r'server_side_encryption_configuration|aws_s3_bucket_server_side_encryption', content):
            line_num = content[:block_start].count('\n') + 1
            findings.append({
                'severity': 'high',
                'category': 'security',
                'title': f'S3 Bucket Without Encryption ({bucket_name})',
                'description': 'S3 bucket does not have server-side encryption configured.',
                'recommendation': 'Add server_side_encryption_configuration with AES256 or aws:kms algorithm.',
                'file_path': file_path,
                'line_number': line_num,
                'framework': 'AWS-WA-SEC'
            })

    # Check 3: S3 bucket without versioning
    if re.search(r'resource\s+"aws_s3_bucket"', content):
        if not re.search(r'versioning\s*{[^}]*enabled\s*=\s*true|aws_s3_bucket_versioning', content):
            line_num = next((i+1 for i, l in enumerate(lines) if 'aws_s3_bucket' in l), 1)
            findings.append({
                'severity': 'medium',
                'category': 'reliability',
                'title': 'S3 Bucket Without Versioning',
                'description': 'S3 bucket does not have versioning enabled. Data loss from accidental deletion is possible.',
                'recommendation': 'Enable versioning on S3 buckets to protect against accidental data loss.',
                'file_path': file_path,
                'line_number': line_num,
                'framework': 'AWS-WA-REL'
            })

    # Check 4: Missing tags
    resource_blocks = re.finditer(r'resource\s+"aws_\w+"\s+"(\w+)"', content)
    for match in resource_blocks:
        block_start = match.start()
        # Find the closing brace of this resource block
        brace_count = 0
        block_end = block_start
        for i in range(block_start, min(block_start+2000, len(content))):
            if content[i] == '{':
                brace_count += 1
            elif content[i] == '}':
                brace_count -= 1
                if brace_count == 0:
                    block_end = i
                    break
        block_content = content[block_start:block_end]
        if 'tags' not in block_content:
            line_num = content[:block_start].count('\n') + 1
            findings.append({
                'severity': 'low',
                'category': 'cost',
                'title': f'Resource Missing Tags ({match.group(1)})',
                'description': 'Resource does not have tags defined. Tags are essential for cost allocation and resource management.',
                'recommendation': 'Add tags including Environment, Team, Project, and ManagedBy.',
                'file_path': file_path,
                'line_number': line_num,
                'framework': 'AWS-WA-COST'
            })
        break  # Only report once to avoid noise

    # Check 5: Provider without version constraint
    if re.search(r'provider\s+"', content):
        if not re.search(r'required_providers|version\s*=', content):
            findings.append({
                'severity': 'medium',
                'category': 'reliability',
                'title': 'Provider Without Version Constraint',
                'description': 'Provider does not have a version constraint. Upgrades may introduce breaking changes.',
                'recommendation': 'Pin provider versions in required_providers block with version constraints.',
                'file_path': file_path,
                'line_number': 1,
                'framework': 'AWS-WA-REL'
            })

    # Check 6: No state locking (DynamoDB for S3 backend)
    if re.search(r'backend\s+"s3"', content):
        if not re.search(r'dynamodb_table', content):
            line_num = next((i+1 for i, l in enumerate(lines) if 'backend' in l and 's3' in l), 1)
            findings.append({
                'severity': 'high',
                'category': 'reliability',
                'title': 'S3 Backend Without State Locking',
                'description': 'S3 backend does not configure DynamoDB table for state locking. Concurrent operations may corrupt state.',
                'recommendation': 'Add dynamodb_table parameter to the S3 backend configuration.',
                'file_path': file_path,
                'line_number': line_num,
                'framework': 'AWS-WA-REL'
            })

    # Check 7: RDS without deletion protection
    if re.search(r'resource\s+"aws_db_instance"', content):
        if not re.search(r'deletion_protection\s*=\s*true', content):
            line_num = next((i+1 for i, l in enumerate(lines) if 'aws_db_instance' in l), 1)
            findings.append({
                'severity': 'high',
                'category': 'reliability',
                'title': 'RDS Without Deletion Protection',
                'description': 'RDS instance does not have deletion protection enabled. Accidental terraform destroy will delete the database.',
                'recommendation': 'Set deletion_protection = true on production RDS instances.',
                'file_path': file_path,
                'line_number': line_num,
                'framework': 'AWS-WA-REL'
            })

    # Check 8: RDS without encryption
    if re.search(r'resource\s+"aws_db_instance"', content):
        if not re.search(r'storage_encrypted\s*=\s*true', content):
            line_num = next((i+1 for i, l in enumerate(lines) if 'aws_db_instance' in l), 1)
            findings.append({
                'severity': 'high',
                'category': 'security',
                'title': 'RDS Without Encryption at Rest',
                'description': 'RDS instance does not have storage encryption enabled.',
                'recommendation': 'Set storage_encrypted = true and specify a KMS key.',
                'file_path': file_path,
                'line_number': line_num,
                'framework': 'AWS-WA-SEC'
            })

    # Check 9: Security group with 0.0.0.0/0 ingress
    if re.search(r'cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]', content):
        line_num = next((i+1 for i, l in enumerate(lines) if '0.0.0.0/0' in l), 1)
        findings.append({
            'severity': 'critical',
            'category': 'security',
            'title': 'Security Group Open to World',
            'description': 'Security group allows ingress from 0.0.0.0/0 (all IPs). This exposes the resource to the internet.',
            'recommendation': 'Restrict CIDR blocks to known IP ranges or use security group references.',
            'file_path': file_path,
            'line_number': line_num,
            'framework': 'AWS-WA-SEC'
        })

    # Check 10: Sensitive variable without sensitive flag
    sensitive_vars = re.finditer(r'variable\s+"(password|secret|token|key|credentials)\w*"', content, re.IGNORECASE)
    for match in sensitive_vars:
        var_start = match.start()
        var_block = content[var_start:var_start+300]
        if 'sensitive' not in var_block or 'sensitive = true' not in var_block.replace(' ', '').replace('=', ' = '):
            line_num = content[:var_start].count('\n') + 1
            findings.append({
                'severity': 'medium',
                'category': 'security',
                'title': f'Sensitive Variable Not Marked ({match.group(1)})',
                'description': 'Variable containing sensitive data is not marked with sensitive = true.',
                'recommendation': 'Add sensitive = true to prevent the value from being displayed in logs and output.',
                'file_path': file_path,
                'line_number': line_num,
                'framework': 'AWS-WA-SEC'
            })

    # Check 11: Hardcoded credentials
    cred_patterns = re.finditer(r'(access_key|secret_key|password|token)\s*=\s*"[^"]{8,}"', content, re.IGNORECASE)
    for match in cred_patterns:
        if 'var.' not in match.group(0) and 'data.' not in match.group(0):
            line_num = content[:match.start()].count('\n') + 1
            findings.append({
                'severity': 'critical',
                'category': 'security',
                'title': 'Hardcoded Credentials Detected',
                'description': 'Credentials appear to be hardcoded in the Terraform configuration.',
                'recommendation': 'Use variables, environment variables, or a secrets manager instead of hardcoding credentials.',
                'file_path': file_path,
                'line_number': line_num,
                'framework': 'AWS-WA-SEC'
            })

    # Check 12: CloudWatch logging not enabled
    if re.search(r'resource\s+"aws_(lb|alb|elb|cloudfront_distribution)"', content):
        if not re.search(r'access_logs|logging_config', content):
            findings.append({
                'severity': 'medium',
                'category': 'compliance',
                'title': 'Access Logging Not Enabled',
                'description': 'Load balancer or CDN does not have access logging configured.',
                'recommendation': 'Enable access logs for audit trail and security monitoring.',
                'file_path': file_path,
                'line_number': 1,
                'framework': 'AWS-WA-SEC'
            })

    return findings


def analyze_dockerfile(content, file_path='unknown'):
    """Analyze Dockerfile for security and best practice issues."""
    findings = []
    lines = content.split('\n')

    # Check 1: Using latest tag in FROM
    from_latest = re.finditer(r'^FROM\s+(\S+):latest', content, re.MULTILINE)
    for match in from_latest:
        line_num = content[:match.start()].count('\n') + 1
        findings.append({
            'severity': 'medium',
            'category': 'reliability',
            'title': 'Base Image Uses :latest Tag',
            'description': f'FROM {match.group(1)}:latest — using :latest tag makes builds non-reproducible.',
            'recommendation': 'Pin base image to a specific version tag or SHA256 digest.',
            'file_path': file_path,
            'line_number': line_num,
            'framework': 'DOCKER-CIS'
        })

    # Check 2: FROM without tag
    from_no_tag = re.finditer(r'^FROM\s+([a-zA-Z0-9_/.-]+)\s*$', content, re.MULTILINE)
    for match in from_no_tag:
        if ':' not in match.group(1) and '@' not in match.group(1):
            line_num = content[:match.start()].count('\n') + 1
            findings.append({
                'severity': 'medium',
                'category': 'reliability',
                'title': 'Base Image Without Version Tag',
                'description': f'FROM {match.group(1)} — no tag specified, defaults to :latest.',
                'recommendation': 'Specify an explicit version tag for the base image.',
                'file_path': file_path,
                'line_number': line_num,
                'framework': 'DOCKER-CIS'
            })

    # Check 3: Running as root (no USER instruction)
    if not re.search(r'^USER\s+\S+', content, re.MULTILINE):
        findings.append({
            'severity': 'high',
            'category': 'security',
            'title': 'Container Runs as Root',
            'description': 'No USER instruction found. Container will run as root by default.',
            'recommendation': 'Add USER instruction to run as a non-root user (e.g., USER 1001 or USER appuser).',
            'file_path': file_path,
            'line_number': len(lines),
            'framework': 'DOCKER-CIS'
        })

    # Check 4: Using ADD instead of COPY
    add_instructions = re.finditer(r'^ADD\s+', content, re.MULTILINE)
    for match in add_instructions:
        # ADD is okay for URLs and tar extraction
        add_line = content[match.start():content.find('\n', match.start())]
        if 'http' not in add_line and '.tar' not in add_line and '.gz' not in add_line:
            line_num = content[:match.start()].count('\n') + 1
            findings.append({
                'severity': 'low',
                'category': 'best-practice',
                'title': 'Use COPY Instead of ADD',
                'description': 'ADD has implicit tar extraction and URL fetching. COPY is more explicit and predictable.',
                'recommendation': 'Replace ADD with COPY unless you specifically need tar extraction or URL fetching.',
                'file_path': file_path,
                'line_number': line_num,
                'framework': 'DOCKER-CIS'
            })

    # Check 5: No HEALTHCHECK
    if not re.search(r'^HEALTHCHECK\s+', content, re.MULTILINE):
        findings.append({
            'severity': 'low',
            'category': 'reliability',
            'title': 'No HEALTHCHECK Instruction',
            'description': 'Dockerfile does not define a HEALTHCHECK. Container orchestrators cannot determine container health.',
            'recommendation': 'Add HEALTHCHECK instruction (e.g., HEALTHCHECK CMD curl -f http://localhost/ || exit 1).',
            'file_path': file_path,
            'line_number': len(lines),
            'framework': 'DOCKER-CIS'
        })

    # Check 6: Not using multi-stage build
    from_count = len(re.findall(r'^FROM\s+', content, re.MULTILINE))
    if from_count == 1 and ('RUN.*install' in content or 'RUN.*build' in content):
        findings.append({
            'severity': 'low',
            'category': 'performance',
            'title': 'Consider Multi-Stage Build',
            'description': 'Single-stage build with install/build steps. Multi-stage builds reduce final image size.',
            'recommendation': 'Use multi-stage builds to separate build dependencies from runtime image.',
            'file_path': file_path,
            'line_number': 1,
            'framework': 'DOCKER-CIS'
        })

    # Check 7: Secrets in build args or ENV
    secret_patterns = re.finditer(r'^(ARG|ENV)\s+(PASSWORD|SECRET|API_KEY|TOKEN|PRIVATE_KEY)\s*=', content, re.MULTILINE | re.IGNORECASE)
    for match in secret_patterns:
        line_num = content[:match.start()].count('\n') + 1
        findings.append({
            'severity': 'critical',
            'category': 'security',
            'title': 'Secret Exposed in Dockerfile',
            'description': f'{match.group(1)} contains sensitive value ({match.group(2)}). This is baked into the image layer.',
            'recommendation': 'Use Docker BuildKit secrets (--mount=type=secret) or runtime environment variables instead.',
            'file_path': file_path,
            'line_number': line_num,
            'framework': 'DOCKER-CIS'
        })

    # Check 8: COPY . . without .dockerignore consideration
    if re.search(r'^COPY\s+\.\s+\.', content, re.MULTILINE):
        line_num = next((i+1 for i, l in enumerate(lines) if re.match(r'COPY\s+\.\s+\.', l)), 1)
        findings.append({
            'severity': 'medium',
            'category': 'security',
            'title': 'Broad COPY Statement',
            'description': 'COPY . . copies entire build context including potentially sensitive files (.env, .git, etc.).',
            'recommendation': 'Use specific COPY paths or ensure .dockerignore excludes sensitive files.',
            'file_path': file_path,
            'line_number': line_num,
            'framework': 'DOCKER-CIS'
        })

    return findings


def analyze_cicd(content, file_path='unknown'):
    """Analyze CI/CD pipeline files for security issues."""
    findings = []
    lines = content.split('\n')

    # Check 1: Hardcoded secrets
    secret_patterns = re.finditer(
        r'(password|secret|token|api_key|aws_access_key|aws_secret)\s*[:=]\s*["\']([^"\']{8,})["\']',
        content, re.IGNORECASE
    )
    for match in secret_patterns:
        # Skip if it's a reference to a secret store
        context = content[max(0, match.start()-50):match.end()+50]
        if 'secrets.' not in context and '${{' not in context and 'vault' not in context.lower():
            line_num = content[:match.start()].count('\n') + 1
            findings.append({
                'severity': 'critical',
                'category': 'security',
                'title': 'Hardcoded Secret in Pipeline',
                'description': f'Potential hardcoded secret ({match.group(1)}) found in CI/CD configuration.',
                'recommendation': 'Use CI/CD secret management (GitHub Secrets, GitLab CI Variables, etc.) instead of hardcoding.',
                'file_path': file_path,
                'line_number': line_num,
                'framework': 'CICD-SEC'
            })

    # Check 2: No caching configured
    if re.search(r'(steps|jobs|stages):', content):
        if not re.search(r'(cache|actions/cache|restore_cache|save_cache)', content):
            findings.append({
                'severity': 'low',
                'category': 'performance',
                'title': 'No Caching Configured',
                'description': 'Pipeline does not use caching. Build times may be unnecessarily long.',
                'recommendation': 'Add caching for dependencies (node_modules, pip cache, Maven repository, etc.).',
                'file_path': file_path,
                'line_number': 1,
                'framework': 'CICD-SEC'
            })

    # Check 3: No timeout configured
    if re.search(r'(jobs|stages):', content):
        if not re.search(r'timeout|time_limit|timeout-minutes', content):
            findings.append({
                'severity': 'low',
                'category': 'reliability',
                'title': 'No Pipeline Timeout',
                'description': 'No timeout configured. Stuck pipelines may consume resources indefinitely.',
                'recommendation': 'Set timeout-minutes on jobs to prevent runaway builds.',
                'file_path': file_path,
                'line_number': 1,
                'framework': 'CICD-SEC'
            })

    # Check 4: No test step
    if not re.search(r'(run:.*test|pytest|jest|mocha|npm test|go test|mvn test|gradle test)', content, re.IGNORECASE):
        findings.append({
            'severity': 'medium',
            'category': 'reliability',
            'title': 'No Test Step in Pipeline',
            'description': 'Pipeline does not appear to run tests. Code may be deployed without verification.',
            'recommendation': 'Add a test step to validate code before deployment.',
            'file_path': file_path,
            'line_number': 1,
            'framework': 'CICD-SEC'
        })

    # Check 5: No PR trigger (GitHub Actions specific)
    if '.github/workflows' in file_path or 'on:' in content:
        if not re.search(r'pull_request|merge_request', content):
            findings.append({
                'severity': 'medium',
                'category': 'best-practice',
                'title': 'No Pull Request Trigger',
                'description': 'Pipeline does not trigger on pull requests. Changes may not be validated before merge.',
                'recommendation': 'Add pull_request trigger to validate changes before merging.',
                'file_path': file_path,
                'line_number': 1,
                'framework': 'CICD-SEC'
            })

    # Check 6: No artifact/image scanning
    if re.search(r'(docker.*build|docker.*push|image)', content, re.IGNORECASE):
        if not re.search(r'(trivy|snyk|grype|anchore|scan|vulnerability)', content, re.IGNORECASE):
            findings.append({
                'severity': 'high',
                'category': 'security',
                'title': 'No Container Image Scanning',
                'description': 'Pipeline builds/pushes container images without vulnerability scanning.',
                'recommendation': 'Add image scanning step using Trivy, Snyk, or Grype before pushing images.',
                'file_path': file_path,
                'line_number': 1,
                'framework': 'CICD-SEC'
            })

    # Check 7: Using third-party actions without pinning (GitHub Actions)
    unpinned_actions = re.finditer(r'uses:\s*([^@\s]+)@(master|main|v\d+)\s*$', content, re.MULTILINE)
    for match in unpinned_actions:
        line_num = content[:match.start()].count('\n') + 1
        findings.append({
            'severity': 'medium',
            'category': 'security',
            'title': 'Unpinned GitHub Action',
            'description': f'Action {match.group(1)} uses branch/tag reference instead of SHA pin.',
            'recommendation': 'Pin actions to full SHA commit hash to prevent supply chain attacks.',
            'file_path': file_path,
            'line_number': line_num,
            'framework': 'CICD-SEC'
        })

    # Check 8: No environment protection for deploy
    if re.search(r'(deploy|production|release)', content, re.IGNORECASE):
        if not re.search(r'environment:|approval|manual', content, re.IGNORECASE):
            findings.append({
                'severity': 'high',
                'category': 'security',
                'title': 'No Environment Protection for Deployment',
                'description': 'Deployment step does not use environment protection rules or manual approval.',
                'recommendation': 'Add environment protection with required reviewers for production deployments.',
                'file_path': file_path,
                'line_number': 1,
                'framework': 'CICD-SEC'
            })

    return findings


def detect_file_type(file_path, content=''):
    """Detect the type of infrastructure file."""
    path_lower = file_path.lower()
    if path_lower.endswith('.tf'):
        return 'terraform'
    elif path_lower.endswith('dockerfile') or 'dockerfile' in path_lower:
        return 'dockerfile'
    elif '.github/workflows' in path_lower or 'jenkinsfile' in path_lower.lower():
        return 'cicd'
    elif path_lower.endswith(('.yaml', '.yml')):
        # Check content to determine if it's Kubernetes or CI/CD
        if any(kw in content for kw in ['apiVersion:', 'kind: Deployment', 'kind: Service', 'kind: Pod',
                                          'kind: StatefulSet', 'kind: DaemonSet', 'kind: ConfigMap',
                                          'kind: Ingress', 'kind: NetworkPolicy', 'kind: ClusterRole']):
            return 'kubernetes'
        elif any(kw in content for kw in ['stages:', 'pipeline:', 'jobs:', 'steps:', 'on:']):
            return 'cicd'
        else:
            return 'kubernetes'  # Default YAML to kubernetes
    return None


def analyze_content(content, file_type, file_path='unknown'):
    """Route content to the appropriate analyzer."""
    if file_type == 'kubernetes':
        findings = analyze_kubernetes(content, file_path)
    elif file_type == 'terraform':
        findings = analyze_terraform(content, file_path)
    elif file_type == 'dockerfile':
        findings = analyze_dockerfile(content, file_path)
    elif file_type == 'cicd':
        findings = analyze_cicd(content, file_path)
    else:
        findings = []

    # Filter out findings on lines with ignore comments
    # Supports: # deploypilot-ignore, # deploypilot:ignore, # noqa:deploypilot
    if findings:
        lines = content.split('\n')
        ignore_lines = set()
        for i, line in enumerate(lines):
            if any(tag in line.lower() for tag in ['deploypilot-ignore', 'deploypilot:ignore', 'noqa:deploypilot']):
                ignore_lines.add(i + 1)  # 1-indexed line numbers

        if ignore_lines:
            findings = [f for f in findings if f.get('line_number') not in ignore_lines]

    return findings


def calculate_risk_score(findings):
    """Calculate risk score from findings. Score = max(0, 100 - total_points)."""
    points = 0
    for f in findings:
        severity = f.get('severity', 'info')
        if severity == 'critical':
            points += 10
        elif severity == 'high':
            points += 5
        elif severity == 'medium':
            points += 2
        elif severity == 'low':
            points += 1
    return max(0, 100 - points)


def count_by_severity(findings):
    """Count findings by severity level."""
    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for f in findings:
        sev = f.get('severity', 'info')
        if sev in counts:
            counts[sev] += 1
    return counts


def scan_directory(directory_path):
    """Walk a directory and scan all infrastructure files."""
    all_findings = []
    scannable_extensions = ('.tf', '.yaml', '.yml', '.dockerfile')
    scannable_names = ('Dockerfile', 'Jenkinsfile', 'docker-compose.yml', 'docker-compose.yaml')

    for root, dirs, files in os.walk(directory_path):
        # Skip hidden directories and common non-infra dirs
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ('node_modules', 'vendor', '__pycache__', '.git')]
        for filename in files:
            full_path = os.path.join(root, filename)
            rel_path = os.path.relpath(full_path, directory_path)

            should_scan = (
                filename.lower().endswith(scannable_extensions) or
                filename in scannable_names or
                '.github/workflows' in rel_path.replace('\\', '/')
            )

            if should_scan:
                try:
                    with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    file_type = detect_file_type(rel_path, content)
                    if file_type:
                        file_findings = analyze_content(content, file_type, rel_path)
                        all_findings.extend(file_findings)
                except Exception:
                    continue

    return all_findings


def clone_and_scan_repo(repo_url, token=None):
    """Clone a GitHub repo and scan it for infrastructure issues."""
    clone_dir = os.path.join('/tmp', f'infraaudit-{uuid.uuid4().hex[:12]}')

    try:
        # Build clone URL with token if provided
        if token:
            # Extract owner/repo from URL
            match = re.match(r'https?://github\.com/([^/]+/[^/]+?)(?:\.git)?$', repo_url)
            if match:
                repo_path = match.group(1)
                clone_url = f'https://{token}@github.com/{repo_path}.git'
            else:
                clone_url = repo_url
        else:
            # No token — try public clone but warn if it fails
            clone_url = repo_url

        # Clone with depth 1 for speed
        env = os.environ.copy()
        env['GIT_TERMINAL_PROMPT'] = '0'
        env['GIT_ASKPASS'] = '/bin/false'  # Always fail if asked for password
        env['GIT_SSH_COMMAND'] = 'ssh -o BatchMode=yes'
        env['GIT_CONFIG_NOSYSTEM'] = '1'
        env['GIT_CONFIG_GLOBAL'] = '/dev/null'
        env['HOME'] = clone_dir  # Isolate from user's ~/.gitconfig

        # Use -c options to disable all credential helpers
        git_cmd = [
            'git',
            '-c', 'credential.helper=',
            '-c', 'credential.helper=/bin/false',
            'clone', '--depth', '1', '--single-branch',
            clone_url, clone_dir
        ]

        result = subprocess.run(
            git_cmd, capture_output=True, text=True, timeout=120, env=env
        )

        if result.returncode != 0:
            error_msg = result.stderr.lower()
            if 'authentication' in error_msg or 'fatal: could not read' in error_msg or 'terminal prompts disabled' in error_msg:
                return None, 'Authentication failed. This appears to be a private repository — please provide a GitHub Personal Access Token with repo scope.'
            elif 'not found' in error_msg or 'does not exist' in error_msg:
                return None, 'Repository not found. Check the URL and ensure the repo exists.'
            else:
                return None, f'Failed to clone repository: {result.stderr[:200]}'

        # Scan the cloned directory
        findings = scan_directory(clone_dir)

        if not findings:
            return [], None

        # Deduplicate findings — group same issue across files, keep unique per file
        seen = set()
        unique_findings = []
        for f in findings:
            key = (f['severity'], f['title'], f.get('file_path', ''))
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        return unique_findings, None

    except subprocess.TimeoutExpired:
        return None, 'Repository clone timed out (>2 min). The repository may be too large. Try a smaller repo or contact support.'
    except Exception as e:
        return None, f'Error scanning repository: {str(e)}'
    finally:
        # Clean up
        if os.path.exists(clone_dir):
            shutil.rmtree(clone_dir, ignore_errors=True)


# ============================================================
# ROUTES
# ============================================================

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        try:
            email = request.form.get('email', '').strip().lower()
            name = request.form.get('name', '').strip()
            password = request.form.get('password', '')
            confirm = request.form.get('confirm_password', '')

            if not email or not name or not password:
                flash('All fields are required.', 'error')
                return render_template('auth.html', mode='register')

            if password != confirm:
                flash('Passwords do not match.', 'error')
                return render_template('auth.html', mode='register')

            if len(password) < 8:
                flash('Password must be at least 8 characters.', 'error')
                return render_template('auth.html', mode='register')

            if not re.search(r'[A-Z]', password):
                flash('Password must contain at least one uppercase letter.', 'error')
                return render_template('auth.html', mode='register')

            if not re.search(r'[a-z]', password):
                flash('Password must contain at least one lowercase letter.', 'error')
                return render_template('auth.html', mode='register')

            if not re.search(r'[0-9]', password):
                flash('Password must contain at least one number.', 'error')
                return render_template('auth.html', mode='register')

            if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
                flash('Password must contain at least one special character (!@#$%^&* etc).', 'error')
                return render_template('auth.html', mode='register')

            if User.query.filter_by(email=email).first():
                flash('Email already registered.', 'error')
                return render_template('auth.html', mode='register')

            user = User(email=email, name=name)
            user.set_password(password)
            # Auto-activate 7-day Pro trial for new users
            user.plan = 'pro'
            user.plan_expires_at = datetime.now(timezone.utc) + timedelta(days=7)
            db.session.add(user)
            db.session.commit()

            login_user(user)
            flash('🎉 Welcome! You have a 7-day Pro trial — full access to all features. Explore everything!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash('Registration failed. Please try again.', 'error')
            return render_template('auth.html', mode='register')

    return render_template('auth.html', mode='register')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        try:
            email = request.form.get('email', '').strip().lower()
            password = request.form.get('password', '')

            user = User.query.filter_by(email=email).first()
            if user and user.check_password(password):
                login_user(user)
                next_page = request.args.get('next')
                flash('Welcome back!', 'success')
                return redirect(next_page or url_for('dashboard'))
            else:
                flash('Invalid email or password.', 'error')
        except Exception:
            flash('Login failed. Please try again.', 'error')

    return render_template('auth.html', mode='login')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    # Show upgrade success message
    if request.args.get('upgraded'):
        flash(f'🎉 Welcome to the {current_user.plan.upper()} plan! You now have access to unlimited projects and scans.', 'success')

    projects = Project.query.filter_by(user_id=current_user.id).order_by(Project.created_at.desc()).all()
    scans = Scan.query.join(Project).filter(Project.user_id == current_user.id).order_by(Scan.created_at.desc()).limit(10).all()

    total_projects = len(projects)
    total_scans = Scan.query.join(Project).filter(Project.user_id == current_user.id).count()
    avg_risk = 0
    if projects:
        scores = [p.risk_score for p in projects if p.risk_score is not None]
        avg_risk = round(sum(scores) / len(scores)) if scores else 100

    total_critical = sum(s.critical_count for s in scans)

    # Risk trend data (last 10 scans)
    recent_scans = Scan.query.join(Project).filter(
        Project.user_id == current_user.id
    ).order_by(Scan.created_at.asc()).limit(10).all()
    trend_labels = [s.created_at.strftime('%m/%d') for s in recent_scans]
    trend_data = [s.risk_score for s in recent_scans]

    return render_template('dashboard.html',
                           projects=projects,
                           scans=scans,
                           total_projects=total_projects,
                           total_scans=total_scans,
                           avg_risk=avg_risk,
                           total_critical=total_critical,
                           trend_labels=json.dumps(trend_labels),
                           trend_data=json.dumps(trend_data))


@app.route('/projects')
@login_required
def projects():
    user_projects = Project.query.filter_by(user_id=current_user.id).order_by(Project.created_at.desc()).all()
    return render_template('projects.html', projects=user_projects)


@app.route('/projects/new', methods=['GET', 'POST'])
@login_required
def project_new():
    # Check plan limits
    if not current_user.can_create_project():
        flash(f'You\'ve reached the {current_user.plan} plan limit of {current_user.get_plan_limit("projects")} projects. Upgrade to Pro for unlimited projects.', 'error')
        return redirect(url_for('upgrade'))

    if request.method == 'POST':
        try:
            name = request.form.get('name', '').strip()
            repo_url = request.form.get('repo_url', '').strip()
            github_token = request.form.get('github_token', '').strip()

            if not name:
                flash('Project name is required.', 'error')
                return render_template('project_new.html')

            # Plan check: GitHub repo connection is Pro+ only
            if repo_url and not current_user.is_plan_active():
                flash('GitHub repo integration is a Pro feature. Free plan supports manual paste scanning only.', 'error')
                return redirect(url_for('upgrade'))

            project = Project(
                user_id=current_user.id,
                name=name,
                repo_url=repo_url if repo_url else None
            )
            db.session.add(project)

            # Store token on user if provided
            if github_token:
                current_user.github_token = github_token

            db.session.commit()
            flash('Project created successfully!', 'success')

            # Auto-scan if repo URL provided
            if repo_url:
                return redirect(url_for('project_scan', project_id=project.id))

            return redirect(url_for('project_detail', project_id=project.id))
        except Exception as e:
            db.session.rollback()
            flash('Failed to create project.', 'error')

    return render_template('project_new.html')


@app.route('/projects/<int:project_id>')
@login_required
def project_detail(project_id):
    project = Project.query.filter_by(id=project_id, user_id=current_user.id).first_or_404()
    scans = Scan.query.filter_by(project_id=project.id).order_by(Scan.created_at.desc()).all()
    latest_findings = []
    if scans:
        latest_findings = Finding.query.filter_by(scan_id=scans[0].id).all()
    has_token = bool(current_user.github_token)
    return render_template('project_detail.html', project=project, scans=scans, findings=latest_findings, has_token=has_token)


@app.route('/projects/<int:project_id>/token', methods=['POST'])
@login_required
def project_update_token(project_id):
    project = Project.query.filter_by(id=project_id, user_id=current_user.id).first_or_404()
    token = request.form.get('github_token', '').strip()
    if not token:
        flash('Please provide a valid GitHub Personal Access Token.', 'error')
    elif not token.startswith(('ghp_', 'github_pat_')):
        flash('Invalid token format. GitHub PATs start with ghp_ or github_pat_.', 'error')
    else:
        current_user.github_token = token
        db.session.commit()
        flash('GitHub token updated successfully! You can now scan private repositories.', 'success')
    return redirect(url_for('project_detail', project_id=project.id))


@app.route('/projects/<int:project_id>/delete', methods=['POST'])
@login_required
def project_delete(project_id):
    project = Project.query.filter_by(id=project_id, user_id=current_user.id).first_or_404()
    project_name = project.name
    db.session.delete(project)
    db.session.commit()
    flash(f'Project "{project_name}" deleted successfully.', 'success')
    return redirect(url_for('projects'))


@app.route('/projects/<int:project_id>/scan')
@login_required
def project_scan(project_id):
    project = Project.query.filter_by(id=project_id, user_id=current_user.id).first_or_404()

    # Plan check: GitHub repo scanning is Pro+ only
    if not current_user.is_plan_active() and project.repo_url:
        flash('GitHub repo scanning is a Pro feature. Upgrade to scan repositories automatically.', 'error')
        return redirect(url_for('upgrade'))

    # Plan check: scan limit
    if not current_user.is_plan_active():
        month_start = datetime.now(timezone.utc).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        scans_this_month = Scan.query.join(Project).filter(
            Project.user_id == current_user.id,
            Scan.created_at >= month_start
        ).count()
        if scans_this_month >= PLAN_LIMITS['free']['scans_per_month']:
            flash(f'You\'ve used all {PLAN_LIMITS["free"]["scans_per_month"]} free scans this month. Upgrade to Pro for unlimited scans.', 'error')
            return redirect(url_for('upgrade'))

    if not project.repo_url:
        flash('No repository URL configured for this project.', 'error')
        return redirect(url_for('project_detail', project_id=project.id))

    try:
        token = current_user.github_token
        findings_list, error = clone_and_scan_repo(project.repo_url, token)

        if error:
            flash(f'Scan failed: {error}', 'error')
            return redirect(url_for('project_detail', project_id=project.id))

        # Calculate scores
        risk_score = calculate_risk_score(findings_list)
        severity_counts = count_by_severity(findings_list)

        # Create scan record
        scan = Scan(
            project_id=project.id,
            status='completed',
            risk_score=risk_score,
            findings_count=len(findings_list),
            critical_count=severity_counts['critical'],
            high_count=severity_counts['high'],
            medium_count=severity_counts['medium'],
            low_count=severity_counts['low'],
            info_count=severity_counts['info']
        )
        db.session.add(scan)
        db.session.flush()

        # Create finding records
        for f in findings_list:
            finding = Finding(
                scan_id=scan.id,
                severity=f['severity'],
                category=f['category'],
                title=f['title'],
                description=f['description'],
                recommendation=f['recommendation'],
                file_path=f.get('file_path'),
                line_number=f.get('line_number'),
                framework=f.get('framework')
            )
            db.session.add(finding)

        # Update project
        project.last_scan_at = datetime.now(timezone.utc)
        project.risk_score = risk_score
        db.session.commit()

        flash(f'Scan completed! Risk score: {risk_score}/100 with {len(findings_list)} findings.', 'success')
        return redirect(url_for('scan_detail', scan_id=scan.id))

    except Exception as e:
        db.session.rollback()
        flash(f'Scan failed: {str(e)}', 'error')
        return redirect(url_for('project_detail', project_id=project.id))


@app.route('/scan/<int:scan_id>')
@login_required
def scan_detail(scan_id):
    scan = Scan.query.join(Project).filter(
        Scan.id == scan_id,
        Project.user_id == current_user.id
    ).first_or_404()
    findings = Finding.query.filter_by(scan_id=scan.id).order_by(
        Finding.file_path.asc(),
        db.case(
            (Finding.severity == 'critical', 0),
            (Finding.severity == 'high', 1),
            (Finding.severity == 'medium', 2),
            (Finding.severity == 'low', 3),
            else_=4
        )
    ).all()

    # Framework coverage
    frameworks = {}
    for f in findings:
        if f.framework:
            if f.framework not in frameworks:
                frameworks[f.framework] = 0
            frameworks[f.framework] += 1

    return render_template('scan_detail.html', scan=scan, findings=findings, frameworks=frameworks)


@app.route('/scan/<int:scan_id>/export')
@login_required
def scan_export(scan_id):
    # Plan check: export is Pro+ only
    if not current_user.is_plan_active():
        flash('Report export is a Pro feature. Upgrade to download scan reports.', 'error')
        return redirect(url_for('upgrade'))

    scan = Scan.query.join(Project).filter(
        Scan.id == scan_id,
        Project.user_id == current_user.id
    ).first_or_404()
    findings = Finding.query.filter_by(scan_id=scan.id).order_by(
        db.case(
            (Finding.severity == 'critical', 0),
            (Finding.severity == 'high', 1),
            (Finding.severity == 'medium', 2),
            (Finding.severity == 'low', 3),
            else_=4
        )
    ).all()

    # Generate PDF
    from fpdf import FPDF
    from io import BytesIO

    class PDF(FPDF):
        def header(self):
            self.set_font('Helvetica', 'B', 16)
            self.set_text_color(6, 182, 212)
            self.cell(0, 10, 'DeployPilot AI - InfraAudit Report', ln=True, align='C')
            self.set_font('Helvetica', '', 9)
            self.set_text_color(100, 100, 100)
            self.cell(0, 6, f'Generated: {datetime.now(timezone.utc).strftime("%B %d, %Y %H:%M UTC")}', ln=True, align='C')
            self.ln(5)
            self.set_draw_color(40, 40, 60)
            self.line(10, self.get_y(), 200, self.get_y())
            self.ln(8)

        def footer(self):
            self.set_y(-15)
            self.set_font('Helvetica', 'I', 8)
            self.set_text_color(150, 150, 150)
            self.cell(0, 10, f'Page {self.page_no()} | deploypilotai.automationvijay.site', align='C')

    pdf = PDF()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    # Project Info
    pdf.set_font('Helvetica', 'B', 13)
    pdf.set_text_color(30, 30, 50)
    pdf.cell(0, 8, f'Project: {scan.project.name}', ln=True)
    pdf.set_font('Helvetica', '', 10)
    pdf.set_text_color(80, 80, 100)
    if scan.project.repo_url:
        pdf.cell(0, 6, f'Repository: {scan.project.repo_url}', ln=True)
    pdf.cell(0, 6, f'Scan Date: {scan.created_at.strftime("%B %d, %Y %H:%M")}', ln=True)
    pdf.cell(0, 6, f'Status: {scan.status.upper()}', ln=True)
    pdf.ln(6)

    # Risk Score Box
    pdf.set_font('Helvetica', 'B', 12)
    pdf.set_text_color(30, 30, 50)
    pdf.cell(0, 8, 'Risk Score', ln=True)
    score = scan.risk_score
    if score >= 80:
        pdf.set_text_color(16, 185, 129)
    elif score >= 60:
        pdf.set_text_color(234, 179, 8)
    elif score >= 40:
        pdf.set_text_color(249, 115, 22)
    else:
        pdf.set_text_color(239, 68, 68)
    pdf.set_font('Helvetica', 'B', 28)
    pdf.cell(30, 15, str(score), ln=False)
    pdf.set_font('Helvetica', '', 10)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 15, f' / 100', ln=True)
    pdf.ln(4)

    # Summary
    pdf.set_font('Helvetica', 'B', 12)
    pdf.set_text_color(30, 30, 50)
    pdf.cell(0, 8, 'Summary', ln=True)
    pdf.set_font('Helvetica', '', 10)
    pdf.set_text_color(60, 60, 80)
    pdf.cell(0, 6, f'Total Findings: {scan.findings_count}  |  Critical: {scan.critical_count}  |  High: {scan.high_count}  |  Medium: {scan.medium_count}  |  Low: {scan.low_count}', ln=True)
    pdf.ln(8)

    # Findings
    pdf.set_font('Helvetica', 'B', 12)
    pdf.set_text_color(30, 30, 50)
    pdf.cell(0, 8, f'Findings ({len(findings)})', ln=True)
    pdf.ln(3)

    severity_colors = {
        'critical': (239, 68, 68),
        'high': (249, 115, 22),
        'medium': (234, 179, 8),
        'low': (59, 130, 246),
        'info': (107, 114, 128)
    }

    for i, f in enumerate(findings, 1):
        # Check if we need a new page
        if pdf.get_y() > 250:
            pdf.add_page()

        color = severity_colors.get(f.severity, (107, 114, 128))

        # Severity + Title
        pdf.set_font('Helvetica', 'B', 10)
        pdf.set_text_color(*color)
        pdf.cell(22, 6, f'[{f.severity.upper()}]', ln=False)
        pdf.set_text_color(30, 30, 50)
        pdf.cell(0, 6, f'{f.title}', ln=True)

        # File path
        if f.file_path:
            pdf.set_font('Helvetica', 'I', 8)
            pdf.set_text_color(100, 100, 120)
            pdf.set_x(15)
            pdf.cell(0, 5, f'File: {f.file_path}' + (f':{f.line_number}' if f.line_number else ''), ln=True)

        # Description
        pdf.set_font('Helvetica', '', 9)
        pdf.set_text_color(70, 70, 90)
        desc = (f.description or '')[:300].encode('latin-1', 'replace').decode('latin-1')
        pdf.set_x(15)
        pdf.multi_cell(0, 4.5, desc)

        # Recommendation
        pdf.set_font('Helvetica', 'I', 9)
        pdf.set_text_color(16, 150, 110)
        rec = (f.recommendation or '')[:300].encode('latin-1', 'replace').decode('latin-1')
        pdf.set_x(15)
        pdf.multi_cell(0, 4.5, 'Fix: ' + rec)

        # Framework
        if f.framework:
            pdf.set_font('Helvetica', '', 8)
            pdf.set_text_color(130, 130, 150)
            pdf.set_x(15)
            pdf.cell(0, 5, f'Framework: {f.framework}', ln=True)

        pdf.ln(2)
        pdf.set_draw_color(220, 220, 230)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(4)

    # Output PDF
    pdf_output = BytesIO()
    pdf.output(pdf_output)
    pdf_output.seek(0)

    from flask import send_file
    filename = f'infraaudit-{scan.project.name.lower().replace(" ", "-")}-{scan.created_at.strftime("%Y%m%d")}.pdf'
    return send_file(
        pdf_output,
        mimetype='application/pdf',
        as_attachment=True,
        download_name=filename
    )


@app.route('/analyze', methods=['GET', 'POST'])
@login_required
def analyze():
    results = None
    if request.method == 'POST':
        try:
            # Plan check: scan limit for free users
            if not current_user.is_plan_active():
                month_start = datetime.now(timezone.utc).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
                scans_this_month = Scan.query.join(Project).filter(
                    Project.user_id == current_user.id,
                    Scan.created_at >= month_start
                ).count()
                if scans_this_month >= PLAN_LIMITS['free']['scans_per_month']:
                    flash(f'You\'ve used all {PLAN_LIMITS["free"]["scans_per_month"]} free scans this month. Upgrade to Pro for unlimited scans.', 'error')
                    return redirect(url_for('upgrade'))

            code = request.form.get('code', '')
            file_type = request.form.get('file_type', 'kubernetes')

            if not code.strip():
                flash('Please paste some code to analyze.', 'error')
                return render_template('analyze.html', results=None)

            findings_list = analyze_content(code, file_type, f'manual_input.{file_type}')
            risk_score = calculate_risk_score(findings_list)
            severity_counts = count_by_severity(findings_list)

            # Save as a scan under a "Manual Scans" project
            manual_project = Project.query.filter_by(
                user_id=current_user.id, name='Manual Scans'
            ).first()
            if not manual_project:
                manual_project = Project(
                    user_id=current_user.id,
                    name='Manual Scans',
                    repo_url=None
                )
                db.session.add(manual_project)
                db.session.flush()

            scan = Scan(
                project_id=manual_project.id,
                status='completed',
                risk_score=risk_score,
                findings_count=len(findings_list),
                critical_count=severity_counts['critical'],
                high_count=severity_counts['high'],
                medium_count=severity_counts['medium'],
                low_count=severity_counts['low'],
                info_count=severity_counts['info']
            )
            db.session.add(scan)
            db.session.flush()

            for f in findings_list:
                finding = Finding(
                    scan_id=scan.id,
                    severity=f['severity'],
                    category=f['category'],
                    title=f['title'],
                    description=f['description'],
                    recommendation=f['recommendation'],
                    file_path=f.get('file_path'),
                    line_number=f.get('line_number'),
                    framework=f.get('framework')
                )
                db.session.add(finding)

            manual_project.last_scan_at = datetime.now(timezone.utc)
            manual_project.risk_score = risk_score
            db.session.commit()

            results = {
                'risk_score': risk_score,
                'findings': findings_list,
                'counts': severity_counts,
                'scan_id': scan.id
            }
        except Exception as e:
            db.session.rollback()
            flash(f'Analysis failed: {str(e)}', 'error')

    return render_template('analyze.html', results=results)


@app.route('/pricing')
def pricing():
    return render_template('pricing.html')


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        message = request.form.get('message', '').strip()
        if name and email and message:
            # Send notification email to admin
            email_body = f'''
            <div style="font-family:Arial,sans-serif;max-width:500px;padding:20px;">
                <h3 style="color:#06b6d4;margin-bottom:16px;">New Contact Form Submission</h3>
                <p><strong>Name:</strong> {name}</p>
                <p><strong>Email:</strong> {email}</p>
                <p><strong>Message:</strong></p>
                <p style="background:#f1f5f9;padding:12px;border-radius:8px;">{message}</p>
                <hr style="margin:20px 0;border:none;border-top:1px solid #e2e8f0;">
                <p style="color:#999;font-size:12px;">Sent from DeployPilot AI contact form</p>
            </div>
            '''
            sent = send_email(ADMIN_EMAIL, f'[DeployPilot] Contact from {name} ({email})', email_body)
            if sent:
                flash('Message sent successfully! We\'ll get back to you within 24 hours.', 'success')
            else:
                # Still show success to user (we'll check logs), but log the issue
                flash('Message received! We\'ll get back to you within 24 hours.', 'success')
                app.logger.warning(f'Contact form: email delivery failed for {name} ({email}). Message: {message[:100]}')
        else:
            flash('Please fill in all fields.', 'error')
        return redirect(url_for('contact'))
    return render_template('contact.html')


@app.route('/blog')
def blog():
    return render_template('blog.html')


@app.route('/careers')
def careers():
    return render_template('careers.html')


@app.route('/privacy')
def privacy():
    return render_template('privacy.html')


@app.route('/terms')
def terms():
    return render_template('terms.html')


@app.route('/security')
def security_page():
    return render_template('security.html')


# ============================================================
# FORGOT PASSWORD
# ============================================================

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        user = User.query.filter_by(email=email).first()
        if user:
            token = user.generate_reset_token()
            db.session.commit()
            reset_url = url_for('reset_password', token=token, _external=True)

            # Send reset email
            email_html = f'''
            <div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;padding:40px 20px;">
                <h2 style="color:#06b6d4;margin-bottom:20px;">Reset Your Password</h2>
                <p style="color:#333;line-height:1.6;">Hi {user.name},</p>
                <p style="color:#333;line-height:1.6;">Click the button below to reset your password. This link expires in 1 hour.</p>
                <a href="{reset_url}" style="display:inline-block;background:#06b6d4;color:#fff;padding:12px 32px;border-radius:8px;text-decoration:none;font-weight:bold;margin:20px 0;">Reset Password</a>
                <p style="color:#666;font-size:0.85rem;margin-top:20px;">If you didn't request this, ignore this email.</p>
                <hr style="border:none;border-top:1px solid #eee;margin:30px 0;">
                <p style="color:#999;font-size:0.8rem;">DeployPilot AI · InfraAudit</p>
            </div>
            '''
            sent = send_email(user.email, 'Reset your DeployPilot AI password', email_html)
            if sent:
                flash(f'Password reset link sent to {email}. Check your inbox.', 'success')
            else:
                # Fallback: show link directly if email not configured
                flash(f'Email service not configured. Use this link to reset:', 'info')
                flash(f'{reset_url}', 'info')
        else:
            flash('If an account with that email exists, a reset link has been sent.', 'success')
        return redirect(url_for('forgot_password'))
    return render_template('forgot_password.html')


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()
    if not user or not user.reset_token_expires or user.reset_token_expires.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        flash('Invalid or expired reset link. Please request a new one.', 'error')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')
        if len(password) < 8:
            flash('Password must be at least 8 characters.', 'error')
            return render_template('reset_password.html', token=token)
        if password != confirm:
            flash('Passwords do not match.', 'error')
            return render_template('reset_password.html', token=token)

        user.set_password(password)
        user.reset_token = None
        user.reset_token_expires = None
        db.session.commit()
        flash('Password reset successfully! You can now login.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)


# ============================================================
# PAYMENTS (Razorpay)
# ============================================================

@app.route('/upgrade', methods=['GET'])
@login_required
def upgrade():
    return render_template('upgrade.html', razorpay_key=RAZORPAY_KEY_ID)


@app.route('/create-order', methods=['POST'])
@login_required
def create_order():
    """Create a Razorpay order for plan upgrade."""
    plan_id = request.form.get('plan_id', 'pro_monthly')
    plan_info = PLAN_PRICES.get(plan_id)
    if not plan_info:
        return jsonify({'error': 'Invalid plan'}), 400

    try:
        import hashlib
        import hmac
        import time

        # If Razorpay keys are configured, create real order
        if RAZORPAY_KEY_SECRET:
            import urllib.request
            import base64

            order_data = json.dumps({
                'amount': plan_info['razorpay_amount'],
                'currency': 'INR',
                'receipt': f'order_{current_user.id}_{int(time.time())}',
                'notes': {'plan': plan_id, 'user_id': str(current_user.id)}
            }).encode()

            credentials = base64.b64encode(f'{RAZORPAY_KEY_ID}:{RAZORPAY_KEY_SECRET}'.encode()).decode()
            req = urllib.request.Request(
                'https://api.razorpay.com/v1/orders',
                data=order_data,
                headers={
                    'Content-Type': 'application/json',
                    'Authorization': f'Basic {credentials}'
                }
            )
            with urllib.request.urlopen(req) as response:
                order = json.loads(response.read().decode())

            # Save payment record
            payment = Payment(
                user_id=current_user.id,
                razorpay_order_id=order['id'],
                amount=plan_info['razorpay_amount'],
                plan=plan_id,
                status='pending'
            )
            db.session.add(payment)
            db.session.commit()

            return jsonify({
                'order_id': order['id'],
                'amount': plan_info['razorpay_amount'],
                'currency': 'INR',
                'key': RAZORPAY_KEY_ID,
                'name': 'DeployPilot AI',
                'description': plan_info['label'],
                'prefill': {
                    'name': current_user.name,
                    'email': current_user.email
                }
            })
        else:
            # Test mode — simulate order creation
            fake_order_id = f'order_test_{uuid.uuid4().hex[:12]}'
            payment = Payment(
                user_id=current_user.id,
                razorpay_order_id=fake_order_id,
                amount=plan_info['razorpay_amount'],
                plan=plan_id,
                status='pending'
            )
            db.session.add(payment)
            db.session.commit()

            return jsonify({
                'order_id': fake_order_id,
                'amount': plan_info['razorpay_amount'],
                'currency': 'INR',
                'key': RAZORPAY_KEY_ID,
                'name': 'DeployPilot AI',
                'description': plan_info['label'],
                'test_mode': True,
                'prefill': {
                    'name': current_user.name,
                    'email': current_user.email
                }
            })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/payment-success', methods=['POST'])
@login_required
def payment_success():
    """Verify Razorpay payment and activate plan."""
    data = request.get_json() or request.form
    order_id = data.get('razorpay_order_id', '')
    payment_id = data.get('razorpay_payment_id', '')
    signature = data.get('razorpay_signature', '')

    payment = Payment.query.filter_by(
        razorpay_order_id=order_id, user_id=current_user.id
    ).first()

    if not payment:
        return jsonify({'error': 'Payment not found'}), 404

    # Verify signature (if secret is configured)
    if RAZORPAY_KEY_SECRET and signature:
        import hmac
        import hashlib
        expected = hmac.new(
            RAZORPAY_KEY_SECRET.encode(),
            f'{order_id}|{payment_id}'.encode(),
            hashlib.sha256
        ).hexdigest()
        if expected != signature:
            payment.status = 'failed'
            db.session.commit()
            return jsonify({'error': 'Payment verification failed'}), 400

    # Activate plan
    payment.razorpay_payment_id = payment_id
    payment.razorpay_signature = signature
    payment.status = 'completed'

    # Determine plan from payment record
    from datetime import timedelta
    if 'yearly' in payment.plan:
        current_user.plan_expires_at = datetime.now(timezone.utc) + timedelta(days=365)
    else:
        current_user.plan_expires_at = datetime.now(timezone.utc) + timedelta(days=30)

    if 'team' in payment.plan:
        current_user.plan = 'team'
    else:
        current_user.plan = 'pro'

    db.session.commit()
    return jsonify({'status': 'success', 'plan': current_user.plan})


# ============================================================
# ADMIN DASHBOARD
# ============================================================

def admin_required(f):
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if current_user.email != ADMIN_EMAIL:
            abort(403)
        return f(*args, **kwargs)
    return decorated


@app.route('/admin')
@admin_required
def admin_dashboard():
    users = User.query.order_by(User.created_at.desc()).all()
    total_users = len(users)
    pro_users = sum(1 for u in users if u.plan == 'pro')
    team_users = sum(1 for u in users if u.plan == 'team')
    free_users = sum(1 for u in users if u.plan == 'free')
    total_scans = Scan.query.count()
    total_projects = Project.query.count()
    total_payments = Payment.query.filter_by(status='completed').count()
    total_revenue = db.session.query(db.func.sum(Payment.amount)).filter_by(status='completed').scalar() or 0

    return render_template('admin.html',
                           users=users,
                           total_users=total_users,
                           pro_users=pro_users,
                           team_users=team_users,
                           free_users=free_users,
                           total_scans=total_scans,
                           total_projects=total_projects,
                           total_payments=total_payments,
                           total_revenue=total_revenue)


@app.route('/admin/user/<int:user_id>')
@admin_required
def admin_user_detail(user_id):
    user = User.query.get_or_404(user_id)
    projects = Project.query.filter_by(user_id=user.id).all()
    payments = Payment.query.filter_by(user_id=user.id).order_by(Payment.created_at.desc()).all()
    scans = Scan.query.join(Project).filter(Project.user_id == user.id).order_by(Scan.created_at.desc()).limit(10).all()
    return render_template('admin_user.html', user=user, projects=projects, payments=payments, scans=scans)


with app.app_context():
    db.create_all()


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
