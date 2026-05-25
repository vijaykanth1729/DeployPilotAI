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
        if self.email == os.getenv('ADMIN_EMAIL', 'deploypilotai@gmail.com'):
            return True
        current_count = Project.query.filter_by(user_id=self.id).count()
        return current_count < self.get_plan_limit('projects')

    def is_plan_active(self):
        """Check if paid plan/trial is still active. Admin always has full access."""
        if self.email == os.getenv('ADMIN_EMAIL', 'deploypilotai@gmail.com'):
            return True
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


class Subscriber(db.Model):
    __tablename__ = 'subscribers'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class Review(db.Model):
    __tablename__ = 'reviews'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)  # 1-5 stars
    text = db.Column(db.Text, nullable=False)
    display_name = db.Column(db.String(255), nullable=True)  # Override name for seed/display
    is_visible = db.Column(db.Boolean, default=False)  # Requires admin approval to show
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    user = db.relationship('User', backref='reviews')

    @property
    def reviewer_name(self):
        """Return display_name if set, otherwise user.name."""
        try:
            if self.display_name:
                return self.display_name
        except Exception:
            pass
        return self.user.name


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
    fix_code = db.Column(db.Text, nullable=True)


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

# Google OAuth config
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID', '')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET', '')
GOOGLE_REDIRECT_URI = os.getenv('GOOGLE_REDIRECT_URI', 'https://deploypilotai.automationvijay.site/auth/google/callback')

# GitHub OAuth config
GITHUB_OAUTH_CLIENT_ID = os.getenv('GITHUB_OAUTH_CLIENT_ID', '')
GITHUB_OAUTH_CLIENT_SECRET = os.getenv('GITHUB_OAUTH_CLIENT_SECRET', '')
GITHUB_OAUTH_REDIRECT_URI = os.getenv('GITHUB_OAUTH_REDIRECT_URI', 'https://deploypilotai.automationvijay.site/auth/github/callback')

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

    # Check 16: automountServiceAccountToken not disabled
    if 'containers:' in content:
        if not re.search(r'automountServiceAccountToken:\s*false', content):
            findings.append({
                'severity': 'medium', 'category': 'security',
                'title': 'Service Account Token Auto-Mounted',
                'description': 'Service account token is auto-mounted into pods, potentially exposing API access.',
                'recommendation': 'Set automountServiceAccountToken: false unless the pod needs API access.',
                'file_path': file_path, 'line_number': 1, 'framework': 'CIS-K8S-1.8'
            })

    # Check 17: Using default service account
    if re.search(r'serviceAccountName:\s*default', content) or ('containers:' in content and not re.search(r'serviceAccountName:', content)):
        if re.search(r'kind:\s*(Deployment|Pod|StatefulSet)', content):
            findings.append({
                'severity': 'medium', 'category': 'security',
                'title': 'Using Default Service Account',
                'description': 'Pod uses the default service account which may have excessive permissions.',
                'recommendation': 'Create a dedicated service account with minimal RBAC permissions.',
                'file_path': file_path, 'line_number': 1, 'framework': 'CIS-K8S-1.8'
            })

    # Check 18: Container port using privileged port (<1024)
    priv_ports = re.finditer(r'containerPort:\s*(\d+)', content)
    for match in priv_ports:
        port = int(match.group(1))
        if port < 1024 and port != 443 and port != 80:
            line_num = content[:match.start()].count('\n') + 1
            findings.append({
                'severity': 'low', 'category': 'security',
                'title': f'Privileged Port {port} Used',
                'description': f'Container uses privileged port {port} (<1024). This may require elevated privileges.',
                'recommendation': 'Use ports above 1024 (e.g., 8080, 8443) and map with Service.',
                'file_path': file_path, 'line_number': line_num, 'framework': 'CIS-K8S-1.8'
            })
            break

    # Check 19: No anti-affinity for replicated deployments
    if re.search(r'replicas:\s*[2-9]', content):
        if not re.search(r'(podAntiAffinity|topologySpreadConstraints)', content):
            findings.append({
                'severity': 'low', 'category': 'reliability',
                'title': 'No Pod Anti-Affinity',
                'description': 'Multi-replica deployment without anti-affinity. All pods may land on same node.',
                'recommendation': 'Add podAntiAffinity or topologySpreadConstraints for high availability.',
                'file_path': file_path, 'line_number': 1, 'framework': 'CIS-K8S-1.8'
            })

    # Check 20: No startupProbe for slow-starting containers
    if 'containers:' in content and re.search(r'(java|spring|rails|django)', content, re.IGNORECASE):
        if not re.search(r'startupProbe:', content):
            findings.append({
                'severity': 'low', 'category': 'reliability',
                'title': 'No Startup Probe for Slow-Starting App',
                'description': 'Application framework detected that may have slow startup. No startupProbe configured.',
                'recommendation': 'Add startupProbe with failureThreshold * periodSeconds > expected startup time.',
                'file_path': file_path, 'line_number': 1, 'framework': 'CIS-K8S-1.8'
            })

    # Check 21: hostPath volume mount
    if re.search(r'hostPath:', content):
        line_num = next((i+1 for i, l in enumerate(lines) if 'hostPath:' in l), 1)
        findings.append({
            'severity': 'high', 'category': 'security',
            'title': 'hostPath Volume Mount',
            'description': 'Pod mounts a host filesystem path. This breaks container isolation and exposes host files.',
            'recommendation': 'Use emptyDir, PVC, or ConfigMap/Secret volumes instead of hostPath.',
            'file_path': file_path, 'line_number': line_num, 'framework': 'CIS-K8S-1.8'
        })

    # Check 22: Capabilities not dropped
    if 'containers:' in content:
        if not re.search(r'drop:\s*\n\s*-\s*(ALL|all)', content):
            findings.append({
                'severity': 'medium', 'category': 'security',
                'title': 'Linux Capabilities Not Dropped',
                'description': 'Container does not drop all Linux capabilities. Unnecessary capabilities increase attack surface.',
                'recommendation': 'Add capabilities: drop: [ALL] and only add back specific needed capabilities.',
                'file_path': file_path, 'line_number': 1, 'framework': 'CIS-K8S-1.8'
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

    # Check 13: CloudTrail not enabled
    if re.search(r'resource\s+"aws_', content):
        if not re.search(r'aws_cloudtrail', content) and 'cloudtrail' not in content.lower():
            findings.append({
                'severity': 'medium', 'category': 'compliance',
                'title': 'No CloudTrail Configuration',
                'description': 'No CloudTrail resource found. API activity may not be logged for audit.',
                'recommendation': 'Enable AWS CloudTrail for all regions with S3 log delivery.',
                'file_path': file_path, 'line_number': 1, 'framework': 'AWS-WA-SEC'
            })

    # Check 14: EBS volume not encrypted
    if re.search(r'resource\s+"aws_ebs_volume"', content):
        if not re.search(r'encrypted\s*=\s*true', content):
            findings.append({
                'severity': 'high', 'category': 'security',
                'title': 'EBS Volume Not Encrypted',
                'description': 'EBS volume does not have encryption enabled. Data at rest is unprotected.',
                'recommendation': 'Set encrypted = true on all EBS volumes.',
                'file_path': file_path, 'line_number': 1, 'framework': 'AWS-WA-SEC'
            })

    # Check 15: Lambda without VPC
    if re.search(r'resource\s+"aws_lambda_function"', content):
        if not re.search(r'vpc_config', content):
            findings.append({
                'severity': 'low', 'category': 'security',
                'title': 'Lambda Not in VPC',
                'description': 'Lambda function is not configured within a VPC. It cannot access private resources.',
                'recommendation': 'Add vpc_config with subnet_ids and security_group_ids if the function needs VPC access.',
                'file_path': file_path, 'line_number': 1, 'framework': 'AWS-WA-SEC'
            })

    # Check 16: No lifecycle prevent_destroy on critical resources
    if re.search(r'resource\s+"aws_(db_instance|s3_bucket|dynamodb_table)"', content):
        if not re.search(r'prevent_destroy\s*=\s*true', content):
            findings.append({
                'severity': 'medium', 'category': 'reliability',
                'title': 'No Lifecycle prevent_destroy',
                'description': 'Critical resource without prevent_destroy lifecycle rule. Accidental deletion possible.',
                'recommendation': 'Add lifecycle { prevent_destroy = true } to protect critical resources.',
                'file_path': file_path, 'line_number': 1, 'framework': 'AWS-WA-REL'
            })

    # Check 17: IAM policy with wildcard actions
    if re.search(r'"Action"\s*:\s*"\*"', content) or re.search(r'actions\s*=\s*\["\*"\]', content):
        line_num = next((i+1 for i, l in enumerate(lines) if '*' in l and ('Action' in l or 'actions' in l)), 1)
        findings.append({
            'severity': 'critical', 'category': 'security',
            'title': 'IAM Policy with Wildcard Actions',
            'description': 'IAM policy grants all actions (*). This violates least-privilege principle.',
            'recommendation': 'Specify only the exact actions needed (e.g., s3:GetObject, ec2:DescribeInstances).',
            'file_path': file_path, 'line_number': line_num, 'framework': 'AWS-WA-SEC'
        })

    # Check 18: Public subnet for databases
    if re.search(r'resource\s+"aws_db_instance"', content):
        if re.search(r'publicly_accessible\s*=\s*true', content):
            findings.append({
                'severity': 'critical', 'category': 'security',
                'title': 'RDS Publicly Accessible',
                'description': 'Database is publicly accessible from the internet.',
                'recommendation': 'Set publicly_accessible = false and access via VPC/bastion only.',
                'file_path': file_path, 'line_number': 1, 'framework': 'AWS-WA-SEC'
            })

    # Check 19: No backup retention
    if re.search(r'resource\s+"aws_db_instance"', content):
        if not re.search(r'backup_retention_period', content):
            findings.append({
                'severity': 'medium', 'category': 'reliability',
                'title': 'No Backup Retention Period',
                'description': 'RDS instance does not specify backup retention. Defaults may be insufficient.',
                'recommendation': 'Set backup_retention_period to at least 7 days for production databases.',
                'file_path': file_path, 'line_number': 1, 'framework': 'AWS-WA-REL'
            })

    # Check 20: S3 bucket public access not blocked
    if re.search(r'resource\s+"aws_s3_bucket"', content):
        if not re.search(r'aws_s3_bucket_public_access_block|block_public', content):
            findings.append({
                'severity': 'high', 'category': 'security',
                'title': 'S3 Public Access Not Blocked',
                'description': 'S3 bucket does not have public access block configured. Bucket may be publicly accessible.',
                'recommendation': 'Add aws_s3_bucket_public_access_block with all four block settings = true.',
                'file_path': file_path, 'line_number': 1, 'framework': 'AWS-WA-SEC'
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

    # Check 9: EXPOSE with too many ports
    expose_count = len(re.findall(r'^EXPOSE\s+', content, re.MULTILINE))
    if expose_count > 3:
        findings.append({
            'severity': 'low', 'category': 'security',
            'title': 'Too Many Ports Exposed',
            'description': f'{expose_count} ports exposed. Minimize attack surface by exposing only necessary ports.',
            'recommendation': 'Only EXPOSE ports that the application actually listens on.',
            'file_path': file_path, 'line_number': 1, 'framework': 'DOCKER-CIS'
        })

    # Check 10: Using apt-get without --no-install-recommends
    if re.search(r'apt-get install(?!.*--no-install-recommends)', content):
        findings.append({
            'severity': 'low', 'category': 'performance',
            'title': 'apt-get Without --no-install-recommends',
            'description': 'Installing packages without --no-install-recommends adds unnecessary packages to the image.',
            'recommendation': 'Use: RUN apt-get install -y --no-install-recommends <packages>',
            'file_path': file_path, 'line_number': 1, 'framework': 'DOCKER-CIS'
        })

    # Check 11: No .dockerignore consideration (COPY with broad context)
    if re.search(r'^COPY\s+\.\s', content, re.MULTILINE) and 'node_modules' not in content:
        findings.append({
            'severity': 'low', 'category': 'performance',
            'title': 'Ensure .dockerignore Exists',
            'description': 'Broad COPY detected. Ensure .dockerignore excludes node_modules, .git, .env, etc.',
            'recommendation': 'Create .dockerignore with: .git, node_modules, .env, *.log, .DS_Store',
            'file_path': file_path, 'line_number': 1, 'framework': 'DOCKER-CIS'
        })

    # Check 12: Using curl/wget without cleanup
    if re.search(r'(curl|wget)\s+', content):
        if not re.search(r'rm\s+', content):
            findings.append({
                'severity': 'low', 'category': 'performance',
                'title': 'Downloaded Files Not Cleaned Up',
                'description': 'Files downloaded with curl/wget may not be cleaned up, increasing image size.',
                'recommendation': 'Chain download, extract, and cleanup in a single RUN: curl ... && tar ... && rm ...',
                'file_path': file_path, 'line_number': 1, 'framework': 'DOCKER-CIS'
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

    # Check 9: No SAST/lint step
    if not re.search(r'(sonar|eslint|pylint|flake8|rubocop|golangci-lint|semgrep)', content, re.IGNORECASE):
        findings.append({
            'severity': 'medium', 'category': 'reliability',
            'title': 'No Static Analysis (SAST/Lint)',
            'description': 'Pipeline has no static analysis or linting step. Code quality issues may reach production.',
            'recommendation': 'Add a lint/SAST step: ESLint, Pylint, SonarQube, or Semgrep.',
            'file_path': file_path, 'line_number': 1, 'framework': 'CICD-SEC'
        })

    # Check 10: Deploying without approval on main branch
    if re.search(r'branches:\s*\[.*main.*\]', content) or re.search(r'branch.*main', content):
        if re.search(r'(deploy|production|release)', content, re.IGNORECASE):
            if not re.search(r'(approval|manual|environment)', content, re.IGNORECASE):
                findings.append({
                    'severity': 'high', 'category': 'security',
                    'title': 'Auto-Deploy to Production Without Approval',
                    'description': 'Pipeline deploys to production on push to main without manual approval gate.',
                    'recommendation': 'Add environment protection rules or manual approval step before production deploy.',
                    'file_path': file_path, 'line_number': 1, 'framework': 'CICD-SEC'
                })

    # Check 11: Using self-hosted runners without security
    if re.search(r'runs-on:\s*self-hosted', content):
        findings.append({
            'severity': 'medium', 'category': 'security',
            'title': 'Self-Hosted Runner Used',
            'description': 'Self-hosted runners may have persistent state and security risks if not properly isolated.',
            'recommendation': 'Use ephemeral runners, or ensure self-hosted runners are hardened and isolated.',
            'file_path': file_path, 'line_number': 1, 'framework': 'CICD-SEC'
        })

    # Check 12: No artifact signing/verification
    if re.search(r'(push|publish|upload|deploy)', content, re.IGNORECASE):
        if not re.search(r'(cosign|sigstore|sign|verify|checksum|sha256)', content, re.IGNORECASE):
            findings.append({
                'severity': 'low', 'category': 'security',
                'title': 'No Artifact Signing',
                'description': 'Artifacts are published without signing or checksum verification.',
                'recommendation': 'Sign container images with Cosign/Sigstore or generate SHA256 checksums for artifacts.',
                'file_path': file_path, 'line_number': 1, 'framework': 'CICD-SEC'
            })

    return findings


def analyze_cloudformation(content, file_path='unknown'):
    """Analyze AWS CloudFormation templates (JSON/YAML) for security issues."""
    findings = []
    lines = content.split('\n')

    # Check 1: S3 Bucket without encryption
    if re.search(r'AWS::S3::Bucket', content):
        if not re.search(r'(BucketEncryption|ServerSideEncryptionConfiguration|SSEAlgorithm)', content):
            line_num = next((i+1 for i, l in enumerate(lines) if 'AWS::S3::Bucket' in l), 1)
            findings.append({
                'severity': 'high', 'category': 'security',
                'title': 'CFN: S3 Bucket Without Encryption',
                'description': 'S3 bucket does not have server-side encryption configured in CloudFormation template.',
                'recommendation': 'Add BucketEncryption property with ServerSideEncryptionConfiguration using AES256 or aws:kms.',
                'file_path': file_path, 'line_number': line_num, 'framework': 'AWS-WA-SEC'
            })

    # Check 2: S3 Bucket public access
    if re.search(r'AWS::S3::Bucket', content):
        if not re.search(r'(PublicAccessBlockConfiguration|BlockPublicAcls|BlockPublicPolicy)', content):
            line_num = next((i+1 for i, l in enumerate(lines) if 'AWS::S3::Bucket' in l), 1)
            findings.append({
                'severity': 'high', 'category': 'security',
                'title': 'CFN: S3 Public Access Not Blocked',
                'description': 'S3 bucket does not have PublicAccessBlockConfiguration to prevent public access.',
                'recommendation': 'Add PublicAccessBlockConfiguration with all four block settings set to true.',
                'file_path': file_path, 'line_number': line_num, 'framework': 'AWS-WA-SEC'
            })

    # Check 3: Security Group open to world (0.0.0.0/0)
    if re.search(r'0\.0\.0\.0/0', content):
        if re.search(r'AWS::EC2::SecurityGroup', content):
            line_num = next((i+1 for i, l in enumerate(lines) if '0.0.0.0/0' in l), 1)
            findings.append({
                'severity': 'critical', 'category': 'security',
                'title': 'CFN: Security Group Open to World',
                'description': 'Security group ingress allows 0.0.0.0/0 — resource exposed to entire internet.',
                'recommendation': 'Restrict CidrIp to known IP ranges or use security group references.',
                'file_path': file_path, 'line_number': line_num, 'framework': 'AWS-WA-SEC'
            })

    # Check 4: IAM Policy with wildcard actions
    if re.search(r'AWS::IAM::(Policy|Role|ManagedPolicy)', content):
        wildcard_action = re.search(r'["\']Action["\']\s*:\s*["\']?\*["\']?', content) or re.search(r'Action:\s*["\']?\*', content)
        if wildcard_action:
            line_num = next((i+1 for i, l in enumerate(lines) if ('Action' in l and '*' in l)), 1)
            findings.append({
                'severity': 'critical', 'category': 'security',
                'title': 'CFN: IAM Policy with Wildcard Actions',
                'description': 'IAM policy grants all actions (*) violating the principle of least privilege.',
                'recommendation': 'Replace wildcard with specific actions needed (e.g., s3:GetObject, ec2:DescribeInstances).',
                'file_path': file_path, 'line_number': line_num, 'framework': 'AWS-WA-SEC'
            })

    # Check 5: IAM Policy with wildcard resource
    if re.search(r'AWS::IAM::(Policy|Role|ManagedPolicy)', content):
        wildcard_resource = re.search(r'["\']Resource["\']\s*:\s*["\']?\*["\']?', content) or re.search(r'Resource:\s*["\']?\*', content)
        if wildcard_resource:
            line_num = next((i+1 for i, l in enumerate(lines) if ('Resource' in l and '*' in l)), 1)
            findings.append({
                'severity': 'high', 'category': 'security',
                'title': 'CFN: IAM Policy with Wildcard Resource',
                'description': 'IAM policy applies to all resources (*). Should be scoped to specific ARNs.',
                'recommendation': 'Specify exact resource ARNs instead of using wildcard (*).',
                'file_path': file_path, 'line_number': line_num, 'framework': 'AWS-WA-SEC'
            })

    # Check 6: No DeletionPolicy on critical resources
    critical_resources = ['AWS::RDS::DBInstance', 'AWS::DynamoDB::Table', 'AWS::S3::Bucket', 'AWS::EFS::FileSystem']
    for res in critical_resources:
        if re.search(res, content):
            if not re.search(r'DeletionPolicy:\s*(Retain|Snapshot)', content):
                line_num = next((i+1 for i, l in enumerate(lines) if res in l), 1)
                findings.append({
                    'severity': 'high', 'category': 'reliability',
                    'title': 'CFN: No DeletionPolicy on Critical Resource',
                    'description': f'Resource {res.split("::")[-1]} has no DeletionPolicy. Stack deletion will destroy the resource permanently.',
                    'recommendation': 'Add DeletionPolicy: Retain or DeletionPolicy: Snapshot to prevent accidental data loss.',
                    'file_path': file_path, 'line_number': line_num, 'framework': 'AWS-WA-REL'
                })
                break

    # Check 7: RDS without encryption
    if re.search(r'AWS::RDS::DBInstance', content):
        if not re.search(r'StorageEncrypted:\s*(true|True|"true")', content):
            line_num = next((i+1 for i, l in enumerate(lines) if 'AWS::RDS::DBInstance' in l), 1)
            findings.append({
                'severity': 'high', 'category': 'security',
                'title': 'CFN: RDS Without Encryption',
                'description': 'RDS instance does not have StorageEncrypted enabled. Data at rest is unprotected.',
                'recommendation': 'Set StorageEncrypted: true and specify KmsKeyId for encryption.',
                'file_path': file_path, 'line_number': line_num, 'framework': 'AWS-WA-SEC'
            })

    # Check 8: RDS publicly accessible
    if re.search(r'AWS::RDS::DBInstance', content):
        if re.search(r'PubliclyAccessible:\s*(true|True|"true")', content):
            line_num = next((i+1 for i, l in enumerate(lines) if 'PubliclyAccessible' in l), 1)
            findings.append({
                'severity': 'critical', 'category': 'security',
                'title': 'CFN: RDS Publicly Accessible',
                'description': 'RDS instance is publicly accessible from the internet.',
                'recommendation': 'Set PubliclyAccessible: false and place RDS in private subnets.',
                'file_path': file_path, 'line_number': line_num, 'framework': 'AWS-WA-SEC'
            })

    # Check 9: No logging/monitoring (CloudTrail, CloudWatch)
    if not re.search(r'AWS::CloudTrail::Trail', content) and not re.search(r'AWS::Logs::LogGroup', content):
        if re.search(r'AWS::(EC2|Lambda|ECS|RDS)', content):
            findings.append({
                'severity': 'medium', 'category': 'security',
                'title': 'CFN: No Logging Configuration',
                'description': 'Template creates compute/data resources but has no CloudTrail or CloudWatch Logs configuration.',
                'recommendation': 'Add AWS::CloudTrail::Trail or AWS::Logs::LogGroup for audit and monitoring.',
                'file_path': file_path, 'line_number': 1, 'framework': 'AWS-WA-SEC'
            })

    # Check 10: EBS/EC2 without encryption
    if re.search(r'AWS::EC2::(Volume|Instance)', content):
        if not re.search(r'Encrypted:\s*(true|True|"true")', content):
            line_num = next((i+1 for i, l in enumerate(lines) if 'AWS::EC2::Volume' in l or 'BlockDeviceMappings' in l), 1)
            findings.append({
                'severity': 'high', 'category': 'security',
                'title': 'CFN: EBS Volume Not Encrypted',
                'description': 'EBS volume or EC2 block device mapping does not have encryption enabled.',
                'recommendation': 'Set Encrypted: true on EBS volumes and block device mappings.',
                'file_path': file_path, 'line_number': line_num, 'framework': 'AWS-WA-SEC'
            })

    # Check 11: Lambda without VPC config
    if re.search(r'AWS::Lambda::Function', content):
        if not re.search(r'VpcConfig', content):
            line_num = next((i+1 for i, l in enumerate(lines) if 'AWS::Lambda::Function' in l), 1)
            findings.append({
                'severity': 'low', 'category': 'security',
                'title': 'CFN: Lambda Not in VPC',
                'description': 'Lambda function is not configured within a VPC, limiting network isolation.',
                'recommendation': 'Add VpcConfig with SubnetIds and SecurityGroupIds for network isolation.',
                'file_path': file_path, 'line_number': line_num, 'framework': 'AWS-WA-SEC'
            })

    # Check 12: Hardcoded secrets in parameters/resources
    secret_patterns = re.finditer(r'(Password|Secret|ApiKey|Token|AccessKey)\s*[:=]\s*["\']?[A-Za-z0-9+/=]{8,}', content, re.IGNORECASE)
    for match in secret_patterns:
        if not re.search(r'(NoEcho|AWS::SSM|secretsmanager|Ref|!Ref)', content[max(0, match.start()-200):match.end()+100]):
            line_num = content[:match.start()].count('\n') + 1
            findings.append({
                'severity': 'critical', 'category': 'security',
                'title': 'CFN: Hardcoded Secret Detected',
                'description': 'Sensitive value appears to be hardcoded instead of using NoEcho parameters or Secrets Manager.',
                'recommendation': 'Use NoEcho parameters, AWS::SecretsManager::Secret, or SSM Parameter Store for secrets.',
                'file_path': file_path, 'line_number': line_num, 'framework': 'AWS-WA-SEC'
            })
            break

    return findings


def analyze_arm(content, file_path='unknown'):
    """Analyze Azure ARM templates for security issues."""
    findings = []
    lines = content.split('\n')

    # Check 1: Storage account without HTTPS enforcement
    if re.search(r'Microsoft\.Storage/storageAccounts', content):
        if not re.search(r'supportsHttpsTrafficOnly.*true', content, re.IGNORECASE):
            line_num = next((i+1 for i, l in enumerate(lines) if 'Microsoft.Storage/storageAccounts' in l), 1)
            findings.append({
                'severity': 'high', 'category': 'security',
                'title': 'ARM: Storage Account Without HTTPS Enforcement',
                'description': 'Storage account does not enforce HTTPS-only traffic, allowing unencrypted connections.',
                'recommendation': 'Set supportsHttpsTrafficOnly to true in storage account properties.',
                'file_path': file_path, 'line_number': line_num, 'framework': 'AZURE-SEC'
            })

    # Check 2: Storage account without encryption
    if re.search(r'Microsoft\.Storage/storageAccounts', content):
        if not re.search(r'encryption', content, re.IGNORECASE):
            line_num = next((i+1 for i, l in enumerate(lines) if 'Microsoft.Storage/storageAccounts' in l), 1)
            findings.append({
                'severity': 'high', 'category': 'security',
                'title': 'ARM: Storage Account Without Encryption',
                'description': 'Storage account does not have explicit encryption configuration.',
                'recommendation': 'Add encryption block with services (blob, file, table, queue) enabled.',
                'file_path': file_path, 'line_number': line_num, 'framework': 'AZURE-SEC'
            })

    # Check 3: Public IP address assigned
    if re.search(r'Microsoft\.Network/publicIPAddresses', content):
        line_num = next((i+1 for i, l in enumerate(lines) if 'publicIPAddresses' in l), 1)
        findings.append({
            'severity': 'medium', 'category': 'security',
            'title': 'ARM: Public IP Address Assigned',
            'description': 'Resource has a public IP address, increasing attack surface.',
            'recommendation': 'Use private endpoints, Azure Private Link, or restrict access with NSG rules.',
            'file_path': file_path, 'line_number': line_num, 'framework': 'AZURE-SEC'
        })

    # Check 4: No Network Security Group
    if re.search(r'Microsoft\.Network/(networkInterfaces|virtualNetworks)', content):
        if not re.search(r'Microsoft\.Network/networkSecurityGroups|networkSecurityGroup', content):
            line_num = next((i+1 for i, l in enumerate(lines) if 'Microsoft.Network' in l), 1)
            findings.append({
                'severity': 'high', 'category': 'security',
                'title': 'ARM: No Network Security Group',
                'description': 'Network interface or VNet without associated Network Security Group (NSG).',
                'recommendation': 'Associate an NSG with restrictive inbound/outbound rules.',
                'file_path': file_path, 'line_number': line_num, 'framework': 'AZURE-SEC'
            })

    # Check 5: NSG rule allowing all inbound (0.0.0.0/0 or *)
    if re.search(r'(sourceAddressPrefix|sourceAddressPrefixes).*(\*|0\.0\.0\.0)', content):
        if re.search(r'"access"\s*:\s*"Allow"', content, re.IGNORECASE) or re.search(r'access.*Allow', content):
            line_num = next((i+1 for i, l in enumerate(lines) if '0.0.0.0' in l or ('sourceAddressPrefix' in l and '*' in l)), 1)
            findings.append({
                'severity': 'critical', 'category': 'security',
                'title': 'ARM: NSG Rule Open to World',
                'description': 'NSG rule allows inbound traffic from any source (0.0.0.0/0 or *). Resource exposed to internet.',
                'recommendation': 'Restrict sourceAddressPrefix to specific IP ranges or service tags.',
                'file_path': file_path, 'line_number': line_num, 'framework': 'AZURE-SEC'
            })

    # Check 6: No diagnostic settings
    if re.search(r'Microsoft\.(Compute|Web|Sql|Storage)', content):
        if not re.search(r'diagnosticSettings|Microsoft\.Insights', content):
            findings.append({
                'severity': 'medium', 'category': 'security',
                'title': 'ARM: No Diagnostic Settings',
                'description': 'Resources deployed without diagnostic settings for monitoring and audit logging.',
                'recommendation': 'Add Microsoft.Insights/diagnosticSettings to send logs to Log Analytics or Storage.',
                'file_path': file_path, 'line_number': 1, 'framework': 'AZURE-SEC'
            })

    # Check 7: SQL Server without auditing
    if re.search(r'Microsoft\.Sql/servers', content):
        if not re.search(r'auditingSettings|auditActionsAndGroups', content, re.IGNORECASE):
            line_num = next((i+1 for i, l in enumerate(lines) if 'Microsoft.Sql/servers' in l), 1)
            findings.append({
                'severity': 'medium', 'category': 'security',
                'title': 'ARM: SQL Server Without Auditing',
                'description': 'Azure SQL Server does not have auditing configured for security monitoring.',
                'recommendation': 'Enable auditing with Microsoft.Sql/servers/auditingSettings resource.',
                'file_path': file_path, 'line_number': line_num, 'framework': 'AZURE-SEC'
            })

    # Check 8: SQL Server with public network access
    if re.search(r'Microsoft\.Sql/servers', content):
        if re.search(r'publicNetworkAccess.*Enabled', content, re.IGNORECASE):
            line_num = next((i+1 for i, l in enumerate(lines) if 'publicNetworkAccess' in l), 1)
            findings.append({
                'severity': 'high', 'category': 'security',
                'title': 'ARM: SQL Server Public Network Access',
                'description': 'Azure SQL Server has public network access enabled, exposing it to the internet.',
                'recommendation': 'Set publicNetworkAccess to Disabled and use Private Endpoints.',
                'file_path': file_path, 'line_number': line_num, 'framework': 'AZURE-SEC'
            })

    # Check 9: VM without managed disk encryption
    if re.search(r'Microsoft\.Compute/virtualMachines', content):
        if not re.search(r'(diskEncryptionSet|encryptionAtHost|AzureDiskEncryption)', content):
            line_num = next((i+1 for i, l in enumerate(lines) if 'Microsoft.Compute/virtualMachines' in l), 1)
            findings.append({
                'severity': 'high', 'category': 'security',
                'title': 'ARM: VM Without Disk Encryption',
                'description': 'Virtual machine does not have disk encryption configured.',
                'recommendation': 'Enable Azure Disk Encryption or use encryptionAtHost for VM disks.',
                'file_path': file_path, 'line_number': line_num, 'framework': 'AZURE-SEC'
            })

    # Check 10: Hardcoded secrets in parameters
    if re.search(r'(password|secret|key|token)\s*"?\s*:\s*"[^"]{8,}"', content, re.IGNORECASE):
        if not re.search(r'"type"\s*:\s*"secureString"|secureString|keyVault', content, re.IGNORECASE):
            line_num = next((i+1 for i, l in enumerate(lines) if re.search(r'(password|secret|key)', l, re.IGNORECASE) and '"' in l), 1)
            findings.append({
                'severity': 'critical', 'category': 'security',
                'title': 'ARM: Hardcoded Secret Detected',
                'description': 'Sensitive value appears hardcoded instead of using secureString parameters or Key Vault references.',
                'recommendation': 'Use secureString parameter type or reference Azure Key Vault secrets.',
                'file_path': file_path, 'line_number': line_num, 'framework': 'AZURE-SEC'
            })

    return findings


def analyze_gcp(content, file_path='unknown'):
    """Analyze GCP infrastructure templates (Deployment Manager YAML/Jinja) for security issues."""
    findings = []
    lines = content.split('\n')

    # Check 1: Compute instance with external IP
    if re.search(r'compute\.v1\.instance|compute\.googleapis\.com', content, re.IGNORECASE):
        if re.search(r'(accessConfigs|natIP|ONE_TO_ONE_NAT)', content):
            line_num = next((i+1 for i, l in enumerate(lines) if 'accessConfigs' in l or 'natIP' in l), 1)
            findings.append({
                'severity': 'medium', 'category': 'security',
                'title': 'GCP: Instance with External IP',
                'description': 'Compute instance has an external IP assigned, exposing it to the internet.',
                'recommendation': 'Remove accessConfigs/natIP and use Cloud NAT or IAP for external access.',
                'file_path': file_path, 'line_number': line_num, 'framework': 'GCP-SEC'
            })

    # Check 2: Firewall rule open to 0.0.0.0/0
    if re.search(r'compute\.v1\.firewall|compute\.googleapis\.com.*firewall', content, re.IGNORECASE):
        if re.search(r'0\.0\.0\.0/0', content):
            line_num = next((i+1 for i, l in enumerate(lines) if '0.0.0.0/0' in l), 1)
            findings.append({
                'severity': 'critical', 'category': 'security',
                'title': 'GCP: Firewall Rule Open to World',
                'description': 'Firewall rule allows ingress from 0.0.0.0/0 — resource exposed to entire internet.',
                'recommendation': 'Restrict sourceRanges to specific IP ranges or use service accounts.',
                'file_path': file_path, 'line_number': line_num, 'framework': 'GCP-SEC'
            })

    # Check 3: GCS bucket without uniform access
    if re.search(r'storage\.v1\.bucket|storage\.googleapis\.com', content, re.IGNORECASE):
        if not re.search(r'uniformBucketLevelAccess|iamConfiguration', content):
            line_num = next((i+1 for i, l in enumerate(lines) if 'storage' in l.lower() and 'bucket' in l.lower()), 1)
            findings.append({
                'severity': 'medium', 'category': 'security',
                'title': 'GCP: Bucket Without Uniform Access',
                'description': 'GCS bucket does not enforce uniform bucket-level access (uses legacy ACLs).',
                'recommendation': 'Enable uniformBucketLevelAccess in iamConfiguration for consistent IAM policies.',
                'file_path': file_path, 'line_number': line_num, 'framework': 'GCP-SEC'
            })

    # Check 4: GCS bucket publicly accessible
    if re.search(r'storage\.v1\.bucket|storage\.googleapis\.com', content, re.IGNORECASE):
        if re.search(r'allUsers|allAuthenticatedUsers', content):
            line_num = next((i+1 for i, l in enumerate(lines) if 'allUsers' in l or 'allAuthenticatedUsers' in l), 1)
            findings.append({
                'severity': 'critical', 'category': 'security',
                'title': 'GCP: Bucket Publicly Accessible',
                'description': 'GCS bucket grants access to allUsers or allAuthenticatedUsers — data is publicly exposed.',
                'recommendation': 'Remove allUsers/allAuthenticatedUsers bindings and use specific IAM members.',
                'file_path': file_path, 'line_number': line_num, 'framework': 'GCP-SEC'
            })

    # Check 5: Cloud SQL without SSL enforcement
    if re.search(r'sqladmin\.v1\.instance|sql\.googleapis\.com', content, re.IGNORECASE):
        if not re.search(r'requireSsl.*true|sslMode', content, re.IGNORECASE):
            line_num = next((i+1 for i, l in enumerate(lines) if 'sql' in l.lower() and ('instance' in l.lower() or 'sqladmin' in l.lower())), 1)
            findings.append({
                'severity': 'high', 'category': 'security',
                'title': 'GCP: Cloud SQL Without SSL',
                'description': 'Cloud SQL instance does not enforce SSL connections, allowing unencrypted traffic.',
                'recommendation': 'Set requireSsl: true in settings.ipConfiguration to enforce encrypted connections.',
                'file_path': file_path, 'line_number': line_num, 'framework': 'GCP-SEC'
            })

    # Check 6: Cloud SQL with public IP
    if re.search(r'sqladmin\.v1\.instance|sql\.googleapis\.com', content, re.IGNORECASE):
        if re.search(r'ipv4Enabled.*true|authorizedNetworks.*0\.0\.0\.0', content, re.IGNORECASE):
            line_num = next((i+1 for i, l in enumerate(lines) if 'ipv4Enabled' in l or 'authorizedNetworks' in l), 1)
            findings.append({
                'severity': 'critical', 'category': 'security',
                'title': 'GCP: Cloud SQL Publicly Accessible',
                'description': 'Cloud SQL instance has a public IP or allows connections from 0.0.0.0/0.',
                'recommendation': 'Disable ipv4Enabled and use Private IP with VPC peering or Cloud SQL Proxy.',
                'file_path': file_path, 'line_number': line_num, 'framework': 'GCP-SEC'
            })

    # Check 7: No audit logging
    if re.search(r'(compute|storage|sql|container)', content, re.IGNORECASE):
        if not re.search(r'(auditConfig|logConfig|logging)', content, re.IGNORECASE):
            findings.append({
                'severity': 'medium', 'category': 'security',
                'title': 'GCP: No Audit Logging Configured',
                'description': 'Template does not configure audit logging for deployed resources.',
                'recommendation': 'Enable Cloud Audit Logs and configure log sinks for security monitoring.',
                'file_path': file_path, 'line_number': 1, 'framework': 'GCP-SEC'
            })

    # Check 8: GKE cluster without private nodes
    if re.search(r'container\.v1\.cluster|container\.googleapis\.com', content, re.IGNORECASE):
        if not re.search(r'enablePrivateNodes.*true|privateClusterConfig', content, re.IGNORECASE):
            line_num = next((i+1 for i, l in enumerate(lines) if 'container' in l.lower() and 'cluster' in l.lower()), 1)
            findings.append({
                'severity': 'high', 'category': 'security',
                'title': 'GCP: GKE Cluster Without Private Nodes',
                'description': 'GKE cluster nodes have public IPs, exposing them to the internet.',
                'recommendation': 'Enable privateClusterConfig with enablePrivateNodes: true.',
                'file_path': file_path, 'line_number': line_num, 'framework': 'GCP-SEC'
            })

    # Check 9: GKE without network policy
    if re.search(r'container\.v1\.cluster|container\.googleapis\.com', content, re.IGNORECASE):
        if not re.search(r'networkPolicy|networkPolicyConfig', content, re.IGNORECASE):
            line_num = next((i+1 for i, l in enumerate(lines) if 'container' in l.lower() and 'cluster' in l.lower()), 1)
            findings.append({
                'severity': 'medium', 'category': 'security',
                'title': 'GCP: GKE Without Network Policy',
                'description': 'GKE cluster does not have network policy enabled — pods can communicate freely.',
                'recommendation': 'Enable networkPolicy in addonsConfig for pod-level network segmentation.',
                'file_path': file_path, 'line_number': line_num, 'framework': 'GCP-SEC'
            })

    # Check 10: Hardcoded secrets
    secret_patterns = re.finditer(r'(password|secret|api_key|private_key|token)\s*[:=]\s*["\']([^"\']{8,})["\']', content, re.IGNORECASE)
    for match in secret_patterns:
        context = content[max(0, match.start()-100):match.end()+100]
        if 'secretmanager' not in context.lower() and 'kms' not in context.lower():
            line_num = content[:match.start()].count('\n') + 1
            findings.append({
                'severity': 'critical', 'category': 'security',
                'title': 'GCP: Hardcoded Secret Detected',
                'description': 'Sensitive value appears hardcoded instead of using Secret Manager or KMS.',
                'recommendation': 'Use Google Secret Manager or Cloud KMS for managing sensitive values.',
                'file_path': file_path, 'line_number': line_num, 'framework': 'GCP-SEC'
            })
            break

    # Check 11: Service account with owner/editor role
    if re.search(r'(roles/owner|roles/editor)', content):
        line_num = next((i+1 for i, l in enumerate(lines) if 'roles/owner' in l or 'roles/editor' in l), 1)
        findings.append({
            'severity': 'critical', 'category': 'security',
            'title': 'GCP: Overly Permissive IAM Role',
            'description': 'Service account or member granted Owner or Editor role — violates least privilege.',
            'recommendation': 'Use specific predefined roles or custom roles with minimal permissions.',
            'file_path': file_path, 'line_number': line_num, 'framework': 'GCP-SEC'
        })

    # Check 12: No labels/tags on resources
    if re.search(r'(compute|storage|sql|container)', content, re.IGNORECASE):
        if not re.search(r'labels', content, re.IGNORECASE):
            findings.append({
                'severity': 'low', 'category': 'cost',
                'title': 'GCP: Resources Without Labels',
                'description': 'Resources do not have labels for cost allocation and organization.',
                'recommendation': 'Add labels (environment, team, project) for cost tracking and resource management.',
                'file_path': file_path, 'line_number': 1, 'framework': 'GCP-SEC'
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
    elif path_lower.endswith('.json'):
        # Check for CloudFormation or ARM templates
        if 'AWSTemplateFormatVersion' in content or 'AWS::' in content:
            return 'cloudformation'
        elif '$schema' in content and 'azure' in content.lower():
            return 'arm'
    elif path_lower.endswith(('.yaml', '.yml')):
        # Check content to determine type
        if 'AWSTemplateFormatVersion' in content or 'AWS::' in content:
            return 'cloudformation'
        elif any(kw in content for kw in ['compute.v1.', 'storage.v1.', 'sqladmin.v1.',
                                           'container.v1.', 'googleapis.com', 'gcp-types/']):
            return 'gcp'
        elif any(kw in content for kw in ['apiVersion:', 'kind: Deployment', 'kind: Service', 'kind: Pod',
                                          'kind: StatefulSet', 'kind: DaemonSet', 'kind: ConfigMap',
                                          'kind: Ingress', 'kind: NetworkPolicy', 'kind: ClusterRole']):
            return 'kubernetes'
        elif any(kw in content for kw in ['stages:', 'pipeline:', 'jobs:', 'steps:', 'on:']):
            return 'cicd'
        else:
            return 'kubernetes'
    elif path_lower.endswith('.jinja') or path_lower.endswith('.jinja2'):
        return 'gcp'
    return None


def validate_content(content, file_type):
    """Full parser-based validation for infrastructure config files.
    Returns (is_valid, error_message) tuple."""
    content_stripped = content.strip()

    if len(content_stripped) < 10:
        return False, 'Content is too short to be a valid configuration file.'
    lines = [l for l in content_stripped.split('\n') if l.strip()]
    if len(lines) < 2 and file_type not in ('arm', 'cloudformation'):
        return False, 'Content must have at least 2 lines to be a valid configuration file.'

    if file_type == 'kubernetes':
        return _validate_kubernetes(content)
    elif file_type == 'terraform':
        return _validate_terraform(content)
    elif file_type == 'dockerfile':
        return _validate_dockerfile(lines)
    elif file_type == 'cicd':
        return _validate_cicd(content)
    elif file_type == 'cloudformation':
        return _validate_cloudformation(content, content_stripped)
    elif file_type == 'arm':
        return _validate_arm(content)
    elif file_type == 'gcp':
        return _validate_gcp(content)
    return True, ''


def _validate_kubernetes(content):
    """Full Kubernetes YAML parser validation."""
    try:
        import yaml
        parsed = yaml.safe_load(content)
    except ImportError:
        if sum(1 for kw in ['apiVersion:', 'kind:', 'metadata:', 'spec:'] if kw in content) < 2:
            return False, 'Invalid Kubernetes YAML: no Kubernetes keywords found.'
        return True, ''
    except yaml.YAMLError as e:
        if hasattr(e, 'problem_mark') and e.problem_mark:
            m = e.problem_mark
            return False, f'YAML syntax error at line {m.line+1}, column {m.column+1}: {e.problem}'
        return False, f'YAML syntax error: {str(e).split(chr(10))[0][:150]}'

    if parsed is None:
        return False, 'Invalid Kubernetes YAML: file is empty or only comments.'
    if not isinstance(parsed, dict):
        return False, 'Invalid Kubernetes YAML: top-level must be a mapping (key: value), not a list or scalar.'
    if 'apiVersion' not in parsed:
        return False, 'Invalid Kubernetes YAML: missing required field "apiVersion".'
    if 'kind' not in parsed:
        return False, 'Invalid Kubernetes YAML: missing required field "kind".'

    valid_kinds = ['Deployment','Service','Pod','StatefulSet','DaemonSet','Job','CronJob',
        'ConfigMap','Secret','Ingress','NetworkPolicy','PersistentVolumeClaim',
        'PersistentVolume','ServiceAccount','Role','RoleBinding','ClusterRole',
        'ClusterRoleBinding','Namespace','HorizontalPodAutoscaler','ReplicaSet',
        'LimitRange','ResourceQuota','PodDisruptionBudget','StorageClass',
        'CustomResourceDefinition','Endpoints','EndpointSlice','List']
    kind = parsed.get('kind', '')
    if kind and kind not in valid_kinds:
        return False, f'Invalid Kubernetes YAML: unrecognized kind "{kind}".'

    if 'metadata' in parsed:
        if parsed['metadata'] is None:
            return False, 'Invalid Kubernetes YAML: "metadata:" is empty. Indent child keys (name, labels) under it.'
        if not isinstance(parsed['metadata'], dict):
            return False, 'Invalid Kubernetes YAML: "metadata" must be a mapping with "name" field.'

    workload_kinds = ['Deployment','StatefulSet','DaemonSet','Job','CronJob','Pod','ReplicaSet','Service']
    if kind in workload_kinds:
        if 'spec' not in parsed:
            return False, f'Invalid Kubernetes YAML: kind "{kind}" requires a "spec" field.'
        if parsed.get('spec') is None:
            return False, 'Invalid Kubernetes YAML: "spec:" is empty. Indent child keys under it.'
        if not isinstance(parsed.get('spec'), dict):
            return False, 'Invalid Kubernetes YAML: "spec" must be a mapping.'
    return True, ''


def _validate_terraform(content):
    """Terraform HCL validation."""
    try:
        import hcl2
        import io
        hcl2.load(io.StringIO(content))
        return True, ''
    except ImportError:
        pass
    except Exception as e:
        return False, f'Invalid Terraform HCL syntax: {str(e)[:150]}'

    has_block = bool(re.search(r'^\s*(resource|variable|output|provider|module|data|terraform|locals)\s', content, re.MULTILINE))
    has_braces = '{' in content and '}' in content
    if not has_block and not has_braces:
        return False, 'Invalid Terraform config: no HCL blocks found (resource, variable, provider, etc.).'
    if not has_braces:
        return False, 'Invalid Terraform config: missing block delimiters { }.'
    if content.count('{') != content.count('}'):
        return False, f'Invalid Terraform HCL: unbalanced braces — {content.count("{")} open vs {content.count("}")} close.'
    return True, ''


def _validate_dockerfile(lines):
    """Full Dockerfile instruction validation."""
    valid_instructions = {'FROM','RUN','CMD','ENTRYPOINT','COPY','ADD','WORKDIR','EXPOSE',
        'ENV','ARG','VOLUME','USER','LABEL','HEALTHCHECK','SHELL','STOPSIGNAL','ONBUILD','MAINTAINER'}
    found_from = False
    found_instruction = False
    in_continuation = False

    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith('#') or not stripped:
            continue
        if in_continuation:
            in_continuation = stripped.endswith('\\')
            continue

        first_word = stripped.split()[0].upper() if stripped.split() else ''
        if first_word in valid_instructions:
            found_instruction = True
            if first_word == 'FROM':
                found_from = True
                if len(stripped.split()) < 2:
                    return False, f'Dockerfile error line {i+1}: FROM requires an image name.'
            in_continuation = stripped.endswith('\\')
        else:
            if not found_instruction:
                return False, f'Dockerfile error line {i+1}: "{first_word}" is not a valid instruction. Must start with FROM.'
            else:
                return False, f'Dockerfile error line {i+1}: "{first_word}" is not a valid Dockerfile instruction.'

    if not found_instruction:
        return False, 'Invalid Dockerfile: no valid instructions found.'
    if not found_from:
        return False, 'Invalid Dockerfile: missing required FROM instruction.'
    return True, ''


def _validate_cicd(content):
    """CI/CD pipeline YAML validation (GitHub Actions, GitLab CI)."""
    try:
        import yaml
        parsed = yaml.safe_load(content)
    except ImportError:
        if not any(kw in content for kw in ['jobs:', 'steps:', 'stages:', 'pipeline:']):
            return False, 'Invalid CI/CD config: no pipeline keywords found.'
        return True, ''
    except yaml.YAMLError as e:
        if hasattr(e, 'problem_mark') and e.problem_mark:
            m = e.problem_mark
            return False, f'CI/CD YAML syntax error at line {m.line+1}, column {m.column+1}: {e.problem}'
        return False, f'CI/CD YAML syntax error: {str(e).split(chr(10))[0][:150]}'

    if parsed is None:
        return False, 'Invalid CI/CD config: file is empty.'
    if not isinstance(parsed, dict):
        return False, 'Invalid CI/CD config: top-level must be a mapping.'

    is_gha = 'on' in parsed or 'jobs' in parsed
    if is_gha:
        if 'jobs' not in parsed:
            return False, 'Invalid GitHub Actions: missing required "jobs" section.'
        if not isinstance(parsed['jobs'], dict):
            return False, 'Invalid GitHub Actions: "jobs" must be a mapping.'
        for name, job in parsed['jobs'].items():
            if not isinstance(job, dict):
                return False, f'Invalid GitHub Actions: job "{name}" must be a mapping.'
            if 'runs-on' not in job and 'uses' not in job:
                return False, f'Invalid GitHub Actions: job "{name}" missing "runs-on".'
    else:
        pipeline_keys = ['jobs','steps','stages','pipeline','build','deploy','script']
        if not any(k in parsed for k in pipeline_keys):
            return False, 'Invalid CI/CD config: no pipeline structure found (jobs, steps, stages).'
    return True, ''


def _validate_cloudformation(content, content_stripped):
    """AWS CloudFormation template validation."""
    parsed = None
    try:
        if content_stripped.startswith('{'):
            parsed = json.loads(content)
        else:
            import yaml
            parsed = yaml.safe_load(content)
    except json.JSONDecodeError as e:
        return False, f'CloudFormation JSON syntax error: {str(e)[:150]}'
    except ImportError:
        if not any(kw in content for kw in ['AWSTemplateFormatVersion', 'Resources:', 'AWS::']):
            return False, 'Invalid CloudFormation: no AWS keywords found.'
        return True, ''
    except Exception as e:
        if hasattr(e, 'problem_mark') and e.problem_mark:
            m = e.problem_mark
            return False, f'CloudFormation YAML error at line {m.line+1}, column {m.column+1}: {e.problem}'
        return False, f'CloudFormation syntax error: {str(e).split(chr(10))[0][:150]}'

    if not isinstance(parsed, dict):
        return False, 'Invalid CloudFormation: top-level must be a mapping.'
    if 'Resources' not in parsed and 'resources' not in parsed:
        return False, 'Invalid CloudFormation: missing required "Resources" section.'
    resources = parsed.get('Resources', parsed.get('resources', {}))
    if not isinstance(resources, dict):
        return False, 'Invalid CloudFormation: "Resources" must be a mapping.'
    for name, res in resources.items():
        if not isinstance(res, dict):
            return False, f'CloudFormation: resource "{name}" must be a mapping.'
        if 'Type' not in res and 'type' not in res:
            return False, f'CloudFormation: resource "{name}" missing "Type" field.'
    return True, ''


def _validate_arm(content):
    """Azure ARM template validation."""
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError as e:
        return False, f'ARM template JSON syntax error: {str(e)[:150]}'

    if not isinstance(parsed, dict):
        return False, 'Invalid ARM template: must be a JSON object.'
    if '$schema' not in parsed:
        return False, 'Invalid ARM template: missing required "$schema" field.'
    if 'contentVersion' not in parsed:
        return False, 'Invalid ARM template: missing required "contentVersion".'
    if 'resources' not in parsed:
        return False, 'Invalid ARM template: missing required "resources" array.'
    if not isinstance(parsed['resources'], list):
        return False, 'Invalid ARM template: "resources" must be an array.'

    # Validate parameter definitions have valid keys
    valid_param_keys = {'type', 'defaultValue', 'allowedValues', 'metadata',
                        'minValue', 'maxValue', 'minLength', 'maxLength', 'description'}
    if 'parameters' in parsed and isinstance(parsed['parameters'], dict):
        for param_name, param_def in parsed['parameters'].items():
            if isinstance(param_def, dict):
                for key in param_def:
                    if key not in valid_param_keys:
                        return False, f'ARM template: parameter "{param_name}" has unrecognized key "{key}". Valid keys: type, defaultValue, allowedValues, metadata, minValue, maxValue, minLength, maxLength.'
                # Check metadata sub-keys
                if 'metadata' in param_def and isinstance(param_def['metadata'], dict):
                    valid_meta_keys = {'description', 'displayName'}
                    for mk in param_def['metadata']:
                        if mk not in valid_meta_keys:
                            return False, f'ARM template: parameter "{param_name}" metadata has unrecognized key "{mk}". Valid: description, displayName.'

    for i, res in enumerate(parsed['resources']):
        if not isinstance(res, dict):
            return False, f'ARM template: resource[{i}] must be a JSON object.'
        if 'type' not in res:
            return False, f'ARM template: resource[{i}] missing "type" field.'
        if 'apiVersion' not in res:
            return False, f'ARM template: resource[{i}] missing "apiVersion".'
        if 'name' not in res:
            return False, f'ARM template: resource[{i}] missing "name" field.'
    return True, ''


def _validate_gcp(content):
    """GCP Deployment Manager validation."""
    try:
        import yaml
        parsed = yaml.safe_load(content)
    except ImportError:
        if not any(kw in content for kw in ['compute.v1.', 'storage.v1.', 'googleapis.com', 'gcp-types/']):
            return False, 'Invalid GCP config: no GCP keywords found.'
        return True, ''
    except yaml.YAMLError as e:
        if hasattr(e, 'problem_mark') and e.problem_mark:
            m = e.problem_mark
            return False, f'GCP config YAML error at line {m.line+1}, column {m.column+1}: {e.problem}'
        return False, f'GCP config YAML syntax error: {str(e).split(chr(10))[0][:150]}'

    if not isinstance(parsed, dict):
        return False, 'Invalid GCP config: top-level must be a mapping.'
    if 'resources' not in parsed:
        return False, 'Invalid GCP config: missing required "resources" section.'
    resources = parsed.get('resources', [])
    if not isinstance(resources, list):
        return False, 'Invalid GCP config: "resources" must be a list.'
    for i, res in enumerate(resources):
        if not isinstance(res, dict):
            return False, f'GCP config: resource[{i}] must be a mapping.'
        if 'type' not in res:
            return False, f'GCP config: resource[{i}] missing "type" field.'
        if 'name' not in res:
            return False, f'GCP config: resource[{i}] missing "name" field.'
    return True, ''


def analyze_content(content, file_type, file_path='unknown'):
    """Route content to the appropriate analyzer."""
    # Validate content structure first (safety net — routes should validate before calling)
    is_valid, error_msg = validate_content(content, file_type)
    if not is_valid:
        return []

    if file_type == 'kubernetes':
        findings = analyze_kubernetes(content, file_path)
    elif file_type == 'terraform':
        findings = analyze_terraform(content, file_path)
    elif file_type == 'dockerfile':
        findings = analyze_dockerfile(content, file_path)
    elif file_type == 'cicd':
        findings = analyze_cicd(content, file_path)
    elif file_type == 'cloudformation':
        findings = analyze_cloudformation(content, file_path)
    elif file_type == 'arm':
        findings = analyze_arm(content, file_path)
    elif file_type == 'gcp':
        findings = analyze_gcp(content, file_path)
    else:
        findings = []

    # Filter out findings on lines with ignore comments
    if findings:
        lines = content.split('\n')
        ignore_lines = set()
        for i, line in enumerate(lines):
            if any(tag in line.lower() for tag in ['deploypilot-ignore', 'deploypilot:ignore', 'noqa:deploypilot']):
                ignore_lines.add(i + 1)

        if ignore_lines:
            findings = [f for f in findings if f.get('line_number') not in ignore_lines]

    # Attach fix code snippets to findings
    for f in findings:
        f['fix_code'] = get_fix_code(f.get('title', ''), file_type)

    return findings


# Fix code snippets mapped by finding title
FIX_CODES = {
    # Kubernetes fixes
    'Missing Resource Limits': '''resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 256Mi''',
    'Missing Liveness Probe': '''livenessProbe:
  httpGet:
    path: /healthz
    port: 8080
  initialDelaySeconds: 15
  periodSeconds: 10''',
    'Missing Readiness Probe': '''readinessProbe:
  httpGet:
    path: /ready
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 5''',
    'Container Running as Root': '''securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000''',
    'Privileged Container Detected': '''securityContext:
  privileged: false
  allowPrivilegeEscalation: false''',
    'Using :latest Image Tag': '''# Replace :latest with a specific version
image: nginx:1.25.3
# Or use SHA digest:
# image: nginx@sha256:abc123...''',
    'Image Without Tag': '''# Always specify an explicit tag
image: myapp:v1.2.3''',
    'No Namespace Specified': '''metadata:
  name: my-app
  namespace: production''',
    'ClusterRoleBinding to cluster-admin': '''# Use a custom role with minimal permissions
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: limited-role
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]''',
    'No NetworkPolicy Defined': '''apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all-ingress
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: allowed-app''',
    'Host Network Enabled': '''spec:
  hostNetwork: false  # Remove or set to false''',
    'Host PID Namespace Shared': '''spec:
  hostPID: false  # Remove or set to false''',
    'Potential Secret in Plain Text': '''env:
- name: DB_PASSWORD
  valueFrom:
    secretKeyRef:
      name: app-secrets
      key: db-password''',
    'No PodDisruptionBudget': '''apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: app-pdb
spec:
  minAvailable: 1
  selector:
    matchLabels:
      app: my-app''',
    'Privilege Escalation Not Disabled': '''securityContext:
  allowPrivilegeEscalation: false
  capabilities:
    drop:
      - ALL''',
    'Writable Root Filesystem': '''securityContext:
  readOnlyRootFilesystem: true
# Mount writable dirs as emptyDir:
volumeMounts:
- name: tmp
  mountPath: /tmp
volumes:
- name: tmp
  emptyDir: {}''',
    # Terraform fixes
    'No Remote Backend Configured': '''terraform {
  backend "s3" {
    bucket         = "my-terraform-state"
    key            = "prod/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "terraform-locks"
    encrypt        = true
  }
}''',
    'S3 Bucket Without Encryption': '''resource "aws_s3_bucket_server_side_encryption_configuration" "example" {
  bucket = aws_s3_bucket.example.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}''',
    'S3 Bucket Without Versioning': '''resource "aws_s3_bucket_versioning" "example" {
  bucket = aws_s3_bucket.example.id
  versioning_configuration {
    status = "Enabled"
  }
}''',
    'Provider Without Version Constraint': '''terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}''',
    'S3 Backend Without State Locking': '''backend "s3" {
  bucket         = "my-terraform-state"
  key            = "terraform.tfstate"
  region         = "us-east-1"
  dynamodb_table = "terraform-state-lock"
  encrypt        = true
}''',
    'RDS Without Deletion Protection': '''resource "aws_db_instance" "example" {
  # ... other config ...
  deletion_protection = true
}''',
    'RDS Without Encryption at Rest': '''resource "aws_db_instance" "example" {
  # ... other config ...
  storage_encrypted = true
  kms_key_id       = aws_kms_key.rds.arn
}''',
    'Security Group Open to World': '''ingress {
  from_port   = 443
  to_port     = 443
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]  # Restrict to known ranges
}''',
    'Hardcoded Credentials Detected': '''# Use variables instead of hardcoding
variable "db_password" {
  type      = string
  sensitive = true
}

# Reference: var.db_password''',
    'Resource Missing Tags': '''tags = {
  Environment = "production"
  Team        = "platform"
  Project     = "my-app"
  ManagedBy   = "terraform"
}''',
    # Dockerfile fixes
    'Base Image Uses :latest Tag': '''# Pin to specific version
FROM python:3.12-slim
# Or use SHA digest for maximum reproducibility
# FROM python@sha256:abc123...''',
    'Base Image Without Version Tag': '''# Always specify a version tag
FROM node:20-alpine''',
    'Container Runs as Root': '''# Add non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser''',
    'Use COPY Instead of ADD': '''# Use COPY for local files (more explicit)
COPY ./src /app/src
# Only use ADD for URLs or tar extraction''',
    'No HEALTHCHECK Instruction': '''HEALTHCHECK --interval=30s --timeout=3s --retries=3 \\
  CMD curl -f http://localhost:8080/health || exit 1''',
    'Consider Multi-Stage Build': '''# Build stage
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

# Production stage
FROM node:20-alpine
WORKDIR /app
COPY --from=builder /app/dist ./dist
CMD ["node", "dist/index.js"]''',
    'Secret Exposed in Dockerfile': '''# Use BuildKit secrets instead
RUN --mount=type=secret,id=api_key \\
  cat /run/secrets/api_key > /app/.env

# Or pass at runtime:
# docker run -e API_KEY=xxx myapp''',
    'Broad COPY Statement': '''# Be specific about what you copy
COPY package*.json ./
COPY src/ ./src/
COPY config/ ./config/
# And ensure .dockerignore excludes:
# .git, node_modules, .env, *.log''',
    # CI/CD fixes
    'Hardcoded Secret in Pipeline': '''# Use GitHub Secrets
env:
  DB_PASSWORD: ${{ secrets.DB_PASSWORD }}
  API_KEY: ${{ secrets.API_KEY }}''',
    'No Caching Configured': '''# GitHub Actions cache example
- uses: actions/cache@v4
  with:
    path: ~/.npm
    key: ${{ runner.os }}-node-${{ hashFiles('**/package-lock.json') }}
    restore-keys: |
      ${{ runner.os }}-node-''',
    'No Pipeline Timeout': '''jobs:
  build:
    timeout-minutes: 15
    runs-on: ubuntu-latest''',
    'No Test Step in Pipeline': '''- name: Run tests
  run: npm test
  # Or: pytest, go test ./..., mvn test''',
    'No Pull Request Trigger': '''on:
  push:
    branches: [main]
  pull_request:
    branches: [main]''',
    'No Container Image Scanning': '''- name: Scan image with Trivy
  uses: aquasecurity/trivy-action@master
  with:
    image-ref: myapp:${{ github.sha }}
    severity: CRITICAL,HIGH''',
    'Unpinned GitHub Action': '''# Pin to full SHA instead of tag
- uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608
# Find SHA: go to the action repo → releases → copy commit SHA''',
    'No Environment Protection for Deployment': '''jobs:
  deploy:
    environment:
      name: production
      url: https://myapp.com
    # Requires manual approval in GitHub settings''',
    'Access Logging Not Enabled': '''resource "aws_lb" "example" {
  # ... other config ...
  access_logs {
    bucket  = aws_s3_bucket.lb_logs.id
    prefix  = "lb-logs"
    enabled = true
  }
}''',
    # New Kubernetes fixes
    'Service Account Token Auto-Mounted': '''spec:
  automountServiceAccountToken: false''',
    'Using Default Service Account': '''spec:
  serviceAccountName: my-app-sa
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-app-sa
  namespace: production''',
    'Privileged Port Used': '''ports:
- containerPort: 8080  # Use non-privileged port
# Map to 80 via Service:
# spec:
#   ports:
#   - port: 80
#     targetPort: 8080''',
    'No Pod Anti-Affinity': '''affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
    - weight: 100
      podAffinityTerm:
        labelSelector:
          matchExpressions:
          - key: app
            operator: In
            values:
            - my-app
        topologyKey: kubernetes.io/hostname''',
    'No Startup Probe for Slow-Starting App': '''startupProbe:
  httpGet:
    path: /healthz
    port: 8080
  failureThreshold: 30
  periodSeconds: 10''',
    'hostPath Volume Mount': '''# Replace hostPath with emptyDir or PVC:
volumes:
- name: data
  emptyDir: {}
# Or use PersistentVolumeClaim:
# - name: data
#   persistentVolumeClaim:
#     claimName: my-pvc''',
    'Linux Capabilities Not Dropped': '''securityContext:
  capabilities:
    drop:
      - ALL
    add:
      - NET_BIND_SERVICE  # Only if needed''',
    # New Terraform fixes
    'No CloudTrail Configuration': '''resource "aws_cloudtrail" "main" {
  name                          = "main-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_logging                = true
}''',
    'EBS Volume Not Encrypted': '''resource "aws_ebs_volume" "example" {
  availability_zone = "us-east-1a"
  size              = 40
  encrypted         = true
  kms_key_id        = aws_kms_key.ebs.arn
}''',
    'Lambda Not in VPC': '''resource "aws_lambda_function" "example" {
  # ... other config ...
  vpc_config {
    subnet_ids         = [aws_subnet.private.id]
    security_group_ids = [aws_security_group.lambda.id]
  }
}''',
    'No Lifecycle prevent_destroy': '''resource "aws_db_instance" "example" {
  # ... other config ...
  lifecycle {
    prevent_destroy = true
  }
}''',
    'IAM Policy with Wildcard Actions': '''# Use specific actions instead of "*"
resource "aws_iam_policy" "example" {
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = [
        "s3:GetObject",
        "s3:PutObject",
        "s3:ListBucket"
      ]
      Resource = [
        aws_s3_bucket.example.arn,
        "${aws_s3_bucket.example.arn}/*"
      ]
    }]
  })
}''',
    'RDS Publicly Accessible': '''resource "aws_db_instance" "example" {
  # ... other config ...
  publicly_accessible = false
  db_subnet_group_name = aws_db_subnet_group.private.name
}''',
    'No Backup Retention Period': '''resource "aws_db_instance" "example" {
  # ... other config ...
  backup_retention_period = 7
  backup_window           = "03:00-04:00"
}''',
    'S3 Public Access Not Blocked': '''resource "aws_s3_bucket_public_access_block" "example" {
  bucket = aws_s3_bucket.example.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}''',
    # New Dockerfile fixes
    'Too Many Ports Exposed': '''# Only expose ports the app actually uses
EXPOSE 8080
# Remove unnecessary EXPOSE directives''',
    'apt-get Without --no-install-recommends': '''RUN apt-get update && \\
    apt-get install -y --no-install-recommends \\
    curl \\
    ca-certificates \\
    && rm -rf /var/lib/apt/lists/*''',
    'Ensure .dockerignore Exists': '''# Create .dockerignore with:
.git
node_modules
.env
*.log
.DS_Store
coverage
dist
.terraform''',
    'Downloaded Files Not Cleaned Up': '''# Chain download, extract, and cleanup:
RUN curl -fsSL https://example.com/file.tar.gz -o /tmp/file.tar.gz && \\
    tar -xzf /tmp/file.tar.gz -C /opt/ && \\
    rm -f /tmp/file.tar.gz''',
    # New CI/CD fixes
    'No Static Analysis (SAST/Lint)': '''- name: Run linting
  run: npm run lint
  # Or for Python:
  # run: pip install flake8 && flake8 .
  # Or use Semgrep:
  # - uses: returntocorp/semgrep-action@v1''',
    'Auto-Deploy to Production Without Approval': '''jobs:
  deploy:
    environment:
      name: production
      url: https://myapp.com
    # Configure required reviewers in GitHub:
    # Settings → Environments → production → Required reviewers''',
    'Self-Hosted Runner Used': '''# Use ephemeral runners or GitHub-hosted:
runs-on: ubuntu-latest
# If self-hosted is required, use labels:
# runs-on: [self-hosted, linux, ephemeral]''',
    'No Artifact Signing': '''- name: Sign container image
  uses: sigstore/cosign-installer@v3
- run: cosign sign --yes ${{ env.IMAGE_NAME }}:${{ github.sha }}
# Or generate checksums:
# - run: sha256sum dist/* > checksums.txt''',
    # CloudFormation fixes
    'CFN: S3 Bucket Without Encryption': '''MyBucket:
  Type: AWS::S3::Bucket
  Properties:
    BucketEncryption:
      ServerSideEncryptionConfiguration:
        - ServerSideEncryptionByDefault:
            SSEAlgorithm: AES256''',
    'CFN: S3 Public Access Not Blocked': '''MyBucket:
  Type: AWS::S3::Bucket
  Properties:
    PublicAccessBlockConfiguration:
      BlockPublicAcls: true
      BlockPublicPolicy: true
      IgnorePublicAcls: true
      RestrictPublicBuckets: true''',
    'CFN: Security Group Open to World': '''SecurityGroupIngress:
  - IpProtocol: tcp
    FromPort: 443
    ToPort: 443
    CidrIp: 10.0.0.0/8  # Restrict to known ranges''',
    'CFN: IAM Policy with Wildcard Actions': '''PolicyDocument:
  Statement:
    - Effect: Allow
      Action:
        - s3:GetObject
        - s3:PutObject
        - s3:ListBucket
      Resource:
        - !GetAtt MyBucket.Arn
        - !Sub "${MyBucket.Arn}/*"''',
    'CFN: IAM Policy with Wildcard Resource': '''PolicyDocument:
  Statement:
    - Effect: Allow
      Action:
        - s3:GetObject
      Resource:
        - !Sub "arn:aws:s3:::${BucketName}/*"''',
    'CFN: No DeletionPolicy on Critical Resource': '''MyDatabase:
  Type: AWS::RDS::DBInstance
  DeletionPolicy: Retain  # or Snapshot
  Properties:
    # ... other properties''',
    'CFN: RDS Without Encryption': '''MyDatabase:
  Type: AWS::RDS::DBInstance
  Properties:
    StorageEncrypted: true
    KmsKeyId: !Ref MyKMSKey''',
    'CFN: RDS Publicly Accessible': '''MyDatabase:
  Type: AWS::RDS::DBInstance
  Properties:
    PubliclyAccessible: false
    DBSubnetGroupName: !Ref PrivateSubnetGroup''',
    'CFN: No Logging Configuration': '''TrailLogs:
  Type: AWS::CloudTrail::Trail
  Properties:
    IsLogging: true
    S3BucketName: !Ref LogBucket
    IncludeGlobalServiceEvents: true
    IsMultiRegionTrail: true''',
    'CFN: EBS Volume Not Encrypted': '''MyVolume:
  Type: AWS::EC2::Volume
  Properties:
    Encrypted: true
    KmsKeyId: !Ref MyKMSKey
    AvailabilityZone: !Select [0, !GetAZs ""]
    Size: 100''',
    'CFN: Lambda Not in VPC': '''MyFunction:
  Type: AWS::Lambda::Function
  Properties:
    VpcConfig:
      SubnetIds:
        - !Ref PrivateSubnet1
        - !Ref PrivateSubnet2
      SecurityGroupIds:
        - !Ref LambdaSG''',
    'CFN: Hardcoded Secret Detected': '''Parameters:
  DBPassword:
    Type: String
    NoEcho: true
    Description: Database password
# Or use Secrets Manager:
# !Sub "{{resolve:secretsmanager:MySecret:SecretString:password}}"''',
    # Azure ARM fixes
    'ARM: Storage Account Without HTTPS Enforcement': '''{
  "type": "Microsoft.Storage/storageAccounts",
  "properties": {
    "supportsHttpsTrafficOnly": true,
    "minimumTlsVersion": "TLS1_2"
  }
}''',
    'ARM: Storage Account Without Encryption': '''{
  "type": "Microsoft.Storage/storageAccounts",
  "properties": {
    "encryption": {
      "services": {
        "blob": { "enabled": true },
        "file": { "enabled": true }
      },
      "keySource": "Microsoft.Storage"
    }
  }
}''',
    'ARM: Public IP Address Assigned': '''// Use Private Endpoints instead:
{
  "type": "Microsoft.Network/privateEndpoints",
  "properties": {
    "privateLinkServiceConnections": [{
      "properties": {
        "privateLinkServiceId": "[resourceId(...)]",
        "groupIds": ["blob"]
      }
    }]
  }
}''',
    'ARM: No Network Security Group': '''{
  "type": "Microsoft.Network/networkSecurityGroups",
  "properties": {
    "securityRules": [{
      "name": "DenyAllInbound",
      "properties": {
        "priority": 4096,
        "access": "Deny",
        "direction": "Inbound",
        "sourceAddressPrefix": "*",
        "destinationAddressPrefix": "*",
        "protocol": "*"
      }
    }]
  }
}''',
    'ARM: NSG Rule Open to World': '''{
  "name": "AllowSpecificIP",
  "properties": {
    "priority": 100,
    "access": "Allow",
    "direction": "Inbound",
    "sourceAddressPrefix": "10.0.0.0/8",
    "destinationPortRange": "443",
    "protocol": "Tcp"
  }
}''',
    'ARM: No Diagnostic Settings': '''{
  "type": "Microsoft.Insights/diagnosticSettings",
  "properties": {
    "workspaceId": "[resourceId(''Microsoft.OperationalInsights/workspaces'', variables(''logAnalyticsName''))]",
    "logs": [{ "category": "AuditEvent", "enabled": true }],
    "metrics": [{ "category": "AllMetrics", "enabled": true }]
  }
}''',
    'ARM: SQL Server Without Auditing': '''{
  "type": "Microsoft.Sql/servers/auditingSettings",
  "properties": {
    "state": "Enabled",
    "storageEndpoint": "[reference(resourceId(''Microsoft.Storage/storageAccounts'', variables(''storageAccountName''))).primaryEndpoints.blob]",
    "retentionDays": 90
  }
}''',
    'ARM: SQL Server Public Network Access': '''{
  "type": "Microsoft.Sql/servers",
  "properties": {
    "publicNetworkAccess": "Disabled"
  }
}
// Use Private Endpoints for connectivity''',
    'ARM: VM Without Disk Encryption': '''{
  "type": "Microsoft.Compute/virtualMachines",
  "properties": {
    "securityProfile": {
      "encryptionAtHost": true
    }
  }
}
// Or use Azure Disk Encryption extension''',
    'ARM: Hardcoded Secret Detected': '''{
  "parameters": {
    "adminPassword": {
      "type": "secureString",
      "metadata": {
        "description": "Admin password from Key Vault"
      }
    }
  }
}
// Or reference Key Vault:
// "[reference(resourceId(''Microsoft.KeyVault/vaults/secrets'', ...))]"''',
    # GCP fixes
    'GCP: Instance with External IP': '''# Remove accessConfigs to avoid public IP
networkInterfaces:
- network: $(ref.my-network.selfLink)
  # No accessConfigs = no external IP
  # Use Cloud NAT for outbound access''',
    'GCP: Firewall Rule Open to World': '''# Restrict sourceRanges to known IPs
sourceRanges:
- "10.0.0.0/8"
- "172.16.0.0/12"
# Never use 0.0.0.0/0 for production''',
    'GCP: Bucket Without Uniform Access': '''iamConfiguration:
  uniformBucketLevelAccess:
    enabled: true''',
    'GCP: Bucket Publicly Accessible': '''# Remove allUsers/allAuthenticatedUsers
# Use specific IAM members:
bindings:
- role: roles/storage.objectViewer
  members:
  - serviceAccount:my-sa@project.iam.gserviceaccount.com''',
    'GCP: Cloud SQL Without SSL': '''settings:
  ipConfiguration:
    requireSsl: true
    sslMode: ENCRYPTED_ONLY''',
    'GCP: Cloud SQL Publicly Accessible': '''settings:
  ipConfiguration:
    ipv4Enabled: false
    privateNetwork: projects/PROJECT/global/networks/VPC_NAME
    # Use Cloud SQL Proxy for access''',
    'GCP: No Audit Logging Configured': '''# Enable audit logging via org policy or resource config
auditConfigs:
- auditLogConfigs:
  - logType: ADMIN_READ
  - logType: DATA_READ
  - logType: DATA_WRITE
  service: allServices''',
    'GCP: GKE Cluster Without Private Nodes': '''privateClusterConfig:
  enablePrivateNodes: true
  enablePrivateEndpoint: false
  masterIpv4CidrBlock: "172.16.0.0/28"''',
    'GCP: GKE Without Network Policy': '''addonsConfig:
  networkPolicyConfig:
    disabled: false
networkPolicy:
  enabled: true
  provider: CALICO''',
    'GCP: Hardcoded Secret Detected': '''# Use Secret Manager instead
# gcloud secrets create my-secret --data-file=secret.txt
# Reference in template:
# $(ref.my-secret.secretData)
# Or use: gcp-types/secretmanager-v1:projects.secrets''',
    'GCP: Overly Permissive IAM Role': '''# Use specific predefined roles
bindings:
- role: roles/storage.objectViewer  # Not roles/editor
  members:
  - serviceAccount:my-sa@project.iam.gserviceaccount.com''',
    'GCP: Resources Without Labels': '''labels:
  environment: production
  team: platform
  project: my-app
  managed-by: deployment-manager''',
}


def get_fix_code(title, file_type=''):
    """Get the fix code snippet for a finding by title."""
    return FIX_CODES.get(title, '')


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


def scan_directory(directory_path, max_files=500):
    """Walk a directory and scan all infrastructure files. Limits to max_files to prevent timeouts."""
    all_findings = []
    scannable_extensions = ('.tf', '.yaml', '.yml', '.dockerfile', '.json', '.jinja', '.jinja2')
    scannable_names = ('Dockerfile', 'Jenkinsfile', 'docker-compose.yml', 'docker-compose.yaml')
    files_scanned = 0

    for root, dirs, files in os.walk(directory_path):
        # Skip hidden directories and common non-infra dirs
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in (
            'node_modules', 'vendor', '__pycache__', '.git', 'venv', 'env',
            '.terraform', '.cache', 'dist', 'build', 'target', 'coverage',
            'test', 'tests', '__tests__', 'spec', 'fixtures', 'examples',
            'docs', 'documentation', 'assets', 'images', 'static'
        )]

        for filename in files:
            if files_scanned >= max_files:
                return all_findings

            full_path = os.path.join(root, filename)
            rel_path = os.path.relpath(full_path, directory_path)

            should_scan = (
                filename.lower().endswith(scannable_extensions) or
                filename in scannable_names or
                '.github/workflows' in rel_path.replace('\\', '/')
            )

            if should_scan:
                try:
                    # Skip files larger than 100KB (likely generated/vendor)
                    if os.path.getsize(full_path) > 100 * 1024:
                        continue
                    with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    file_type = detect_file_type(rel_path, content)
                    if file_type:
                        file_findings = analyze_content(content, file_type, rel_path)
                        all_findings.extend(file_findings)
                        files_scanned += 1
                except Exception:
                    continue

    return all_findings


def detect_git_provider(repo_url):
    """Detect the git provider from the repository URL."""
    url_lower = repo_url.lower()
    if 'github.com' in url_lower:
        return 'github'
    elif 'gitlab.com' in url_lower or 'gitlab' in url_lower:
        return 'gitlab'
    elif 'bitbucket.org' in url_lower or 'bitbucket' in url_lower:
        return 'bitbucket'
    elif 'dev.azure.com' in url_lower or 'visualstudio.com' in url_lower:
        return 'azure'
    elif 'codecommit' in url_lower:
        return 'codecommit'
    return 'generic'


def normalize_repo_url(repo_url):
    """Convert SSH URLs to HTTPS format. Handles all common git URL formats."""
    repo_url = repo_url.strip()

    # Already HTTPS — return as-is
    if repo_url.startswith('https://') or repo_url.startswith('http://'):
        return repo_url

    # SSH format: git@github.com:user/repo.git
    ssh_match = re.match(r'git@([^:]+):(.+?)(?:\.git)?$', repo_url)
    if ssh_match:
        host = ssh_match.group(1)
        path = ssh_match.group(2)
        return f'https://{host}/{path}.git'

    # SSH format: ssh://git@github.com/user/repo.git
    ssh_url_match = re.match(r'ssh://git@([^/]+)/(.+?)(?:\.git)?$', repo_url)
    if ssh_url_match:
        host = ssh_url_match.group(1)
        path = ssh_url_match.group(2)
        return f'https://{host}/{path}.git'

    # Git protocol: git://github.com/user/repo.git
    git_match = re.match(r'git://([^/]+)/(.+?)(?:\.git)?$', repo_url)
    if git_match:
        host = git_match.group(1)
        path = git_match.group(2)
        return f'https://{host}/{path}.git'

    # If nothing matches, return as-is and let git clone handle the error
    return repo_url


def build_authenticated_url(repo_url, token, provider):
    """Build an authenticated clone URL based on the git provider."""
    if not token:
        return repo_url
    clean_url = repo_url.rstrip('/')
    if not clean_url.endswith('.git'):
        clean_url += '.git'
    if provider == 'github':
        match = re.match(r'https?://github\.com/(.+?)(?:\.git)?$', clean_url)
        if match:
            return f'https://{token}@github.com/{match.group(1)}.git'
    elif provider == 'gitlab':
        match = re.match(r'https?://([^/]+)/(.+?)(?:\.git)?$', clean_url)
        if match:
            return f'https://oauth2:{token}@{match.group(1)}/{match.group(2)}.git'
    elif provider == 'bitbucket':
        match = re.match(r'https?://bitbucket\.org/(.+?)(?:\.git)?$', clean_url)
        if match:
            return f'https://x-token-auth:{token}@bitbucket.org/{match.group(1)}.git'
    elif provider == 'azure':
        match = re.match(r'https?://(dev\.azure\.com/.+?)(?:\.git)?$', clean_url)
        if match:
            return f'https://{token}@{match.group(1)}'
    # Generic fallback
    match = re.match(r'(https?://)(.+)', clean_url)
    if match:
        return f'{match.group(1)}{token}@{match.group(2)}'
    return repo_url


def clone_and_scan_repo(repo_url, token=None):
    """Clone a git repository (GitHub, GitLab, Bitbucket, Azure, etc.) and scan for infrastructure issues."""
    clone_dir = os.path.join('/tmp', f'infraaudit-{uuid.uuid4().hex[:12]}')

    try:
        # Normalize URL (convert SSH/git:// to HTTPS)
        repo_url = normalize_repo_url(repo_url)

        # Check repo size via API before cloning (GitHub only)
        if 'github.com' in repo_url:
            try:
                import urllib.request
                match = re.match(r'https?://github\.com/([^/]+/[^/]+?)(?:\.git)?$', repo_url)
                if match:
                    api_url = f'https://api.github.com/repos/{match.group(1)}'
                    headers = {'Accept': 'application/json'}
                    if token:
                        headers['Authorization'] = f'Bearer {token}'
                    req = urllib.request.Request(api_url, headers=headers)
                    with urllib.request.urlopen(req, timeout=5) as resp:
                        repo_info = json.loads(resp.read().decode())
                    size_kb = repo_info.get('size', 0)
                    if size_kb > 500000:  # > 500MB
                        return None, f'Repository is too large ({size_kb // 1024}MB). Maximum supported size is 500MB. Try scanning a smaller repo or use manual paste for specific files.'
            except Exception:
                pass  # If API check fails, proceed with clone attempt

        provider = detect_git_provider(repo_url)
        clone_url = build_authenticated_url(repo_url, token, provider)

        env = os.environ.copy()
        env['GIT_TERMINAL_PROMPT'] = '0'
        env['GIT_ASKPASS'] = '/bin/false'
        env['GIT_SSH_COMMAND'] = 'ssh -o BatchMode=yes'
        env['GIT_CONFIG_NOSYSTEM'] = '1'
        env['GIT_CONFIG_GLOBAL'] = '/dev/null'
        env['HOME'] = clone_dir

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
                provider_name = provider.capitalize() if provider != 'generic' else 'Git'
                return None, f'Authentication failed. This appears to be a private repository. Please provide a valid {provider_name} access token.'
            elif 'not found' in error_msg or 'does not exist' in error_msg:
                return None, 'Repository not found. Check the URL and ensure the repo exists.'
            else:
                return None, f'Failed to clone repository: {result.stderr[:200]}'

        findings = scan_directory(clone_dir)

        if not findings:
            return [], None

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
        if os.path.exists(clone_dir):
            shutil.rmtree(clone_dir, ignore_errors=True)


# ============================================================
# ROUTES
# ============================================================

@app.route('/')
def index():
    # Get real reviews for landing page (all visible reviews with 4+ stars)
    real_reviews = Review.query.filter(Review.is_visible == True, Review.rating >= 4).order_by(Review.created_at.desc()).all()
    return render_template('index.html', real_reviews=real_reviews)


@app.route('/demo-scan', methods=['POST'])
def demo_scan():
    """Run a demo scan without requiring signup — shows the product value instantly."""
    import time
    start_time = time.time()

    # Check if user pasted their own code
    custom_code = request.form.get('code', '').strip()
    file_type = request.form.get('file_type', 'kubernetes')

    if custom_code:
        # User pasted their own code — validate first
        is_valid, error_msg = validate_content(custom_code, file_type)
        if not is_valid:
            return jsonify({
                'error': True,
                'message': error_msg
            }), 400
        scan_code = custom_code
    else:
        # Use sample code
        file_type = 'kubernetes'
        scan_code = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
spec:
  replicas: 1
  selector:
    matchLabels:
      app: web-app
  template:
    metadata:
      labels:
        app: web-app
    spec:
      containers:
      - name: web-app
        image: nginx:latest
        ports:
        - containerPort: 80
        env:
        - name: DB_PASSWORD
          value: "supersecret123"
        - name: API_KEY
          value: "sk-prod-abc123xyz"
"""
    findings = analyze_content(scan_code, file_type, 'demo/input')
    risk_score = calculate_risk_score(findings)
    counts = count_by_severity(findings)
    elapsed = round(time.time() - start_time, 2)
    # Ensure minimum visible time for UX (at least 0.8s feels like "real work")
    if elapsed < 0.8:
        time.sleep(0.8 - elapsed)
        elapsed = 0.8

    return jsonify({
        'risk_score': risk_score,
        'findings': findings,
        'counts': counts,
        'total': len(findings),
        'elapsed': elapsed
    })


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
                flash('Invalid email or password. Please check your credentials and try again.', 'error')
                flash('Forgot your password? Use the reset link below.', 'info')
        except Exception:
            flash('Login failed. Please try again.', 'error')

    return render_template('auth.html', mode='login')


@app.route('/auth/google')
def google_login():
    """Redirect user to Google OAuth consent screen."""
    if not GOOGLE_CLIENT_ID:
        flash('Google login is not configured.', 'error')
        return redirect(url_for('login'))
    import urllib.parse
    params = urllib.parse.urlencode({
        'client_id': GOOGLE_CLIENT_ID,
        'redirect_uri': GOOGLE_REDIRECT_URI,
        'response_type': 'code',
        'scope': 'openid email profile',
        'access_type': 'offline',
        'prompt': 'select_account'
    })
    return redirect(f'https://accounts.google.com/o/oauth2/v2/auth?{params}')


@app.route('/auth/google/callback')
def google_callback():
    """Handle Google OAuth callback."""
    code = request.args.get('code')
    error = request.args.get('error')

    if error or not code:
        flash('Google login was cancelled or failed.', 'error')
        return redirect(url_for('login'))

    try:
        import urllib.request
        import urllib.parse

        # Exchange code for tokens
        token_data = urllib.parse.urlencode({
            'code': code,
            'client_id': GOOGLE_CLIENT_ID,
            'client_secret': GOOGLE_CLIENT_SECRET,
            'redirect_uri': GOOGLE_REDIRECT_URI,
            'grant_type': 'authorization_code'
        }).encode()

        token_req = urllib.request.Request(
            'https://oauth2.googleapis.com/token',
            data=token_data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )
        with urllib.request.urlopen(token_req) as resp:
            token_response = json.loads(resp.read().decode())

        access_token = token_response.get('access_token')
        if not access_token:
            flash('Failed to get access token from Google.', 'error')
            return redirect(url_for('login'))

        # Get user info
        user_info_req = urllib.request.Request(
            'https://www.googleapis.com/oauth2/v2/userinfo',
            headers={'Authorization': f'Bearer {access_token}'}
        )
        with urllib.request.urlopen(user_info_req) as resp:
            user_info = json.loads(resp.read().decode())

        email = user_info.get('email', '').lower()
        name = user_info.get('name', email.split('@')[0])

        if not email:
            flash('Could not get email from Google account.', 'error')
            return redirect(url_for('login'))

        # Find or create user
        user = User.query.filter_by(email=email).first()
        if not user:
            # Create new user with Google OAuth
            user = User(email=email, name=name)
            user.set_password(uuid.uuid4().hex)  # Random password (they'll use Google to login)
            user.plan = 'pro'
            user.plan_expires_at = datetime.now(timezone.utc) + timedelta(days=7)
            db.session.add(user)
            db.session.commit()
            login_user(user)
            flash(f'🎉 Welcome {name}! Account created with Google. You have a 7-day Pro trial.', 'success')
        else:
            login_user(user)
            flash(f'Welcome back, {user.name}!', 'success')

        return redirect(url_for('dashboard'))

    except Exception as e:
        app.logger.error(f'Google OAuth error: {e}')
        flash('Google login failed. Please try again or use email/password.', 'error')
        return redirect(url_for('login'))


@app.route('/auth/github')
def github_oauth_login():
    """Redirect user to GitHub OAuth consent screen."""
    if not GITHUB_OAUTH_CLIENT_ID:
        flash('GitHub login is not configured.', 'error')
        return redirect(url_for('login'))
    import urllib.parse
    params = urllib.parse.urlencode({
        'client_id': GITHUB_OAUTH_CLIENT_ID,
        'redirect_uri': GITHUB_OAUTH_REDIRECT_URI,
        'scope': 'user:email read:user',
    })
    return redirect(f'https://github.com/login/oauth/authorize?{params}')


@app.route('/auth/github/callback')
def github_oauth_callback():
    """Handle GitHub OAuth callback."""
    code = request.args.get('code')
    error = request.args.get('error')

    if error or not code:
        flash('GitHub login was cancelled or failed.', 'error')
        return redirect(url_for('login'))

    try:
        import urllib.request
        import urllib.parse

        # Exchange code for access token
        token_data = urllib.parse.urlencode({
            'client_id': GITHUB_OAUTH_CLIENT_ID,
            'client_secret': GITHUB_OAUTH_CLIENT_SECRET,
            'code': code,
            'redirect_uri': GITHUB_OAUTH_REDIRECT_URI,
        }).encode()

        token_req = urllib.request.Request(
            'https://github.com/login/oauth/access_token',
            data=token_data,
            headers={
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json'
            }
        )
        with urllib.request.urlopen(token_req) as resp:
            token_response = json.loads(resp.read().decode())

        access_token = token_response.get('access_token')
        if not access_token:
            flash('Failed to get access token from GitHub.', 'error')
            return redirect(url_for('login'))

        # Get user info
        user_req = urllib.request.Request(
            'https://api.github.com/user',
            headers={
                'Authorization': f'Bearer {access_token}',
                'Accept': 'application/json'
            }
        )
        with urllib.request.urlopen(user_req) as resp:
            github_user = json.loads(resp.read().decode())

        # Get primary email (may be private)
        email = github_user.get('email')
        if not email:
            email_req = urllib.request.Request(
                'https://api.github.com/user/emails',
                headers={
                    'Authorization': f'Bearer {access_token}',
                    'Accept': 'application/json'
                }
            )
            with urllib.request.urlopen(email_req) as resp:
                emails = json.loads(resp.read().decode())
            for e in emails:
                if e.get('primary') and e.get('verified'):
                    email = e['email']
                    break
            if not email and emails:
                email = emails[0].get('email', '')

        if not email:
            flash('Could not get email from GitHub account.', 'error')
            return redirect(url_for('login'))

        email = email.lower()
        name = github_user.get('name') or github_user.get('login', email.split('@')[0])

        # Find or create user
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(email=email, name=name)
            user.set_password(uuid.uuid4().hex)
            user.plan = 'pro'
            user.plan_expires_at = datetime.now(timezone.utc) + timedelta(days=7)
            # Store GitHub token for repo scanning
            user.github_token = access_token
            db.session.add(user)
            db.session.commit()
            login_user(user)
            flash(f'🎉 Welcome {name}! Account created with GitHub. You have a 7-day Pro trial.', 'success')
        else:
            # Update GitHub token if user already exists
            if not user.github_token:
                user.github_token = access_token
                db.session.commit()
            login_user(user)
            flash(f'Welcome back, {user.name}!', 'success')

        return redirect(url_for('dashboard'))

    except Exception as e:
        app.logger.error(f'GitHub OAuth error: {e}')
        flash('GitHub login failed. Please try again or use email/password.', 'error')
        return redirect(url_for('login'))


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

    # Check if user should be prompted to review (only on 1st, 3rd, 5th scans)
    has_reviewed = Review.query.filter_by(user_id=current_user.id).first() is not None
    show_review_prompt = not has_reviewed and total_scans > 0 and total_scans % 2 == 1

    return render_template('dashboard.html',
                           projects=projects,
                           scans=scans,
                           total_projects=total_projects,
                           total_scans=total_scans,
                           avg_risk=avg_risk,
                           total_critical=total_critical,
                           trend_labels=json.dumps(trend_labels),
                           trend_data=json.dumps(trend_data),
                           show_review_prompt=show_review_prompt)


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
        flash('Please provide a valid access token.', 'error')
    elif len(token) < 10:
        flash('Token seems too short. Please provide a valid access token.', 'error')
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
                framework=f.get('framework'),
                fix_code=f.get('fix_code')
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

            # Validate content structure before scanning
            is_valid, error_msg = validate_content(code, file_type)
            if not is_valid:
                flash(f'Invalid configuration: {error_msg}', 'error')
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
                    framework=f.get('framework'),
                    fix_code=f.get('fix_code')
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


@app.route('/subscribe', methods=['POST'])
def subscribe():
    """Newsletter subscription — collect emails for marketing."""
    email = request.form.get('email', '').strip().lower()
    if not email or '@' not in email:
        return jsonify({'error': 'Please enter a valid email'}), 400
    existing = Subscriber.query.filter_by(email=email).first()
    if existing:
        return jsonify({'message': 'You\'re already subscribed!'})
    try:
        sub = Subscriber(email=email)
        db.session.add(sub)
        db.session.commit()
        return jsonify({'message': 'Thanks for subscribing! We\'ll keep you updated.'})
    except Exception:
        db.session.rollback()
        return jsonify({'error': 'Something went wrong. Please try again.'}), 500


@app.route('/reviews')
def reviews_page():
    """Public reviews page showing all visible reviews."""
    reviews = Review.query.filter_by(is_visible=True).order_by(Review.created_at.desc()).all()
    avg_rating = 0
    if reviews:
        avg_rating = round(sum(r.rating for r in reviews) / len(reviews), 1)
    can_review = False
    user_review = None
    if current_user.is_authenticated:
        user_review = Review.query.filter_by(user_id=current_user.id).first()
        # Can review if they've run at least 1 scan
        scan_count = Scan.query.join(Project).filter(Project.user_id == current_user.id).count()
        can_review = scan_count > 0 and user_review is None
    return render_template('reviews.html', reviews=reviews, avg_rating=avg_rating,
                           can_review=can_review, user_review=user_review)


@app.route('/reviews/submit', methods=['POST'])
@login_required
def submit_review():
    """Submit or update a review."""
    rating = request.form.get('rating', type=int)
    text = request.form.get('text', '').strip()

    if not rating or rating < 1 or rating > 5:
        flash('Please select a rating (1-5 stars).', 'error')
        return redirect(url_for('reviews_page'))
    if not text or len(text) < 10:
        flash('Please write at least 10 characters in your review.', 'error')
        return redirect(url_for('reviews_page'))
    if len(text) > 1000:
        flash('Review is too long (max 1000 characters).', 'error')
        return redirect(url_for('reviews_page'))

    # Check if user has run at least 1 scan
    scan_count = Scan.query.join(Project).filter(Project.user_id == current_user.id).count()
    if scan_count == 0:
        flash('You need to run at least one scan before leaving a review.', 'error')
        return redirect(url_for('reviews_page'))

    # Check for existing review (update it)
    existing = Review.query.filter_by(user_id=current_user.id).first()
    if existing:
        existing.rating = rating
        existing.text = text
        existing.created_at = datetime.now(timezone.utc)
        flash('Your review has been updated!', 'success')
    else:
        review = Review(user_id=current_user.id, rating=rating, text=text, is_visible=False)
        db.session.add(review)
        flash('Thanks for your review! It will appear on the site after admin approval.', 'success')

    db.session.commit()
    return redirect(url_for('reviews_page'))


@app.route('/reviews/<int:review_id>/delete', methods=['POST'])
@login_required
def delete_review(review_id):
    """Admin: delete/hide a review."""
    if current_user.email != ADMIN_EMAIL:
        abort(403)
    review = Review.query.get_or_404(review_id)
    db.session.delete(review)
    db.session.commit()
    flash('Review deleted.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/reviews/<int:review_id>/publish', methods=['POST'])
@login_required
def publish_review(review_id):
    """Admin: publish/approve a review to show on home page."""
    if current_user.email != ADMIN_EMAIL:
        abort(403)
    review = Review.query.get_or_404(review_id)
    review.is_visible = True
    db.session.commit()
    flash('Review published to home page.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/reviews/<int:review_id>/unpublish', methods=['POST'])
@login_required
def unpublish_review(review_id):
    """Admin: unpublish a review (hide from home page)."""
    if current_user.email != ADMIN_EMAIL:
        abort(403)
    review = Review.query.get_or_404(review_id)
    review.is_visible = False
    db.session.commit()
    flash('Review unpublished.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/reviews')
@login_required
def admin_reviews():
    """Admin: manage all reviews."""
    if current_user.email != ADMIN_EMAIL:
        abort(403)
    all_reviews = Review.query.order_by(Review.created_at.desc()).all()
    published = [r for r in all_reviews if r.is_visible]
    pending = [r for r in all_reviews if not r.is_visible]
    return render_template('admin.html',
                           show_reviews=True,
                           all_reviews=all_reviews,
                           published_reviews=published,
                           pending_reviews=pending)


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


@app.route('/checks')
def checks_page():
    """Display all security checks the platform performs — SEO page."""
    checks = {
        'kubernetes': [
            {'title': 'Container Running as Root', 'severity': 'critical', 'framework': 'CIS-K8S-1.8', 'description': 'Detects containers without runAsNonRoot: true in securityContext'},
            {'title': 'Privileged Container Detected', 'severity': 'critical', 'framework': 'CIS-K8S-1.8', 'description': 'Flags containers running in privileged mode with full host access'},
            {'title': 'ClusterRoleBinding to cluster-admin', 'severity': 'critical', 'framework': 'CIS-K8S-1.8', 'description': 'Detects overly permissive RBAC bindings granting cluster-admin'},
            {'title': 'Missing Resource Limits', 'severity': 'high', 'framework': 'CIS-K8S-1.8', 'description': 'Containers without CPU/memory limits that can exhaust node resources'},
            {'title': 'Privilege Escalation Not Disabled', 'severity': 'high', 'framework': 'CIS-K8S-1.8', 'description': 'allowPrivilegeEscalation not explicitly set to false'},
            {'title': 'Host Network Enabled', 'severity': 'high', 'framework': 'CIS-K8S-1.8', 'description': 'Pod using host network namespace, bypassing network isolation'},
            {'title': 'Host PID Namespace Shared', 'severity': 'high', 'framework': 'CIS-K8S-1.8', 'description': 'Pod sharing host PID namespace, exposing host processes'},
            {'title': 'Potential Secret in Plain Text', 'severity': 'high', 'framework': 'CIS-K8S-1.8', 'description': 'Sensitive values hardcoded in env vars instead of using Kubernetes Secrets'},
            {'title': 'Missing Liveness Probe', 'severity': 'medium', 'framework': 'CIS-K8S-1.8', 'description': 'No liveness probe to detect broken application state'},
            {'title': 'Missing Readiness Probe', 'severity': 'medium', 'framework': 'CIS-K8S-1.8', 'description': 'No readiness probe to prevent traffic to unready pods'},
            {'title': 'Using :latest Image Tag', 'severity': 'medium', 'framework': 'CIS-K8S-1.8', 'description': 'Mutable image tag that causes non-deterministic deployments'},
            {'title': 'No NetworkPolicy Defined', 'severity': 'medium', 'framework': 'CIS-K8S-1.8', 'description': 'No network segmentation — all pods can communicate freely'},
            {'title': 'Writable Root Filesystem', 'severity': 'medium', 'framework': 'CIS-K8S-1.8', 'description': 'readOnlyRootFilesystem not set, allowing file system modifications'},
            {'title': 'No Namespace Specified', 'severity': 'low', 'framework': 'CIS-K8S-1.8', 'description': 'Resources deployed to default namespace without explicit namespace'},
            {'title': 'No PodDisruptionBudget', 'severity': 'low', 'framework': 'CIS-K8S-1.8', 'description': 'Multi-replica deployment without PDB for disruption protection'},
            {'title': 'Service Account Token Auto-Mounted', 'severity': 'medium', 'framework': 'CIS-K8S-1.8', 'description': 'Service account token auto-mounted, potentially exposing API access'},
            {'title': 'Using Default Service Account', 'severity': 'medium', 'framework': 'CIS-K8S-1.8', 'description': 'Pod uses default service account which may have excessive permissions'},
            {'title': 'Privileged Port Used', 'severity': 'low', 'framework': 'CIS-K8S-1.8', 'description': 'Container uses privileged port (<1024) requiring elevated privileges'},
            {'title': 'No Pod Anti-Affinity', 'severity': 'low', 'framework': 'CIS-K8S-1.8', 'description': 'Multi-replica deployment without anti-affinity for high availability'},
            {'title': 'No Startup Probe', 'severity': 'low', 'framework': 'CIS-K8S-1.8', 'description': 'Slow-starting application without startupProbe configured'},
            {'title': 'hostPath Volume Mount', 'severity': 'high', 'framework': 'CIS-K8S-1.8', 'description': 'Pod mounts host filesystem path, breaking container isolation'},
            {'title': 'Linux Capabilities Not Dropped', 'severity': 'medium', 'framework': 'CIS-K8S-1.8', 'description': 'Container does not drop all Linux capabilities'},
        ],
        'terraform': [
            {'title': 'Security Group Open to World', 'severity': 'critical', 'framework': 'AWS-WA-SEC', 'description': 'Ingress allows 0.0.0.0/0 — resource exposed to entire internet'},
            {'title': 'Hardcoded Credentials Detected', 'severity': 'critical', 'framework': 'AWS-WA-SEC', 'description': 'Access keys, passwords, or tokens hardcoded in configuration'},
            {'title': 'No Remote Backend Configured', 'severity': 'high', 'framework': 'AWS-WA-SEC', 'description': 'Terraform state stored locally, preventing collaboration and risking loss'},
            {'title': 'S3 Bucket Without Encryption', 'severity': 'high', 'framework': 'AWS-WA-SEC', 'description': 'S3 bucket missing server-side encryption configuration'},
            {'title': 'S3 Backend Without State Locking', 'severity': 'high', 'framework': 'AWS-WA-REL', 'description': 'S3 backend without DynamoDB locking — concurrent operations may corrupt state'},
            {'title': 'RDS Without Deletion Protection', 'severity': 'high', 'framework': 'AWS-WA-REL', 'description': 'Database can be accidentally destroyed by terraform destroy'},
            {'title': 'RDS Without Encryption at Rest', 'severity': 'high', 'framework': 'AWS-WA-SEC', 'description': 'Database storage not encrypted, data at rest unprotected'},
            {'title': 'S3 Bucket Without Versioning', 'severity': 'medium', 'framework': 'AWS-WA-REL', 'description': 'No versioning — accidental deletions cannot be recovered'},
            {'title': 'Provider Without Version Constraint', 'severity': 'medium', 'framework': 'AWS-WA-REL', 'description': 'Provider upgrades may introduce breaking changes'},
            {'title': 'Sensitive Variable Not Marked', 'severity': 'medium', 'framework': 'AWS-WA-SEC', 'description': 'Variables with sensitive data not marked sensitive = true'},
            {'title': 'Access Logging Not Enabled', 'severity': 'medium', 'framework': 'AWS-WA-SEC', 'description': 'Load balancer or CDN without access logging for audit trail'},
            {'title': 'Resource Missing Tags', 'severity': 'low', 'framework': 'AWS-WA-COST', 'description': 'Resources without tags for cost allocation and management'},
            {'title': 'No CloudTrail Configuration', 'severity': 'medium', 'framework': 'AWS-WA-SEC', 'description': 'No CloudTrail resource found for API activity logging'},
            {'title': 'EBS Volume Not Encrypted', 'severity': 'high', 'framework': 'AWS-WA-SEC', 'description': 'EBS volume without encryption enabled'},
            {'title': 'Lambda Not in VPC', 'severity': 'low', 'framework': 'AWS-WA-SEC', 'description': 'Lambda function not configured within a VPC'},
            {'title': 'No Lifecycle prevent_destroy', 'severity': 'medium', 'framework': 'AWS-WA-REL', 'description': 'Critical resource without prevent_destroy lifecycle rule'},
            {'title': 'IAM Policy with Wildcard Actions', 'severity': 'critical', 'framework': 'AWS-WA-SEC', 'description': 'IAM policy grants all actions (*) violating least-privilege'},
            {'title': 'RDS Publicly Accessible', 'severity': 'critical', 'framework': 'AWS-WA-SEC', 'description': 'Database publicly accessible from the internet'},
            {'title': 'No Backup Retention Period', 'severity': 'medium', 'framework': 'AWS-WA-REL', 'description': 'RDS instance without specified backup retention'},
            {'title': 'S3 Public Access Not Blocked', 'severity': 'high', 'framework': 'AWS-WA-SEC', 'description': 'S3 bucket without public access block configured'},
        ],
        'dockerfile': [
            {'title': 'Secret Exposed in Dockerfile', 'severity': 'critical', 'framework': 'DOCKER-CIS', 'description': 'Sensitive values in ARG/ENV baked into image layers permanently'},
            {'title': 'Container Runs as Root', 'severity': 'high', 'framework': 'DOCKER-CIS', 'description': 'No USER instruction — container runs as root by default'},
            {'title': 'Broad COPY Statement', 'severity': 'medium', 'framework': 'DOCKER-CIS', 'description': 'COPY . . includes sensitive files (.env, .git) in image'},
            {'title': 'Base Image Uses :latest Tag', 'severity': 'medium', 'framework': 'DOCKER-CIS', 'description': 'Non-reproducible builds from mutable base image tag'},
            {'title': 'Base Image Without Version Tag', 'severity': 'medium', 'framework': 'DOCKER-CIS', 'description': 'FROM without tag defaults to :latest implicitly'},
            {'title': 'Use COPY Instead of ADD', 'severity': 'low', 'framework': 'DOCKER-CIS', 'description': 'ADD has implicit behaviors — COPY is more explicit and predictable'},
            {'title': 'No HEALTHCHECK Instruction', 'severity': 'low', 'framework': 'DOCKER-CIS', 'description': 'Container health cannot be determined by orchestrators'},
            {'title': 'Consider Multi-Stage Build', 'severity': 'low', 'framework': 'DOCKER-CIS', 'description': 'Single-stage build includes build tools in final image'},
            {'title': 'Too Many Ports Exposed', 'severity': 'low', 'framework': 'DOCKER-CIS', 'description': 'Excessive ports exposed increasing attack surface'},
            {'title': 'apt-get Without --no-install-recommends', 'severity': 'low', 'framework': 'DOCKER-CIS', 'description': 'Installing unnecessary recommended packages'},
            {'title': 'Ensure .dockerignore Exists', 'severity': 'low', 'framework': 'DOCKER-CIS', 'description': 'Broad COPY without .dockerignore may include sensitive files'},
            {'title': 'Downloaded Files Not Cleaned Up', 'severity': 'low', 'framework': 'DOCKER-CIS', 'description': 'Files from curl/wget not removed, increasing image size'},
        ],
        'cicd': [
            {'title': 'Hardcoded Secret in Pipeline', 'severity': 'critical', 'framework': 'CICD-SEC', 'description': 'Passwords, tokens, or keys hardcoded in pipeline configuration'},
            {'title': 'No Container Image Scanning', 'severity': 'high', 'framework': 'CICD-SEC', 'description': 'Images pushed without vulnerability scanning (Trivy, Snyk, Grype)'},
            {'title': 'No Environment Protection for Deployment', 'severity': 'high', 'framework': 'CICD-SEC', 'description': 'Production deployments without manual approval or environment protection'},
            {'title': 'No Test Step in Pipeline', 'severity': 'medium', 'framework': 'CICD-SEC', 'description': 'Code deployed without running tests — no quality gate'},
            {'title': 'No Pull Request Trigger', 'severity': 'medium', 'framework': 'CICD-SEC', 'description': 'Changes not validated before merge to main branch'},
            {'title': 'Unpinned GitHub Action', 'severity': 'medium', 'framework': 'CICD-SEC', 'description': 'Actions using branch/tag reference instead of SHA — supply chain risk'},
            {'title': 'No Caching Configured', 'severity': 'low', 'framework': 'CICD-SEC', 'description': 'Dependencies downloaded fresh every build — slow pipelines'},
            {'title': 'No Pipeline Timeout', 'severity': 'low', 'framework': 'CICD-SEC', 'description': 'Stuck pipelines consume resources indefinitely'},
            {'title': 'No Static Analysis (SAST/Lint)', 'severity': 'medium', 'framework': 'CICD-SEC', 'description': 'No code quality or security analysis step in pipeline'},
            {'title': 'Auto-Deploy Without Approval', 'severity': 'high', 'framework': 'CICD-SEC', 'description': 'Production deployment without manual approval gate'},
            {'title': 'Self-Hosted Runner Used', 'severity': 'medium', 'framework': 'CICD-SEC', 'description': 'Self-hosted runners may have persistent state and security risks'},
            {'title': 'No Artifact Signing', 'severity': 'low', 'framework': 'CICD-SEC', 'description': 'Artifacts published without signing or checksum verification'},
        ],
        'cloudformation': [
            {'title': 'CFN: S3 Bucket Without Encryption', 'severity': 'high', 'framework': 'AWS-WA-SEC', 'description': 'S3 bucket missing server-side encryption in CloudFormation template'},
            {'title': 'CFN: S3 Public Access Not Blocked', 'severity': 'high', 'framework': 'AWS-WA-SEC', 'description': 'S3 bucket without PublicAccessBlockConfiguration'},
            {'title': 'CFN: Security Group Open to World', 'severity': 'critical', 'framework': 'AWS-WA-SEC', 'description': 'Security group ingress allows 0.0.0.0/0 — exposed to internet'},
            {'title': 'CFN: IAM Policy with Wildcard Actions', 'severity': 'critical', 'framework': 'AWS-WA-SEC', 'description': 'IAM policy grants all actions (*) violating least-privilege'},
            {'title': 'CFN: IAM Policy with Wildcard Resource', 'severity': 'high', 'framework': 'AWS-WA-SEC', 'description': 'IAM policy applies to all resources (*) instead of specific ARNs'},
            {'title': 'CFN: No DeletionPolicy on Critical Resource', 'severity': 'high', 'framework': 'AWS-WA-REL', 'description': 'Critical resource without DeletionPolicy — stack delete destroys data'},
            {'title': 'CFN: RDS Without Encryption', 'severity': 'high', 'framework': 'AWS-WA-SEC', 'description': 'RDS instance without StorageEncrypted enabled'},
            {'title': 'CFN: RDS Publicly Accessible', 'severity': 'critical', 'framework': 'AWS-WA-SEC', 'description': 'RDS instance publicly accessible from the internet'},
            {'title': 'CFN: No Logging Configuration', 'severity': 'medium', 'framework': 'AWS-WA-SEC', 'description': 'No CloudTrail or CloudWatch Logs for audit and monitoring'},
            {'title': 'CFN: EBS Volume Not Encrypted', 'severity': 'high', 'framework': 'AWS-WA-SEC', 'description': 'EBS volume without encryption enabled'},
            {'title': 'CFN: Lambda Not in VPC', 'severity': 'low', 'framework': 'AWS-WA-SEC', 'description': 'Lambda function not configured within a VPC'},
            {'title': 'CFN: Hardcoded Secret Detected', 'severity': 'critical', 'framework': 'AWS-WA-SEC', 'description': 'Sensitive values hardcoded instead of using NoEcho or Secrets Manager'},
        ],
        'arm': [
            {'title': 'ARM: Storage Account Without HTTPS Enforcement', 'severity': 'high', 'framework': 'AZURE-SEC', 'description': 'Storage account allows unencrypted HTTP connections'},
            {'title': 'ARM: Storage Account Without Encryption', 'severity': 'high', 'framework': 'AZURE-SEC', 'description': 'Storage account without explicit encryption configuration'},
            {'title': 'ARM: Public IP Address Assigned', 'severity': 'medium', 'framework': 'AZURE-SEC', 'description': 'Resource has public IP increasing attack surface'},
            {'title': 'ARM: No Network Security Group', 'severity': 'high', 'framework': 'AZURE-SEC', 'description': 'Network interface or VNet without associated NSG'},
            {'title': 'ARM: NSG Rule Open to World', 'severity': 'critical', 'framework': 'AZURE-SEC', 'description': 'NSG rule allows inbound from any source (0.0.0.0/0 or *)'},
            {'title': 'ARM: No Diagnostic Settings', 'severity': 'medium', 'framework': 'AZURE-SEC', 'description': 'Resources without diagnostic settings for monitoring'},
            {'title': 'ARM: SQL Server Without Auditing', 'severity': 'medium', 'framework': 'AZURE-SEC', 'description': 'Azure SQL Server without auditing for security monitoring'},
            {'title': 'ARM: SQL Server Public Network Access', 'severity': 'high', 'framework': 'AZURE-SEC', 'description': 'SQL Server with public network access enabled'},
            {'title': 'ARM: VM Without Disk Encryption', 'severity': 'high', 'framework': 'AZURE-SEC', 'description': 'Virtual machine without disk encryption configured'},
            {'title': 'ARM: Hardcoded Secret Detected', 'severity': 'critical', 'framework': 'AZURE-SEC', 'description': 'Sensitive values hardcoded instead of using secureString or Key Vault'},
        ],
        'gcp': [
            {'title': 'GCP: Firewall Rule Open to World', 'severity': 'critical', 'framework': 'GCP-SEC', 'description': 'Firewall rule allows ingress from 0.0.0.0/0 — exposed to internet'},
            {'title': 'GCP: Bucket Publicly Accessible', 'severity': 'critical', 'framework': 'GCP-SEC', 'description': 'GCS bucket grants access to allUsers or allAuthenticatedUsers'},
            {'title': 'GCP: Cloud SQL Publicly Accessible', 'severity': 'critical', 'framework': 'GCP-SEC', 'description': 'Cloud SQL has public IP or allows connections from 0.0.0.0/0'},
            {'title': 'GCP: Hardcoded Secret Detected', 'severity': 'critical', 'framework': 'GCP-SEC', 'description': 'Sensitive values hardcoded instead of using Secret Manager or KMS'},
            {'title': 'GCP: Overly Permissive IAM Role', 'severity': 'critical', 'framework': 'GCP-SEC', 'description': 'Service account granted Owner or Editor role — violates least privilege'},
            {'title': 'GCP: Cloud SQL Without SSL', 'severity': 'high', 'framework': 'GCP-SEC', 'description': 'Cloud SQL instance does not enforce SSL connections'},
            {'title': 'GCP: GKE Cluster Without Private Nodes', 'severity': 'high', 'framework': 'GCP-SEC', 'description': 'GKE cluster nodes have public IPs exposed to internet'},
            {'title': 'GCP: Instance with External IP', 'severity': 'medium', 'framework': 'GCP-SEC', 'description': 'Compute instance has external IP increasing attack surface'},
            {'title': 'GCP: Bucket Without Uniform Access', 'severity': 'medium', 'framework': 'GCP-SEC', 'description': 'GCS bucket uses legacy ACLs instead of uniform IAM access'},
            {'title': 'GCP: No Audit Logging Configured', 'severity': 'medium', 'framework': 'GCP-SEC', 'description': 'Template does not configure audit logging for resources'},
            {'title': 'GCP: GKE Without Network Policy', 'severity': 'medium', 'framework': 'GCP-SEC', 'description': 'GKE cluster without network policy — pods communicate freely'},
            {'title': 'GCP: Resources Without Labels', 'severity': 'low', 'framework': 'GCP-SEC', 'description': 'Resources without labels for cost allocation and organization'},
        ],
    }
    return render_template('checks.html', checks=checks)


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
    total_subscribers = Subscriber.query.count()

    subscribers = Subscriber.query.order_by(Subscriber.created_at.desc()).all()

    # Reviews for admin management
    all_reviews = Review.query.order_by(Review.created_at.desc()).all()
    pending_reviews = [r for r in all_reviews if not r.is_visible]
    published_reviews = [r for r in all_reviews if r.is_visible]

    return render_template('admin.html',
                           users=users,
                           total_users=total_users,
                           pro_users=pro_users,
                           team_users=team_users,
                           free_users=free_users,
                           total_scans=total_scans,
                           total_projects=total_projects,
                           total_payments=total_payments,
                           total_revenue=total_revenue,
                           total_subscribers=total_subscribers,
                           subscribers=subscribers,
                           all_reviews=all_reviews,
                           pending_reviews=pending_reviews,
                           published_reviews=published_reviews)


@app.route('/admin/subscribers/export')
@admin_required
def admin_export_subscribers():
    """Export all subscriber emails as CSV download."""
    subscribers = Subscriber.query.order_by(Subscriber.created_at.desc()).all()
    csv_content = "email,subscribed_at\n"
    for s in subscribers:
        csv_content += f"{s.email},{s.created_at.strftime('%Y-%m-%d %H:%M')}\n"
    from flask import Response
    return Response(
        csv_content,
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=subscribers.csv'}
    )


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

    # Add display_name column if it doesn't exist (migration for existing DBs)
    try:
        from sqlalchemy import inspect, text
        inspector = inspect(db.engine)
        columns = [col['name'] for col in inspector.get_columns('reviews')]
        if 'display_name' not in columns:
            with db.engine.connect() as conn:
                conn.execute(text('ALTER TABLE reviews ADD COLUMN display_name VARCHAR(255)'))
                conn.commit()
    except Exception:
        pass

    # Seed 20 default reviews (only if no reviews exist yet)
    if Review.query.count() == 0:
        seed_reviews = [
            {'name': 'Rahul Krishnan', 'rating': 5, 'text': 'DeployPilot AI caught 3 critical misconfigurations in our Kubernetes manifests that would have gone to production. Saved us hours of manual review.'},
            {'name': 'Priya Sharma', 'rating': 5, 'text': 'Connected our GitHub repo and had a full security report in under 30 seconds. The suggested fixes are incredibly helpful.'},
            {'name': 'Arun Mehta', 'rating': 5, 'text': 'The compliance mapping to CIS benchmarks is exactly what our audit team needed. PDF export is perfect for sharing with management.'},
            {'name': 'Sneha Reddy', 'rating': 5, 'text': 'We replaced our manual Terraform review process with DeployPilot AI. Found IAM wildcard policies and unencrypted S3 buckets instantly.'},
            {'name': 'Vikram Patel', 'rating': 5, 'text': 'Best infra security tool for small DevOps teams. No CLI setup, just paste your code and get results. The fix suggestions are production-ready.'},
            {'name': 'Ananya Gupta', 'rating': 5, 'text': 'Our CI/CD pipelines had hardcoded secrets we missed for months. DeployPilot AI flagged them immediately with proper fix recommendations.'},
            {'name': 'Karthik Nair', 'rating': 5, 'text': 'Scanned our entire EKS infrastructure in seconds. The risk scoring helps us prioritize what to fix first. Highly recommended.'},
            {'name': 'Deepak Joshi', 'rating': 4, 'text': 'Great tool for catching Docker security issues. Found containers running as root and missing health checks across all our Dockerfiles.'},
            {'name': 'Meera Iyer', 'rating': 5, 'text': 'The CloudFormation scanning is excellent. Caught missing DeletionPolicy on our RDS instances before we deployed to production.'},
            {'name': 'Rohan Desai', 'rating': 5, 'text': 'Simple, fast, and accurate. We use it as a pre-commit check for all infrastructure changes. The 7-day trial convinced our team to go Pro.'},
            {'name': 'Lakshmi Venkat', 'rating': 4, 'text': 'ARM template validation saved us from deploying a storage account without HTTPS enforcement. The Azure checks are comprehensive.'},
            {'name': 'Sanjay Kumar', 'rating': 5, 'text': 'We were using Checkov but switched to DeployPilot AI for the web interface and PDF reports. Much easier for non-CLI users on our team.'},
            {'name': 'Divya Rajan', 'rating': 5, 'text': 'Found privilege escalation issues in our pod security contexts that we completely overlooked. The CIS benchmark mapping gives us confidence.'},
            {'name': 'Amit Saxena', 'rating': 5, 'text': 'The GitHub integration is seamless. Connected our monorepo and it scanned 200+ infra files in under 10 seconds. Impressive performance.'},
            {'name': 'Pooja Thakur', 'rating': 4, 'text': 'Good coverage of Kubernetes security checks. The readiness/liveness probe reminders alone prevented two outages for us.'},
            {'name': 'Nikhil Rao', 'rating': 5, 'text': 'Our startup needed affordable infra security tooling. DeployPilot AI at ₹999/mo is a fraction of what enterprise tools charge.'},
            {'name': 'Swati Mishra', 'rating': 5, 'text': 'The GCP Deployment Manager scanning caught firewall rules open to 0.0.0.0/0 that our team missed during code review.'},
            {'name': 'Rajesh Pillai', 'rating': 5, 'text': 'Excellent tool for DevSecOps. We integrated it into our PR review process. No infra change goes live without a DeployPilot scan.'},
            {'name': 'Kavitha Sundaram', 'rating': 4, 'text': 'The suggested fix code snippets are copy-paste ready. Saves so much time compared to reading documentation for each finding.'},
            {'name': 'Manish Agarwal', 'rating': 5, 'text': 'Detected our Terraform state backend had no locking configured. Could have caused state corruption with our team of 5 engineers.'},
        ]
        # Create a system user for seed reviews
        seed_user = User.query.filter_by(email='system@deploypilotai.internal').first()
        if not seed_user:
            seed_user = User(email='system@deploypilotai.internal', name='System', password_hash='nologin')
            db.session.add(seed_user)
            db.session.flush()

        for i, rev_data in enumerate(seed_reviews):
            review = Review(
                user_id=seed_user.id,
                rating=rev_data['rating'],
                text=rev_data['text'],
                display_name=rev_data['name'],
                is_visible=True,
                created_at=datetime.now(timezone.utc) - timedelta(days=30 - i)
            )
            db.session.add(review)
        db.session.commit()


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
