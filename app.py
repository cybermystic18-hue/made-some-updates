import os
import json
import uuid
import hmac
import hashlib
import requests
from datetime import datetime, timezone
import sys
from functools import wraps
from flask import (
    Flask, request, jsonify, render_template, session,
    redirect, url_for, flash, send_file, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import markdown
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-this-in-production')

# The secret MUST match the OVA's CONFIG["secret"]
FLAG_GENERATION_SECRET = os.environ.get("FLAG_GENERATION_SECRET", "w7H9sZ2KpL0rQxVtB8fNj3yA5uR1dGmT4oWcXeYiMhPkDzSaFnUqCvLbJgO2EtV")

# DANGEROUS: Hardcoded Credentials - NOT recommended for production
# This is an App Password generated from your Google Account with 2FA enabled.
# Your actual Gmail password is NOT used here.
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = "cybermystic18@gmail.com"
app.config['MAIL_PASSWORD'] = "ahmu zfxm ddsr izrg"
app.config['SECURITY_PASSWORD_SALT'] = os.environ.get('SECURITY_PASSWORD_SALT', 'a-very-secret-salt-12345')
mail = Mail(app)
s = URLSafeTimedSerializer(app.secret_key)

# Data file paths
DATA_DIR = 'data'
USERS_FILE = os.path.join(DATA_DIR, 'users.json')
CHALLENGES_FILE = os.path.join(DATA_DIR, 'challenges.json')
SCORES_FILE = os.path.join(DATA_DIR, 'scores.json')
SUBMISSIONS_FILE = os.path.join(DATA_DIR, 'submissions.json')
ANNOUNCEMENTS_FILE = os.path.join(DATA_DIR, 'announcements.json')
CONFIG_FILE = os.path.join(DATA_DIR, 'config.json')
LOGINS_FILE = os.path.join(DATA_DIR, 'logins.json')
TEAMS_FILE = os.path.join(DATA_DIR, 'teams.json')
HINTS_FILE = os.path.join(DATA_DIR, 'hints.json')
RULES_FILE = os.path.join(DATA_DIR, 'rules.md')
EVENT_FEED_FILE = os.path.join(DATA_DIR, 'event_feed.json')

UPLOAD_FOLDER = os.path.join(DATA_DIR, 'uploads')
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'zip', 'rar', '7z', 'gz', 'tar', 'bz2', 'bin', 'pcap', 'apk', 'exe', 'elf', 'dll'}

# ==============
# JSON helpers
# ==============
def load_json(filename):
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def save_json(filename, data):
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)

def get_config():
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        default_config = {
            "ctf_active": False,
            "ctf_start": "",
            "ctf_end": "",
            "dynamic_scoring": True,
            "team_mode": False,
            "rate_limit": 5,
            "min_score": 25,
            "telegram_bot_token": "",
            "telegram_chat_id": ""
        }
        save_json(CONFIG_FILE, default_config)
        return default_config

def get_rules():
    try:
        with open(RULES_FILE, 'r') as f:
            return f.read()
    except FileNotFoundError:
        with open(RULES_FILE, 'w') as f:
            f.write("# CTF Rules\n\nNo rulez, just fun.")
        return "# CTF Rules\n\nNo rulez, just fun."

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def render_markdown(text):
    """Safely render markdown, including HTML, with a filter for safety."""
    return markdown.markdown(text, extensions=['fenced_code', 'tables'])

def send_verification_email(user_email):
    try:
        token = s.dumps(user_email, salt=app.config['SECURITY_PASSWORD_SALT'])
        link = url_for('confirm_email', token=token, _external=True)

        subject = '🏴‍☠️ Confirm Your Account for ICTAK CTF'
        
        # This is the logo that will appear in the email
        logo_url = url_for('static', filename='img/ictak_logo.png', _external=True)
        # This is the wallpaper that will be the background
        background_image_url = url_for('static', filename='images/wp8997179-4k-one-piece-laptop-wallpapers.jpg', _external=True)

        # HTML content for the email
        html_body = f"""
        <div style="background-color: #000; color: #fff; padding: 20px; text-align: center; font-family: sans-serif; border-radius: 10px; border: 2px solid gold; background-image: url('{background_image_url}'); background-size: cover; background-position: center;">
            <img src="{logo_url}" alt="CTF Logo" style="max-width: 150px; margin-bottom: 20px;">
            <h1 style="color: gold; font-weight: bold; font-size: 24px;">Welcome Aboard, Pirate!</h1>
            <p style="font-size: 16px;">You're just one click away from joining the ultimate treasure hunt.</p>
            <p style="font-size: 16px;">To verify your email address and activate your account, click the button below.</p>
            <a href="{link}" style="background-color: gold; color: #000; text-decoration: none; padding: 12px 24px; border-radius: 5px; font-weight: bold; display: inline-block; margin-top: 20px;">
                Verify Your Account
            </a>
            <p style="margin-top: 30px; font-size: 12px; color: #aaa;">If the button doesn't work, you can copy and paste this link into your browser:</p>
            <p style="font-size: 12px;"><a href="{link}" style="color: #ccc;">{link}</a></p>
        </div>
        """

        msg = Message(subject, sender=app.config['MAIL_USERNAME'], recipients=[user_email])
        msg.body = f'Your CTF account requires email verification. Click this link to verify: {link}'
        msg.html = html_body
        
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Failed to send email: {e}", file=sys.stderr)
        return False

def send_password_reset_email(user_email):
    try:
        token = s.dumps(user_email, salt='password-reset-salt')
        link = url_for('reset_password_confirm', token=token, _external=True)

        subject = '🏴‍☠️ Password Reset for ICTAK CTF'
        logo_url = url_for('static', filename='img/ictak_logo.png', _external=True)
        background_image_url = url_for('static', filename='images/wp8997179-4k-one-piece-laptop-wallpapers.jpg', _external=True)


        html_body = f"""
        <div style="background-color: #000; color: #fff; padding: 20px; text-align: center; font-family: sans-serif; border-radius: 10px; border: 2px solid gold; background-image: url('{background_image_url}'); background-size: cover; background-position: center;">
            <img src="{logo_url}" alt="CTF Logo" style="max-width: 150px; margin-bottom: 20px;">
            <h1 style="color: gold; font-weight: bold; font-size: 24px;">Password Reset Requested</h1>
            <p style="font-size: 16px;">We received a request to reset your password. Click the button below to set a new password.</p>
            <a href="{link}" style="background-color: gold; color: #000; text-decoration: none; padding: 12px 24px; border-radius: 5px; font-weight: bold; display: inline-block; margin-top: 20px;">
                Reset Password
            </a>
            <p style="margin-top: 30px; font-size: 12px; color: #aaa;">If you did not request a password reset, please ignore this email.</p>
            <p style="font-size: 12px;"><a href="{link}" style="color: #ccc;">{link}</a></p>
        </div>
        """
        
        msg = Message(subject, sender=app.config['MAIL_USERNAME'], recipients=[user_email])
        msg.body = f'A password reset has been requested for your account. Click this link to reset: {link}'
        msg.html = html_body

        mail.send(msg)
        return True
    except Exception as e:
        print(f"Failed to send password reset email: {e}", file=sys.stderr)
        return False

# =====================
# Auth decorators
# =====================
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('You must be logged in to view this page.', 'error')
            return redirect(url_for('login'))
        users = load_json(USERS_FILE)
        user = next((u for u in users if u['id'] == session['user_id']), None)
        if not user or not user.get('is_confirmed', False):
            flash('Please confirm your email address to access this page.', 'error')
            session.clear()
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Admin access required!', 'error')
            return redirect(url_for('login'))
        users = load_json(USERS_FILE)
        user = next((u for u in users if u['id'] == session['user_id']), None)
        if not user or not user.get('is_admin', False):
            flash('Admin access required!', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated

def team_leader_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        teams = load_json(TEAMS_FILE)
        user = next((u for u in load_json(USERS_FILE) if u['id'] == session['user_id']), None)
        team = next((t for t in teams if t['id'] == user.get('team_id')), None)
        if not team or team['creator_id'] != session['user_id']:
            flash('You are not the leader of this team.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated

# ======================
# Utilities / features
# ======================
def log_submission(user_id, challenge_id, flag, success, ip):
    submissions = load_json(SUBMISSIONS_FILE)
    submissions.append({
        "timestamp": datetime.now().isoformat(),
        "user_id": user_id,
        "challenge_id": challenge_id,
        "flag": flag,
        "success": success,
        "ip": ip
    })
    save_json(SUBMISSIONS_FILE, submissions)

def log_event(event_type, message, **kwargs):
    events = load_json(EVENT_FEED_FILE)
    events.append({
        "timestamp": datetime.now().isoformat(),
        "type": event_type,
        "message": message,
        **kwargs
    })
    save_json(EVENT_FEED_FILE, events)

def get_challenge_solves_count(challenge_id, scores):
    """Counts the number of unique users who have solved at least one flag for a given challenge."""
    solved_users = {s['user_id'] for s in scores if s['challenge_id'] == challenge_id and s['score'] > 0}
    return len(solved_users)

def calculate_dynamic_score(base_score, solves, total_users):
    config = get_config()
    if not config.get('dynamic_scoring', True):
        return base_score
    if total_users == 0:
        return base_score
    solve_percentage = solves / total_users
    deduction = int(base_score * 0.4 * solve_percentage)
    final_score = max(config.get('min_score', 25), base_score - deduction)
    return final_score

def generate_avatar_url(user):
    seed = user.get('avatar_seed', user['id'])
    return f"https://api.dicebear.com/7.x/adventurer-neutral/svg?seed={seed}&size=200"

def generate_flag_suffixes(email, chal_id, secret, flag_count):
    md5_email = hashlib.md5(email.encode()).hexdigest()
    suffixes = []
    current_hash = None
    for i in range(flag_count):
        if i == 0:
            message = chal_id + md5_email + secret
        else:
            message = chal_id + current_hash + secret
        current_hash = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()
        suffixes.append(current_hash[-10:])
    return suffixes

def generate_full_flags(email, chal_id, secret, base_flags_data):
    base_flag_strings = [f['base_flag'] for f in base_flags_data]
    flag_count = len(base_flag_strings)
    suffixes = generate_flag_suffixes(email, chal_id, secret, flag_count)
    full_flags = []
    for i, base in enumerate(base_flag_strings):
        suffix = suffixes[i]
        if base.endswith("}"):
            new_flag = base[:-1] + "_" + suffix + "}"
        else:
            new_flag = base + "_" + suffix
        full_flags.append({"flag": new_flag, "id": base_flags_data[i]['id']})
    return full_flags

def pre_generate_flags_for_user(user, challenges):
    user.setdefault('pre_generated_flags', {})
    for challenge in challenges:
        dynamic_base_flags = [f for f in challenge.get('flags', []) if f.get('type') == 'dynamic']
        if dynamic_base_flags:
            user['pre_generated_flags'][challenge['id']] = generate_full_flags(
                user['email'], challenge['id'], FLAG_GENERATION_SECRET, dynamic_base_flags
            )
    return user

def send_file_to_telegram(file_path, bot_token, chat_id):
    if not bot_token or not chat_id:
        return
    url = f"https://api.telegram.org/bot{bot_token}/sendDocument"
    try:
        with open(file_path, 'rb') as f:
            files = {'document': (os.path.basename(file_path), f)}
            data = {'chat_id': chat_id}
            requests.post(url, data=data, files=files, timeout=10)
    except Exception as e:
        print(f"Failed to send {file_path} to Telegram: {e}", file=sys.stderr)

def recalculate_solves():
    """Recalculates solve counts for all challenges based on successful submissions."""
    scores = load_json(SCORES_FILE)
    challenges = load_json(CHALLENGES_FILE)
    
    for challenge in challenges:
        challenge['solves'] = get_challenge_solves_count(challenge['id'], scores)
    
    save_json(CHALLENGES_FILE, challenges)

def is_ctf_active():
    config = get_config()
    if not config.get('ctf_active', False):
        return False
    
    start_time_str = config.get('ctf_start')
    end_time_str = config.get('ctf_end')
    
    if not start_time_str or not end_time_str:
        return False
        
    try:
        start_time = datetime.fromisoformat(start_time_str).replace(tzinfo=timezone.utc)
        end_time = datetime.fromisoformat(end_time_str).replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        
        return start_time <= now < end_time
    except (ValueError, TypeError):
        return False

def get_user_score_after_join(user_id, team_id, scores, users):
    """Calculates a user's score based on submissions made while in the specified team."""
    user = next((u for u in users if u['id'] == user_id), None)
    if not user:
        return 0
    
    join_time = None
    for event in reversed(load_json(EVENT_FEED_FILE)):
        if event['type'] == 'team_join' and event.get('user_id') == user_id:
            join_time = datetime.fromisoformat(event['timestamp'])
            break
    if not join_time:
        return sum(s['score'] for s in scores if s['user_id'] == user_id)
        
    total_score = 0
    for score in scores:
        if score['user_id'] == user_id:
            score_time = datetime.fromisoformat(score['timestamp'])
            if score_time >= join_time and score['score'] > 0:
                total_score += score['score']
    return total_score
    
def get_team_total_score(team_id, scores, users):
    """Calculates the total score for a team, including all members' contributions."""
    team_members = [u['id'] for u in users if u.get('team_id') == team_id]
    team_scores = [s['score'] for s in scores if s['user_id'] in team_members]
    return sum(team_scores)

def get_user_total_score(user_id, scores):
    """Calculates the total score for a single user."""
    return sum(s['score'] for s in scores if s['user_id'] == user_id)
    
# =========
# Routes
# =========
@app.route('/')
def landing_page():
    config = get_config()
    return render_template('landing.html', team_mode=config.get('team_mode'))

@app.route('/rules')
def rules():
    config = get_config()
    rules_content = get_rules()
    return render_template('rules.html', rules_content=rules_content, team_mode=config.get('team_mode'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    config = get_config()
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']
        
        if len(username) > 24:
            flash("Username must be 24 characters or less.", 'error')
            return render_template('register.html', team_mode=config.get('team_mode'))

        users = load_json(USERS_FILE)
        existing_user = next((u for u in users if u['username'] == username or u['email'] == email), None)

        if existing_user:
            if existing_user['email'] == email and not existing_user.get('is_confirmed', False):
                flash('An unverified account already exists with this email. Please check your email for the verification link or log in to resend it.', 'warning')
                return redirect(url_for('login'))
            else:
                flash('Username or email already exists!', 'error')
                return render_template('register.html', team_mode=config.get('team_mode'))

        new_user = {
            "id": str(uuid.uuid4()),
            "username": username,
            "email": email,
            "password": generate_password_hash(password),
            "is_admin": len(users) == 0,
            "is_banned": False,
            "is_confirmed": False,
            "created_at": datetime.now().isoformat(),
            "avatar_seed": str(uuid.uuid4()),
            "bio": "",
            "location": "",
            "website": "",
            "team_id": None,
            "team_status": "none",
            "achievements": []
        }

        challenges = load_json(CHALLENGES_FILE)
        new_user = pre_generate_flags_for_user(new_user, challenges)

        users.append(new_user)
        save_json(USERS_FILE, users)
        
        send_verification_email(new_user['email'])
        log_event("user_join", f"New user '{username}' has joined the platform.")
        flash('Registration successful! Please check your email for a verification link.', 'info')
        return redirect(url_for('login'))
    return render_template('register.html', team_mode=config.get('team_mode'))

@app.route('/resend_verification', methods=['GET', 'POST'])
def resend_verification():
    if request.method == 'POST':
        email = request.form['email']
        users = load_json(USERS_FILE)
        user = next((u for u in users if u['email'] == email), None)
        if user and not user.get('is_confirmed', False):
            if send_verification_email(user['email']):
                flash('A new verification email has been sent. Please check your inbox.', 'success')
            else:
                flash('Failed to send verification email. Please try again later.', 'error')
        else:
            flash('Invalid email or account is already verified.', 'error')
        return redirect(url_for('login'))
    return render_template('resend_verification.html')

@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'], max_age=3600)
    except:
        flash('The confirmation link is invalid or has expired.', 'error')
        return redirect(url_for('login'))
    
    users = load_json(USERS_FILE)
    user = next((u for u in users if u.get('email') == email), None)
    
    if user:
        if user.get('is_confirmed', False):
            flash('Account already confirmed. Please log in.', 'info')
        else:
            user['is_confirmed'] = True
            save_json(USERS_FILE, users)
            flash('Account successfully confirmed! You can now log in.', 'success')
    else:
        flash('Invalid confirmation link.', 'error')
    return redirect(url_for('login'))

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form['email']
        users = load_json(USERS_FILE)
        user = next((u for u in users if u['email'] == email), None)
        if user and user.get('is_confirmed', False):
            if send_password_reset_email(user['email']):
                flash('A password reset link has been sent to your email.', 'info')
            else:
                flash('Failed to send password reset email. Please try again later.', 'error')
        else:
            flash('Email not found or account is not verified.', 'error')
        return redirect(url_for('login'))
    return render_template('reset_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password_confirm(token):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)
    except:
        flash('The password reset link is invalid or has expired.', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        password = request.form['password']
        users = load_json(USERS_FILE)
        user = next((u for u in users if u['email'] == email), None)
        if user:
            user['password'] = generate_password_hash(password)
            save_json(USERS_FILE, users)
            flash('Your password has been reset successfully. Please log in with your new password.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid user account.', 'error')
            return redirect(url_for('login'))

    return render_template('reset_password_confirm.html', token=token)

@app.route('/login', methods=['GET', 'POST'])
def login():
    config = get_config()
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        users = load_json(USERS_FILE)
        user = next((u for u in users if u['username'] == username), None)
        
        if user and check_password_hash(user['password'], password):
            if user.get('is_banned', False):
                flash('Your account has been banned.', 'error')
                return render_template('login.html', team_mode=config.get('team_mode'))
            
            if not user.get('is_confirmed', False):
                flash(f'Your account is not verified. <a href="{url_for("resend_verification")}" class="alert-link">Click here to resend the verification email.</a>', 'warning')
                return render_template('login.html', team_mode=config.get('team_mode'))

            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = user.get('is_admin', False)

            logins = load_json(LOGINS_FILE)
            logins.append({
                "timestamp": datetime.now().isoformat(),
                "user_id": user['id'],
                "username": username,
                "ip": request.remote_addr
            })
            save_json(LOGINS_FILE, logins)

            return redirect(url_for('admin_panel' if user.get('is_admin', False) else 'dashboard'))
        else:
            flash('Invalid credentials!', 'error')
    return render_template('login.html', team_mode=config.get('team_mode'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('landing_page'))

@app.route('/dashboard')
@login_required
def dashboard():
    config = get_config()
    
    if not is_ctf_active():
        all_announcements = load_json(ANNOUNCEMENTS_FILE)
        latest_announcement = all_announcements[-1] if all_announcements else None
        return render_template('dashboard.html',
                               ctf_active=False,
                               challenges=[],
                               latest_announcement=latest_announcement,
                               all_announcements=all_announcements,
                               user_rank=None,
                               user_total_score=0,
                               user_solved_count=0,
                               total_challenges=0,
                               recent_solves=[],
                               team_mode=config.get('team_mode', False),
                               ctf_start=config['ctf_start'],
                               ctf_end=config['ctf_end'],
                               config=config,
                               progress_percent=0)

    challenges = load_json(CHALLENGES_FILE)
    visible_challenges = [c for c in challenges if c.get('visible', True)]
    scores = load_json(SCORES_FILE)
    users = load_json(USERS_FILE)
    
    user_solved_flag_ids = {s.get('flag_id') for s in scores if s['user_id'] == session['user_id'] and s['score'] > 0}
    user_solved_challenge_ids = {s['challenge_id'] for s in scores if s['user_id'] == session['user_id'] and s['score'] > 0}

    team_solved_challenge_ids = set()
    user = next((u for u in users if u['id'] == session['user_id']), None)
    
    if config.get('team_mode', False) and user and user.get('team_id') and user.get('team_status') == 'member':
        team_members = [m.get('id') for m in users if m.get('team_id') == user['team_id'] and m.get('team_status') == 'member']
        for score_entry in scores:
            if score_entry['user_id'] in team_members and score_entry['score'] > 0:
                team_solved_challenge_ids.add(score_entry['challenge_id'])

    enriched = []
    for challenge in visible_challenges:
        all_flag_ids = {f.get('id') for f in challenge.get('flags', [])}
        solved_for_chal = len(all_flag_ids.intersection(user_solved_flag_ids))
        total_for_chal = len(all_flag_ids)
        
        challenge['solved_count'] = solved_for_chal
        challenge['total_flags'] = total_for_chal
        
        is_solved_by_team = config.get('team_mode', False) and user.get('team_id') and user.get('team_status') == 'member' and challenge['id'] in team_solved_challenge_ids
        
        if is_solved_by_team:
            challenge['is_complete'] = True
        else:
            challenge['is_complete'] = (total_for_chal > 0 and solved_for_chal == total_for_chal)

        requires_met = True
        for req_id in challenge.get('requires', []):
            if is_solved_by_team:
                if req_id not in team_solved_challenge_ids:
                    requires_met = False
                    break
            else:
                if req_id not in user_solved_challenge_ids:
                    requires_met = False
                    break
        challenge['unlocked'] = requires_met

        enriched.append(challenge)

    user_total_score = sum(s['score'] for s in scores if s['user_id'] == session['user_id'])
    
    totals = {}
    for s in scores:
        totals[s['user_id']] = totals.get(s['user_id'], 0) + s['score']
    sorted_totals = sorted(totals.items(), key=lambda x: x[1], reverse=True)
    user_rank = None
    for rank, (uid, sc) in enumerate(sorted_totals, start=1):
        if uid == session['user_id']:
            user_rank = rank
            break

    recent_solves = [s for s in scores if s['user_id'] == session['user_id'] and s['score'] > 0]
    recent_solves.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    recent_solves = recent_solves[:5]

    all_announcements = load_json(ANNOUNCEMENTS_FILE)
    latest_announcement = all_announcements[-1] if all_announcements else None

    user_solved_count = len({c['id'] for c in challenges if c['id'] in user_solved_challenge_ids})
    total_challenges = len(challenges)
    progress_percent = (user_solved_count / total_challenges * 100) if total_challenges > 0 else 0

    return render_template('dashboard.html',
                           ctf_active=True,
                           challenges=enriched,
                           latest_announcement=latest_announcement,
                           all_announcements=all_announcements,
                           user_rank=user_rank,
                           user_total_score=user_total_score,
                           user_solved_count=user_solved_count,
                           total_challenges=total_challenges,
                           team_mode=config.get('team_mode', False),
                           ctf_start=config['ctf_start'],
                           ctf_end=config['ctf_end'],
                           config=config,
                           progress_percent=progress_percent)

@app.route('/api/event_feed')
def get_event_feed():
    events = load_json(EVENT_FEED_FILE)
    return jsonify(events[-20:])

@app.route('/api/score_history')
@login_required
def api_score_history():
    scores = load_json(SCORES_FILE)
    user_scores = [s for s in scores if s['user_id'] == session['user_id'] and s['score'] > 0]
    user_scores.sort(key=lambda x: x['timestamp'])

    cumulative_scores = []
    current_score = 0
    timestamps = []

    for score_entry in user_scores:
        current_score += score_entry['score']
        timestamps.append(datetime.fromisoformat(score_entry['timestamp']).strftime('%Y-%m-%d %H:%M:%S'))
        cumulative_scores.append(current_score)
    return jsonify({
        'timestamps': timestamps,
        'scores': cumulative_scores
    })

@app.route('/challenge/<challenge_id>')
@login_required
def challenge_view(challenge_id):
    if not is_ctf_active():
        flash("The CTF is currently not active.", "error")
        return redirect(url_for('dashboard'))
    challenges = load_json(CHALLENGES_FILE)
    challenge = next((c for c in challenges if c['id'] == challenge_id), None)
    if not challenge:
        flash('Challenge not found!', 'error')
        return redirect(url_for('dashboard'))
    config = get_config()
    users = load_json(USERS_FILE)
    user = next((u for u in users if u['id'] == session['user_id']), None)
    scores = load_json(SCORES_FILE)
    is_team_member = config.get('team_mode', False) and user.get('team_id') and user.get('team_status') == 'member'
    user_solved_challenges = {s['challenge_id'] for s in scores if s['user_id'] == session['user_id'] and s['score'] > 0}
    required_challenges = set(challenge.get('requires', []))
    is_solved_by_team = False
    if is_team_member:
        team_members = [u['id'] for u in users if u.get('team_id') == user['team_id'] and u.get('team_status') == 'member']
        team_solved_challenges = {s['challenge_id'] for s in scores if s['user_id'] in team_members and s['score'] > 0}
        is_solved_by_team = challenge['id'] in team_solved_challenges
        if required_challenges and not required_challenges.issubset(team_solved_challenges):
            flash('Your team must complete the prerequisite challenges first!', 'error')
            return redirect(url_for('dashboard'))
    else:
        if required_challenges and not required_challenges.issubset(user_solved_challenges):
            flash('You must complete the prerequisite challenges first!', 'error')
            return redirect(url_for('dashboard'))
    is_complete = is_solved_by_team or (challenge['id'] in user_solved_challenges)
    user_solved_flag_ids = {
        s.get('flag_id')
        for s in scores
        if s['user_id'] == session['user_id'] and s['challenge_id'] == challenge_id and s['score'] > 0
    }
    flags_with_status = []
    for f in challenge.get('flags', []):
        flags_with_status.append({
            'type': f['type'],
            'status': 'solved' if f.get('id') in user_solved_flag_ids else 'unsolved',
            'id': f['id']
        })
    hints_data = load_json(HINTS_FILE)
    hints_taken_ids = set()
    if is_team_member:
        hints_taken_ids = {
            h['hint_index']
            for h in hints_data
            if h['challenge_id'] == challenge_id and h.get('team_id') == user['team_id']
        }
    else:
        hints_taken_ids = {
            h['hint_index']
            for h in hints_data
            if h['challenge_id'] == challenge_id and h['user_id'] == session['user_id']
        }
    hints_taken = sorted(list(hints_taken_ids))
    user_total_score = sum(s['score'] for s in scores if s['user_id'] == session['user_id'])
    challenge['rendered_description'] = render_markdown(challenge['description'])
    penalty_per_hint = int(challenge.get('base_score', 0) * 0.10)
    return render_template('challenge.html',
                           challenge=challenge,
                           hints_taken=hints_taken,
                           flags_with_status=flags_with_status,
                           user_total_score=user_total_score,
                           is_complete=is_complete,
                           team_mode=config.get('team_mode'),
                           penalty_per_hint=penalty_per_hint)

@app.route('/download_file/<challenge_id>/<filename>')
@login_required
def download_file(challenge_id, filename):
    if not is_ctf_active():
        flash("The CTF is currently not active.", "error")
        return redirect(url_for('dashboard'))
    challenges = load_json(CHALLENGES_FILE)
    challenge = next((c for c in challenges if c['id'] == challenge_id), None)
    if not challenge:
        flash("Challenge not found.", "error")
        return redirect(url_for('dashboard'))
    users = load_json(USERS_FILE)
    user = next((u for u in users if u['id'] == session['user_id']), None)
    config = get_config()
    scores = load_json(SCORES_FILE)
    user_solved_challenges = {s['challenge_id'] for s in scores if s['user_id'] == session['user_id'] and s['score'] > 0}
    required_challenges = set(challenge.get('requires', []))
    is_team_member = config.get('team_mode', False) and user.get('team_id') and user.get('team_status') == 'member'
    if is_team_member:
        team_members = [u['id'] for u in users if u.get('team_id') == user['team_id'] and u.get('team_status') == 'member']
        team_solved_challenges = {s['challenge_id'] for s in scores if s['user_id'] in team_members and s['score'] > 0}
        if required_challenges and not required_challenges.issubset(team_solved_challenges):
            flash('Your team must complete the prerequisite challenges before downloading this file.', 'error')
            return redirect(url_for('challenge_view', challenge_id=challenge_id))
    else:
        if required_challenges and not required_challenges.issubset(user_solved_challenges):
            flash('You must complete the prerequisite challenges before downloading this file.', 'error')
            return redirect(url_for('challenge_view', challenge_id=challenge_id))
    if not challenge.get('files') or filename not in challenge['files']:
        flash("File not found for this challenge.", "error")
        return redirect(url_for('challenge_view', challenge_id=challenge_id))
    filepath = os.path.join(UPLOAD_FOLDER, challenge_id, filename)
    if os.path.exists(filepath):
        return send_file(filepath, as_attachment=True)
    else:
        flash("File does not exist on the server.", "error")
        return redirect(url_for('challenge_view', challenge_id=challenge_id))

@app.route('/profile')
@app.route('/profile/<username>')
@login_required
def user_profile(username=None):
    users = load_json(USERS_FILE)
    if not username:
        user = next((u for u in users if u['id'] == session['user_id']), None)
    else:
        user = next((u for u in users if u['username'] == username), None)
    if not user:
        flash('User not found!', 'error')
        return redirect(url_for('dashboard'))
    scores = load_json(SCORES_FILE)
    user_scores = [s for s in scores if s['user_id'] == user['id']]
    total_score = sum(s['score'] for s in user_scores)
    challenges = load_json(CHALLENGES_FILE)
    solved_flags = {s['flag_id'] for s in user_scores if s['score'] > 0}
    total_solves = 0
    for challenge in challenges:
        all_flags = {f.get('id') for f in challenge.get('flags', [])}
        if all_flags and all_flags.issubset(solved_flags):
            total_solves += 1
    totals = {}
    for s in scores:
        totals[s['user_id']] = totals.get(s['user_id'], 0) + s['score']
    sorted_totals = sorted(totals.items(), key=lambda x: x[1], reverse=True)
    user_rank = None
    for rank, (uid, sc) in enumerate(sorted_totals, start=1):
        if uid == user['id']:
            user_rank = rank
            break
    recent = sorted([s for s in user_scores if s['score'] > 0], key=lambda x: x.get('timestamp', ''), reverse=True)[:5]
    avatar_url = generate_avatar_url(user)
    is_own_profile = session['user_id'] == user['id']
    teams = load_json(TEAMS_FILE)
    user_team = next((t for t in teams if t['id'] == user.get('team_id')), None)
    config = get_config()
    team_info = None
    if config.get('team_mode') and user.get('team_id') and user_team and user.get('team_status') == 'member':
        team_members = [u for u in users if u.get('team_id') == user_team['id'] and u.get('team_status') == 'member']
        team_member_ids = [m['id'] for m in team_members]
        team_members_scores = [s for s in scores if s['user_id'] in team_member_ids]
        team_total_score = sum(s['score'] for s in team_members_scores)
        all_teams = load_json(TEAMS_FILE)
        all_teams_scores = {}
        for team in all_teams:
            all_teams_scores[team['id']] = sum(s['score'] for s in scores if s['user_id'] in team['members'] and next((u for u in users if u['id'] == s['user_id']), {}).get('team_status') == 'member')
        sorted_teams = sorted(all_teams_scores.items(), key=lambda x: x[1], reverse=True)
        team_rank = next((rank for rank, (tid, _) in enumerate(sorted_teams, 1) if tid == user['team_id']), None)
        team_solves = len({s['challenge_id'] for s in team_members_scores if s['score'] > 0})
        total_challenges = len(challenges)
        team_info = {
            'name': user_team['name'],
            'total_score': team_total_score,
            'rank': team_rank,
            'solved_count': team_solves,
            'total_challenges': total_challenges
        }
    return render_template('profile.html',
                           user=user,
                           avatar_url=avatar_url,
                           total_score=total_score,
                           total_solves=total_solves,
                           user_rank=user_rank or 'Unranked',
                           recent_solves=recent,
                           is_own_profile=is_own_profile,
                           user_team=user_team,
                           team_info=team_info,
                           team_mode=config.get('team_mode'))

@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    users = load_json(USERS_FILE)
    idx = next(i for i, u in enumerate(users) if u['id'] == session['user_id'])
    user = users[idx]
    config = get_config()
    if request.method == 'POST':
        user['bio'] = request.form.get('bio', '')[:500]
        user['location'] = request.form.get('location', '')[:100]
        user['website'] = request.form.get('website', '')[:200]
        if 'regenerate_avatar' in request.form:
            user['avatar_seed'] = str(uuid.uuid4())
        save_json(USERS_FILE, users)
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('user_profile'))
    avatar_url = generate_avatar_url(user)
    return render_template('edit_profile.html', user=user, avatar_url=avatar_url, team_mode=config.get('team_mode'))

@app.route('/submit_flag', methods=['POST'])
@login_required
def submit_flag():
    if not is_ctf_active():
        return jsonify({"success": False, "message": "The CTF is currently not active."})
    challenge_id = request.form['challenge_id']
    submitted_flag = request.form['flag'].strip()
    config = get_config()
    challenges = load_json(CHALLENGES_FILE)
    challenge = next((c for c in challenges if c['id'] == challenge_id), None)
    if not challenge:
        return jsonify({"success": False, "message": "Challenge not found!"})
    users = load_json(USERS_FILE)
    user_index = next((i for i, u in enumerate(users) if u['id'] == session['user_id']), None)
    if user_index is None:
        return jsonify({"success": False, "message": "User not found!"})
    user = users[user_index]
    scores = load_json(SCORES_FILE)
    is_correct = False
    flag_id = None
    for sf in [f for f in challenge.get('flags', []) if f.get('type') == 'static']:
        if submitted_flag == sf.get('flag'):
            is_correct = True
            flag_id = sf.get('id')
            break
    if not is_correct:
        dyn = user.get('pre_generated_flags', {}).get(challenge_id, [])
        for entry in dyn:
            if submitted_flag == entry.get('flag'):
                is_correct = True
                flag_id = entry.get('id')
                break
    log_submission(session['user_id'], challenge_id, submitted_flag, is_correct, request.remote_addr)
    if not is_correct:
        return jsonify({"success": False, "message": "Incorrect flag!"})
    is_team_mode_on = config.get('team_mode', False)
    user_is_in_team = user.get('team_id') and user.get('team_status') == 'member'
    user_solved_flags = {s['flag_id'] for s in scores if s['user_id'] == session['user_id'] and s['score'] > 0}
    if not is_team_mode_on:
        if flag_id in user_solved_flags:
            message = "You have already solved this flag."
            return jsonify({"success": False, "message": message})
    if is_team_mode_on:
        if user_is_in_team:
            team_members = [u['id'] for u in users if u.get('team_id') == user['team_id']]
            team_solved_flags = {s['flag_id'] for s in scores if s['user_id'] in team_members and s['score'] > 0}
            if flag_id in team_solved_flags:
                message = "Your team has already solved this flag."
                return jsonify({"success": False, "message": message})
        else:
            if flag_id in user_solved_flags:
                message = "You have already solved this flag."
                return jsonify({"success": False, "message": message})
    is_first_blood = not any(s['challenge_id'] == challenge_id and s['score'] > 0 for s in scores)
    total_flags_count = len(challenge.get('flags', [])) or 1
    per_flag_base = challenge.get('base_score', 0) / total_flags_count
    all_users = load_json(USERS_FILE)
    unique_solvers = {s['user_id'] for s in scores if s['challenge_id'] == challenge_id and s['score'] > 0}
    dynamic = calculate_dynamic_score(per_flag_base, len(unique_solvers), len(all_users))
    final_score = dynamic
    score_entry = {
        "user_id": session['user_id'],
        "username": session['username'],
        "challenge_id": challenge_id,
        "challenge_title": challenge['title'],
        "score": final_score,
        "timestamp": datetime.now().isoformat(),
        "flag_id": flag_id
    }
    if is_first_blood:
        score_entry['first_blood'] = True
    scores.append(score_entry)
    save_json(SCORES_FILE, scores)
    recalculate_solves()
    user_team_name = next((t['name'] for t in load_json(TEAMS_FILE) if t['id'] == user.get('team_id')), None)
    if is_first_blood:
        if is_team_mode_on and user_is_in_team and user_team_name:
            log_event("team_solve_first_blood", f"FIRST BLOOD! Crew '{user_team_name}' claimed the treasure: '{challenge['title']}'!")
        else:
            log_event("solve_first_blood", f"FIRST BLOOD! '{session['username']}' found the treasure: '{challenge['title']}'!")
    else:
        if is_team_mode_on and user_is_in_team and user_team_name:
            log_event("team_solve", f"Crew '{user_team_name}' found the treasure: '{challenge['title']}'!")
        else:
            log_event("solve", f"'{session['username']}' found the treasure: '{challenge['title']}'!")
    user_solved_challenges_in_category = {s['challenge_id'] for s in scores if s['user_id'] == session['user_id'] and s['score'] > 0 and s.get('challenge_category') == challenge['category']}
    all_challenges_in_category = {c['id'] for c in challenges if c['category'] == challenge['category']}
    if all_challenges_in_category.issubset(user_solved_challenges_in_category):
        if challenge['category'] not in user.get('achievements', []):
            user.setdefault('achievements', []).append(challenge['category'])
            save_json(USERS_FILE, users)
            log_event("achievement", f"'{session['username']}' earned the achievement: '{challenge['category']} Master'!")
    message = f"Correct! You got +{final_score} points for this flag."
    return jsonify({"success": True, "message": message})

@app.route('/take_hint/<challenge_id>/<int:hint_index>', methods=['POST'])
@login_required
def take_hint(challenge_id, hint_index):
    if not is_ctf_active():
        flash("The CTF is currently not active.", "error")
        return redirect(url_for('dashboard'))
    hints_data = load_json(HINTS_FILE)
    scores_data = load_json(SCORES_FILE)
    challenges = load_json(CHALLENGES_FILE)
    users = load_json(USERS_FILE)
    user = next((u for u in users if u['id'] == session['user_id']), None)
    config = get_config()
    challenge = next((c for c in challenges if c['id'] == challenge_id), None)
    if not challenge:
        flash('Challenge not found!', 'error')
        return redirect(url_for('dashboard'))
    is_team_member = config.get('team_mode', False) and user.get('team_id') and user.get('team_status') == 'member'
    hint_already_taken = False
    if is_team_member:
        if any(h['challenge_id'] == challenge_id and h['hint_index'] == hint_index and h.get('team_id') == user['team_id'] for h in hints_data):
            hint_already_taken = True
    else:
        if any(h['user_id'] == session['user_id'] and h['challenge_id'] == challenge_id and h['hint_index'] == hint_index for h in hints_data):
            hint_already_taken = True
    if hint_already_taken:
        flash("This hint has already been unlocked. No further penalty will be applied.", 'info')
        return redirect(url_for('challenge_view', challenge_id=challenge_id))
    penalty_per_hint = int(challenge.get('base_score', 0) * 0.10)
    user_current_score = sum(s['score'] for s in scores_data if s['user_id'] == session['user_id'])
    if user_current_score < penalty_per_hint:
        flash("You don't have enough points to claim this hint. Solve other challenges first!", 'error')
        return redirect(url_for('challenge_view', challenge_id=challenge_id))
    hint_entry = {
        "user_id": session['user_id'],
        "challenge_id": challenge_id,
        "hint_index": hint_index,
        "timestamp": datetime.now().isoformat()
    }
    if is_team_member:
        hint_entry['team_id'] = user['team_id']
    hints_data.append(hint_entry)
    penalty_score_entry = {
        "user_id": session['user_id'],
        "username": session['username'],
        "challenge_id": challenge_id,
        "challenge_title": challenge['title'],
        "score": -penalty_per_hint,
        "timestamp": datetime.now().isoformat(),
        "flag_id": f"HINT_PENALTY_{challenge_id}_{hint_index}"
    }
    scores_data.append(penalty_score_entry)
    save_json(HINTS_FILE, hints_data)
    save_json(SCORES_FILE, scores_data)
    recalculate_solves()
    flash("Hint claimed! Your score has been reduced by a penalty.", 'info')
    return redirect(url_for('challenge_view', challenge_id=challenge_id))

@app.route('/scoreboard')
def scoreboard():
    recalculate_solves()
    scores = load_json(SCORES_FILE)
    users = load_json(USERS_FILE)
    config = get_config()
    user_scores = {u['id']: {'total': 0, 'solves': set()} for u in users}
    for s in scores:
        user_scores[s['user_id']]['total'] += s['score']
        if s['score'] > 0:
            user_scores[s['user_id']]['solves'].add(s['challenge_id'])
    unified_leaderboard = []
    if config.get('team_mode', False):
        teams = load_json(TEAMS_FILE)
        team_leaderboard = []
        for team in teams:
            team_total_score = 0
            team_solves = set()
            team_members_info = []
            team_members = [u for u in users if u.get('team_id') == team['id'] and u.get('team_status') == 'member']
            team_member_ids = [m['id'] for m in team_members]
            team_scores_list = [s for s in scores if s['user_id'] in team_member_ids]
            team_total_score = sum(s['score'] for s in team_scores_list)
            team_solves = {s['challenge_id'] for s in team_scores_list if s['score'] > 0}
            for member_user in team_members:
                team_members_info.append(member_user['username'])
            team_leaderboard.append({
                'name': team['name'],
                'total': team_total_score,
                'solves': len(team_solves),
                'members': team_members_info,
                'is_team': True
            })
        team_leaderboard = sorted(team_leaderboard, key=lambda x: x['total'], reverse=True)
        unified_leaderboard.extend(team_leaderboard)
    solo_players = [u for u in users if u.get('team_status') != 'member']
    solo_leaderboard = []
    for solo_user in solo_players:
        solo_id = solo_user['id']
        solo_leaderboard.append({
            'name': solo_user['username'],
            'total': user_scores.get(solo_id, {'total': 0})['total'],
            'solves': len(user_scores.get(solo_id, {'solves': set()})['solves']),
            'is_team': False,
            'status': solo_user.get('team_status')
        })
    solo_leaderboard = sorted(solo_leaderboard, key=lambda x: x['total'], reverse=True)
    unified_leaderboard.extend(solo_leaderboard)
    unified_leaderboard = sorted(unified_leaderboard, key=lambda x: x['total'], reverse=True)
    return render_template('scoreboard.html',
                           leaderboard=unified_leaderboard,
                           team_mode=config.get('team_mode', False),
                           config=config)

@app.route('/teams')
@login_required
def teams_list():
    config = get_config()
    if not config.get('team_mode', False):
        flash("Team mode is not enabled.", "error")
        return redirect(url_for('dashboard'))
    teams = load_json(TEAMS_FILE)
    users = load_json(USERS_FILE)
    for team in teams:
        team_members = [u for u in users if u.get('team_id') == team['id'] and u.get('team_status') == 'member']
        team['member_count'] = len(team_members)
    user = next((u for u in users if u['id'] == session['user_id']), None)
    user_team = next((t for t in teams if t['id'] == user.get('team_id')), None)
    team_solves_by_member = {}
    if user_team:
        scores = load_json(SCORES_FILE)
        challenges = load_json(CHALLENGES_FILE)
        challenge_map = {c['id']: c['title'] for c in challenges}
        team_members = [u for u in users if u.get('team_id') == user_team['id'] and u.get('team_status') == 'member']
        for member_user in team_members:
            member_solves = [s for s in scores if s['user_id'] == member_user['id'] and s['score'] > 0]
            member_solves.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
            team_solves_by_member[member_user['username']] = [{
                'challenge_title': challenge_map.get(s['challenge_id'], 'Unknown Challenge'),
                'timestamp': s['timestamp']
            } for s in member_solves]
    return render_template('teams.html',
                           teams=teams,
                           user_team=user_team,
                           team_mode=config.get('team_mode'),
                           user=user,
                           team_solves_by_member=team_solves_by_member)

@app.route('/teams/create', methods=['GET', 'POST'])
@login_required
def create_team():
    config = get_config()
    if not config.get('team_mode', False):
        flash("Team mode is not enabled.", "error")
        return redirect(url_for('dashboard'))
    users = load_json(USERS_FILE)
    user = next((u for u in users if u['id'] == session['user_id']), None)
    scores = load_json(SCORES_FILE)
    if get_user_total_score(user['id'], scores) > 0:
        flash("You cannot create a team if you already have a score.", "error")
        return redirect(url_for('dashboard'))
    if user.get('team_id'):
        flash("You are already in a team.", "error")
        return redirect(url_for('teams_list'))
    if request.method == 'POST':
        team_name = request.form.get('team_name').strip()
        if len(team_name) > 24:
            flash("Team name must be 24 characters or less.", 'error')
            return redirect(url_for('create_team'))
        teams = load_json(TEAMS_FILE)
        if not team_name:
            flash("Team name cannot be empty.", "error")
            return redirect(url_for('create_team'))
        if any(t['name'] == team_name for t in teams):
            flash("Team name already exists. Please choose a different name.", "error")
            return redirect(url_for('create_team'))
        new_team = {
            'id': str(uuid.uuid4()),
            'name': team_name,
            'creator_id': session['user_id'],
            'members': [session['user_id']],
            'pending_members': []
        }
        teams.append(new_team)
        save_json(TEAMS_FILE, teams)
        user['team_id'] = new_team['id']
        user['team_status'] = 'member'
        save_json(USERS_FILE, users)
        log_event("team_create", f"Crew '{team_name}' was formed by '{session['username']}'!")
        flash("Team created successfully!", "success")
        return redirect(url_for('teams_list'))
    return render_template('create_team.html', team_mode=config.get('team_mode'))

@app.route('/teams/join/<team_id>', methods=['POST'])
@login_required
def join_team(team_id):
    config = get_config()
    if not config.get('team_mode', False):
        flash("Team mode is not enabled.", "error")
        return redirect(url_for('dashboard'))
    teams = load_json(TEAMS_FILE)
    users = load_json(USERS_FILE)
    scores = load_json(SCORES_FILE)
    user_id = session['user_id']
    user = next((u for u in users if u['id'] == user_id), None)
    if user.get('team_id'):
        flash("You are already in a team.", "error")
        return redirect(url_for('teams_list'))
    if get_user_total_score(user_id, scores) > 0:
        flash("You can only join a team if your current score is 0.", "error")
        return redirect(url_for('teams_list'))
    team = next((t for t in teams if t['id'] == team_id), None)
    if not team:
        flash("Team not found.", "error")
        return redirect(url_for('teams_list'))
    if user_id in team['pending_members'] or user_id in team['members']:
        flash("You have already requested to join or are a member of this team.", "info")
        return redirect(url_for('teams_list'))
    team['pending_members'].append(user_id)
    save_json(TEAMS_FILE, teams)
    user['team_id'] = team_id
    user['team_status'] = 'pending'
    save_json(USERS_FILE, users)
    log_event("team_join_request", f"'{session['username']}' requested to join crew '{team['name']}'.")
    flash("Your request to join has been sent to the team leader for approval.", "success")
    return redirect(url_for('teams_list'))

@app.route('/teams/withdraw_request/<team_id>', methods=['POST'])
@login_required
def withdraw_join_request(team_id):
    users = load_json(USERS_FILE)
    teams = load_json(TEAMS_FILE)
    user_idx = next((i for i, u in enumerate(users) if u['id'] == session['user_id']), None)
    team_idx = next((i for i, t in enumerate(teams) if t['id'] == team_id), None)
    if user_idx is None or team_idx is None:
        flash("User or team not found.", "error")
        return redirect(url_for('teams_list'))
    user = users[user_idx]
    team = teams[team_idx]
    if user['team_status'] == 'pending' and user['team_id'] == team_id:
        if session['user_id'] in team['pending_members']:
            team['pending_members'].remove(session['user_id'])
            user['team_id'] = None
            user['team_status'] = 'none'
            save_json(TEAMS_FILE, teams)
            save_json(USERS_FILE, users)
            log_event("team_request_withdrawn", f"'{session['username']}' withdrew their request to join crew '{team['name']}'.")
            flash("Your request to join the team has been withdrawn.", "success")
        else:
            flash("Request not found in pending list.", "error")
    else:
        flash("You do not have a pending request for this team.", "error")
    return redirect(url_for('teams_list'))

@app.route('/teams/manage/<team_id>')
@login_required
@team_leader_required
def manage_team(team_id):
    teams = load_json(TEAMS_FILE)
    users = load_json(USERS_FILE)
    config = get_config()
    team = next((t for t in teams if t['id'] == team_id), None)
    if not team:
        flash("Team not found.", "error")
        return redirect(url_for('dashboard'))
    pending_users = [u for u in users if u['id'] in team['pending_members']]
    return render_template('manage_team.html', team=team, pending_users=pending_users, team_mode=config.get('team_mode'))

@app.route('/teams/approve/<team_id>/<user_id>', methods=['POST'])
@login_required
@team_leader_required
def approve_join_request(team_id, user_id):
    teams = load_json(TEAMS_FILE)
    users = load_json(USERS_FILE)
    scores_data = load_json(SCORES_FILE)
    team_idx = next((i for i, t in enumerate(teams) if t['id'] == team_id), None)
    user_idx = next((i for i, u in enumerate(users) if u['id'] == user_id), None)
    if team_idx is None or user_idx is None:
        return jsonify({"success": False, "message": "Team or user not found."})
    team = teams[team_idx]
    user = users[user_idx]
    if get_user_total_score(user['id'], scores_data) > 0:
        flash(f"User '{user['username']}' cannot join a team with a non-zero score. They must be a solo competitor.", 'error')
        return redirect(url_for('manage_team', team_id=team_id))
    if user_id in team['pending_members']:
        team['pending_members'].remove(user_id)
        team['members'].append(user_id)
        user['team_status'] = 'member'
        save_json(TEAMS_FILE, teams)
        save_json(USERS_FILE, users)
        log_event("team_join", f"'{user['username']}' was approved to join crew '{team['name']}'.")
        flash(f"Approved {user['username']} to join the team.", "success")
        return jsonify({"success": True})
    return jsonify({"success": False, "message": "User is not in the pending list."})

@app.route('/teams/reject/<team_id>/<user_id>', methods=['POST'])
@login_required
@team_leader_required
def reject_join_request(team_id, user_id):
    teams = load_json(TEAMS_FILE)
    users = load_json(USERS_FILE)
    team_idx = next((i for i, t in enumerate(teams) if t['id'] == team_id), None)
    user_idx = next((i for i, u in enumerate(users) if u['id'] == user_id), None)
    if team_idx is None or user_idx is None:
        return jsonify({"success": False, "message": "Team or user not found."})
    team = teams[team_idx]
    user = users[user_idx]
    if user_id in team['pending_members']:
        team['pending_members'].remove(user_id)
        user['team_id'] = None
        user['team_status'] = 'none'
        save_json(TEAMS_FILE, teams)
        save_json(USERS_FILE, users)
        log_event("team_request_rejected", f"'{user['username']}' was rejected from joining crew '{team['name']}'.")
        flash(f"Rejected {user['username']}'s request to join the team.", "success")
        return jsonify({"success": True})
    return jsonify({"success": False, "message": "User is not in the pending list."})

@app.route('/teams/leave/<team_id>', methods=['POST'])
@login_required
def leave_team(team_id):
    teams = load_json(TEAMS_FILE)
    users = load_json(USERS_FILE)
    scores = load_json(SCORES_FILE)
    user = next((u for u in users if u['id'] == session['user_id']), None)
    if not user or user.get('team_id') != team_id:
        flash("You are not a member of this team.", "error")
        return redirect(url_for('teams_list'))
    team_idx = next((i for i, t in enumerate(teams) if t['id'] == team_id), None)
    if team_idx is None:
        flash("Team not found.", "error")
        return redirect(url_for('teams_list'))
    team = teams[team_idx]
    is_leader = team['creator_id'] == session['user_id']
    is_only_member = len(team['members']) == 1
    team_total_score = get_team_total_score(team_id, scores, users)
    user_score_in_team = get_user_score_after_join(user['id'], team['id'], scores, users)
    if not is_leader and team_total_score > 0:
        flash("This team has already scored points. Members cannot leave once points are scored.", "error")
        return redirect(url_for('teams_list'))
    if not is_leader and team_total_score == 0 and user_score_in_team > 0:
        flash("You have contributed points to this team. You cannot leave with a score on your record while on a team.", "error")
        return redirect(url_for('teams_list'))
    if is_leader:
        if not is_only_member:
            flash("As the team leader, you cannot leave a team with other members. You must disband it after all members have left.", "error")
            return redirect(url_for('teams_list'))
        else:
            if team_total_score > 0:
                flash("You cannot disband a team with a non-zero score.", "error")
                return redirect(url_for('teams_list'))
            else:
                teams.pop(team_idx)
                user['team_id'] = None
                user['team_status'] = 'none'
                save_json(TEAMS_FILE, teams)
                save_json(USERS_FILE, users)
                log_event("team_disband", f"Crew '{team['name']}' was disbanded by '{session['username']}'.")
                flash("Team disbanded successfully.", "success")
                return redirect(url_for('dashboard'))
    if session['user_id'] in team['members'] and user_score_in_team == 0 and team_total_score == 0:
        team['members'].remove(session['user_id'])
        user['team_id'] = None
        user['team_status'] = 'none'
        save_json(TEAMS_FILE, teams)
        save_json(USERS_FILE, users)
        log_event("team_leave", f"'{session['username']}' has left crew '{team['name']}'.")
        flash("You have left the team.", "success")
        return redirect(url_for('dashboard'))
    return redirect(url_for('teams_list'))

# ==============
# Admin area
# ==============
@app.route('/admin')
@admin_required
def admin_panel():
    config = get_config()
    return render_template('admin/panel.html', team_mode=config.get('team_mode'))

@app.route('/admin/config', methods=['GET', 'POST'])
@admin_required
def admin_config():
    if request.method == 'POST':
        config = {
            "ctf_active": 'ctf_active' in request.form,
            "ctf_start": request.form['ctf_start'],
            "ctf_end": request.form['ctf_end'],
            "dynamic_scoring": 'dynamic_scoring' in request.form,
            "team_mode": 'team_mode' in request.form,
            "rate_limit": int(request.form['rate_limit']),
            "min_score": int(request.form['min_score']),
            "telegram_bot_token": request.form['telegram_bot_token'],
            "telegram_chat_id": request.form['telegram_chat_id']
        }
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
        recalculate_solves()
        flash('Configuration updated!', 'success')
    config = get_config()
    return render_template('admin/config.html', config=config)

@app.route('/admin/challenges', methods=['GET', 'POST'])
@admin_required
def admin_challenges():
    challenges = load_json(CHALLENGES_FILE)
    if request.method == 'POST':
        action = request.form['action']
        if action in ['add', 'edit']:
            challenge_id = request.form.get('id', str(uuid.uuid4()))
            flag_types = request.form.getlist('flag_type[]')
            flag_values = request.form.getlist('flag_value[]')
            flag_ids = request.form.getlist('flag_id[]') if 'flag_id[]' in request.form else []
            challenge_flags = []
            for i, ftype in enumerate(flag_types):
                fid = flag_ids[i] if i < len(flag_ids) and flag_ids[i] else str(uuid.uuid4())
                fdata = {"id": fid, "type": ftype}
                if ftype == 'static':
                    fdata['flag'] = flag_values[i]
                elif ftype == 'dynamic':
                    fdata['base_flag'] = flag_values[i]
                challenge_flags.append(fdata)
            category = request.form.get('category')
            new_category = request.form.get('new_category', '').strip()
            final_category = new_category if new_category else category
            new_challenge_data = {
                "id": challenge_id,
                "title": request.form['title'],
                "description": request.form['description'],
                "category": final_category,
                "base_score": int(request.form['base_score']),
                "difficulty": request.form['difficulty'],
                "visible": 'visible' in request.form,
                "solves": 0,
                "requires": [r.strip() for r in request.form.get('requires', '').split(',') if r.strip()],
                "hints": [request.form.get(f'hint{i}', '').strip() for i in range(1, 4) if request.form.get(f'hint{i}')],
                "flags": challenge_flags,
                "files": []
            }
            users = load_json(USERS_FILE)
            if action == 'add':
                challenges.append(new_challenge_data)
                for u in users:
                    pre_generate_flags_for_user(u, [new_challenge_data])
                save_json(USERS_FILE, users)
                flash('Challenge added!', 'success')
            elif action == 'edit':
                for i, c in enumerate(challenges):
                    if c['id'] == challenge_id:
                        new_challenge_data['solves'] = c.get('solves', 0)
                        new_challenge_data['files'] = c.get('files', [])
                        challenges[i] = new_challenge_data
                        dynamic_base_flags = [f for f in new_challenge_data.get('flags', []) if f.get('type') == 'dynamic']
                        if dynamic_base_flags:
                            for u in users:
                                u.setdefault('pre_generated_flags', {})[new_challenge_data['id']] = generate_full_flags(
                                    u['email'],
                                    new_challenge_data['id'],
                                    FLAG_GENERATION_SECRET,
                                    dynamic_base_flags
                                )
                        else:
                            for u in users:
                                if 'pre_generated_flags' in u and new_challenge_data['id'] in u['pre_generated_flags']:
                                    del u['pre_generated_flags'][new_challenge_data['id']]
                        save_json(USERS_FILE, users)
                        flash('Challenge updated!', 'success')
                        break
            save_json(CHALLENGES_FILE, challenges)
            recalculate_solves()
        elif action == 'delete':
            challenge_id = request.form['challenge_id']
            challenges = [c for c in challenges if c['id'] != challenge_id]
            save_json(CHALLENGES_FILE, challenges)
            users = load_json(USERS_FILE)
            for u in users:
                if 'pre_generated_flags' in u and challenge_id in u['pre_generated_flags']:
                    del u['pre_generated_flags'][challenge_id]
            save_json(USERS_FILE, users)
            recalculate_solves()
            flash('Challenge deleted!', 'success')
    challenges = load_json(CHALLENGES_FILE)
    categories = sorted(list({c['category'] for c in challenges}))
    return render_template('admin/challenges.html', challenges=challenges, categories=categories, config=get_config())

@app.route('/admin/challenges/edit/<challenge_id>')
@admin_required
def edit_challenge(challenge_id):
    challenges = load_json(CHALLENGES_FILE)
    challenge = next((c for c in challenges if c['id'] == challenge_id), None)
    if not challenge:
        flash('Challenge not found!', 'error')
        return redirect(url_for('admin_challenges'))
    categories = sorted(list({c['category'] for c in challenges}))
    return render_template('admin/edit_challenge.html', challenge=challenge, categories=categories, config=get_config())

@app.route('/admin/users')
@admin_required
def admin_users():
    users = load_json(USERS_FILE)
    logins = load_json(LOGINS_FILE)
    search_query = request.args.get('search_query', '').strip().lower()
    if search_query:
        users = [u for u in users if search_query in u['username'].lower() or search_query in u['email'].lower()]
    return render_template('admin/users.html', users=users, logins=logins, search_query=search_query, config=get_config())

@app.route('/admin/promote/<user_id>', methods=['POST'])
@admin_required
def promote_user(user_id):
    users = load_json(USERS_FILE)
    user = next((u for u in users if u['id'] == user_id), None)
    if not user:
        flash('User not found!', 'error')
    else:
        user['is_admin'] = True
        save_json(USERS_FILE, users)
        flash(f"User {user['username']} promoted to admin!", 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/ban/<user_id>', methods=['POST'])
@admin_required
def ban_user(user_id):
    users = load_json(USERS_FILE)
    user = next((u for u in users if u['id'] == user_id), None)
    if not user:
        flash('User not found!', 'error')
    else:
        user['is_banned'] = True
        save_json(USERS_FILE, users)
        flash(f"User {user['username']} has been banned.", 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/deban/<user_id>', methods=['POST'])
@admin_required
def deban_user(user_id):
    users = load_json(USERS_FILE)
    user = next((u for u in users if u['id'] == user_id), None)
    if not user:
        flash('User not found!', 'error')
    else:
        user['is_banned'] = False
        save_json(USERS_FILE, users)
        flash(f"User {user['username']} has been unbanned.", 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/announcements', methods=['GET', 'POST'])
@admin_required
def admin_announcements():
    if request.method == 'POST':
        announcement_id = str(uuid.uuid4())
        announcements = load_json(ANNOUNCEMENTS_FILE)
        announcements.append({
            "id": announcement_id,
            "title": request.form['title'],
            "content": request.form['content'],
            "timestamp": datetime.now().isoformat()
        })
        save_json(ANNOUNCEMENTS_FILE, announcements)
        log_event("announcement", f"News Coo: {request.form['title']}")
        flash('Announcement added!', 'success')
    announcements = load_json(ANNOUNCEMENTS_FILE)
    return render_template('admin/announcements.html', announcements=announcements, config=get_config())

@app.route('/admin/announcements/delete/<announcement_id>', methods=['POST'])
@admin_required
def delete_announcement(announcement_id):
    announcements = load_json(ANNOUNCEMENTS_FILE)
    updated = [a for a in announcements if a.get('id') != announcement_id]
    if len(updated) == len(announcements):
        return jsonify({"success": False, "message": "Announcement not found!"})
    save_json(ANNOUNCEMENTS_FILE, updated)
    return jsonify({"success": True, "message": "Announcement deleted successfully!"})

@app.route('/admin/submissions')
@admin_required
def admin_submissions():
    submissions = load_json(SUBMISSIONS_FILE)
    return render_template('admin/submissions.html', submissions=submissions, config=get_config())

@app.route('/admin/rules', methods=['GET', 'POST'])
@admin_required
def admin_rules():
    if request.method == 'POST':
        rules_content = request.form['rules_content']
        with open(RULES_FILE, 'w') as f:
            f.write(rules_content)
        flash('Rules updated successfully!', 'success')
        return redirect(url_for('admin_rules'))
    return render_template('admin/rules.html', rules_content=get_rules(), config=get_config())

@app.route('/admin/upload_file/<challenge_id>', methods=['POST'])
@admin_required
def admin_upload_file(challenge_id):
    if 'file' not in request.files:
        flash('No file part', 'error')
        return redirect(url_for('edit_challenge', challenge_id=challenge_id))
    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'error')
        return redirect(url_for('edit_challenge', challenge_id=challenge_id))
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        challenge_dir = os.path.join(UPLOAD_FOLDER, challenge_id)
        os.makedirs(challenge_dir, exist_ok=True)
        filepath = os.path.join(challenge_dir, filename)
        file.save(filepath)
        challenges = load_json(CHALLENGES_FILE)
        for c in challenges:
            if c['id'] == challenge_id:
                if 'files' not in c:
                    c['files'] = []
                if filename not in c['files']:
                    c['files'].append(filename)
                break
        save_json(CHALLENGES_FILE, challenges)
        flash(f'File "{filename}" uploaded successfully!', 'success')
    else:
        flash('File type not allowed!', 'error')
    return redirect(url_for('edit_challenge', challenge_id=challenge_id))

@app.route('/admin/delete_file/<challenge_id>/<filename>', methods=['POST'])
@admin_required
def admin_delete_file(challenge_id, filename):
    challenges = load_json(CHALLENGES_FILE)
    challenge_idx = next((i for i, c in enumerate(challenges) if c['id'] == challenge_id), None)
    if challenge_idx is None:
        flash("Challenge not found.", "error")
        return redirect(url_for('admin_challenges'))
    challenge = challenges[challenge_idx]
    if 'files' in challenge and filename in challenge['files']:
        challenge['files'].remove(filename)
        save_json(CHALLENGES_FILE, challenges)
        filepath = os.path.join(UPLOAD_FOLDER, challenge_id, filename)
        if os.path.exists(filepath):
            os.remove(filepath)
        flash(f'File "{filename}" deleted successfully!', 'success')
    else:
        flash("File not found for this challenge.", "error")
    return redirect(url_for('edit_challenge', challenge_id=challenge_id))

@app.route('/admin/reset', methods=['GET', 'POST'])
@admin_required
def admin_reset():
    if request.method == 'POST':
        config = get_config()
        bot_token = config.get('telegram_bot_token')
        chat_id = config.get('telegram_chat_id')
        json_files = [
            USERS_FILE, CHALLENGES_FILE, SCORES_FILE, SUBMISSIONS_FILE,
            ANNOUNCEMENTS_FILE, CONFIG_FILE, LOGINS_FILE, TEAMS_FILE, HINTS_FILE, EVENT_FEED_FILE
        ]
        for fp in json_files:
            if os.path.exists(fp):
                send_file_to_telegram(fp, bot_token, chat_id)
        save_json(SCORES_FILE, [])
        save_json(SUBMISSIONS_FILE, [])
        save_json(LOGINS_FILE, [])
        save_json(HINTS_FILE, [])
        save_json(TEAMS_FILE, [])
        save_json(EVENT_FEED_FILE, [])
        users = load_json(USERS_FILE)
        admin_users = [u for u in users if u.get('is_admin', False)]
        save_json(USERS_FILE, admin_users)
        challenges = load_json(CHALLENGES_FILE)
        for c in challenges:
            c['solves'] = 0
            c['files'] = []
        save_json(CHALLENGES_FILE, challenges)
        flash('CTF Reset Complete!', 'success')
    return render_template('admin/reset.html', config=get_config())

@app.route('/admin/download/<filename>')
@admin_required
def admin_download_file(filename):
    allowed = [
        'users.json', 'challenges.json', 'scores.json', 'submissions.json',
        'announcements.json', 'config.json', 'logins.json', 'teams.json', 'hints.json', 'event_feed.json'
    ]
    if filename not in allowed:
        abort(404)
    path = os.path.join(DATA_DIR, filename)
    if not os.path.exists(path):
        abort(404)
    return send_file(path, as_attachment=True)

# ============
# Entrypoint
# ============
if __name__ == '__main__':
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    for fp in [USERS_FILE, CHALLENGES_FILE, SCORES_FILE, SUBMISSIONS_FILE, ANNOUNCEMENTS_FILE, LOGINS_FILE, TEAMS_FILE, HINTS_FILE, EVENT_FEED_FILE]:
        if not os.path.exists(fp):
            save_json(fp, [])
    if not os.path.exists(CONFIG_FILE):
        get_config()
    if not os.path.exists(RULES_FILE):
        get_rules()
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    app.run(debug=debug, host='0.0.0.0', port=port)