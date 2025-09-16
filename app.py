import os
import logging
import shutil
import random
import string
from flask import Flask, render_template, redirect, url_for, request, flash, get_flashed_messages
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import uuid

db_folder = 'database'
os.makedirs(db_folder, exist_ok=True)
os.makedirs(os.path.join(db_folder, 'users'), exist_ok=True)
os.makedirs(os.path.join(db_folder, 'users', 'system'), exist_ok=True)
os.makedirs(os.path.join(db_folder, 'users', 'admin'), exist_ok=True)
os.makedirs('media/upload', exist_ok=True)
os.makedirs('media/server', exist_ok=True)

server_log_file = os.path.join(db_folder, 'serverlog.txt')
master_log_file = os.path.join(db_folder, 'masterlog.txt')

class DividerFileHandler(logging.FileHandler):
    def __init__(self, filename, *args, **kwargs):
        super().__init__(filename, *args, **kwargs)
        self.divider_written = False
    def emit(self, record):
        msg = self.format(record)
        if not self.divider_written:
            if "Debugger PIN:" in msg or "Press CTRL+C to quit" in msg:
                super().emit(record)
                super().emit(logging.makeLogRecord({
                    'msg': '='*64 + ' SERVER LOG DIVIDER ' + '='*64,
                    'levelno': logging.INFO,
                    'levelname': 'INFO'
                }))
                self.divider_written = True
                return
        super().emit(record)

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[
        DividerFileHandler(server_log_file, encoding='utf-8'),
        logging.StreamHandler()
    ]
)

db_path = os.path.abspath(os.path.join(db_folder, 'database.db'))

app = Flask(__name__, static_folder='media')
app.config['UPLOAD_FOLDER'] = 'media/upload'
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

def log_action(userid, action, details=""):
    entry = f"{datetime.now().strftime('%Y-%m-%d > %H:%M:%S')} > {userid} > {action} > {details}"
    major_actions = [
        'login', 'logout', 'create_user', 'view_dashboard',
        'upload_photo', 'download_photo', 'user_created', 'change_admin_status', 'delete_user'
    ]
    if action in major_actions:
        with open(master_log_file, 'a', encoding='utf-8') as f:
            f.write(entry + '\n')
        logging.info(entry)
    user_log_dir = os.path.join(db_folder, 'users', str(userid))
    os.makedirs(user_log_dir, exist_ok=True)
    user_log_file = os.path.join(user_log_dir, 'logs.txt')
    with open(user_log_file, 'a', encoding='utf-8') as f:
        f.write(entry + '\n')

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class Photo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    uploader_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_base_username(first, middle, last):
    first = first.lower()
    middle = middle.lower() if middle else ''
    last = last.lower()

    if not first or not last:
        return ''

    if middle and len(last) >= 2:
        base = first[0] + middle[0] + last[-2:]
    elif len(first) >= 2 and len(last) >= 2:
        base = first[:2] + last[-2:]
    else:
        base = (first[0] + (middle[0] if middle else '') + last)[:4]
        if len(base) < 4:
            pad_source = last + first + middle
            idx = 0
            while len(base) < 4:
                if idx >= len(pad_source):
                    base += 'x'
                else:
                    base += pad_source[idx]
                idx += 1

    if len(base) > 5:
        base = base[:5]

    return base

def generate_unique_username(base_username):
    username = base_username
    attempts = 0
    while User.query.filter_by(username=username).first():
        attempts += 1
        if len(username) < 5:
            username += random.choice(string.ascii_lowercase + string.digits)
        else:
            username = username[:-1] + random.choice(string.ascii_lowercase + string.digits)
        if attempts > 10:
            username = username + str(random.randint(0,9))
    return username

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            log_action(user.username, "login", f"username: {user.username}")
            return redirect(url_for('dashboard'))
        else:
            log_action(username, "failed_login", "invalid credentials")
            flash('Invalid username or password', 'login')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    log_action(current_user.username, "logout", f"username: {current_user.username}")
    logout_user()
    flash('Logged out successfully', 'login')
    return redirect(url_for('login'))

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))

    users = User.query.filter(User.username != 'admin').order_by(User.username.asc()).all()
    activity_logs = []
    if os.path.exists(master_log_file):
        with open(master_log_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            activity_logs = [line.strip() for line in lines[-100:]]
            activity_logs.reverse()

    if request.method == 'POST':
        if 'register_user' in request.form:
            first_name = request.form.get('first_name', '').strip()
            middle_name = request.form.get('middle_name', '').strip()
            last_name = request.form.get('last_name', '').strip()
            is_admin = bool(request.form.get('is_admin', False))

            if not first_name or not last_name:
                flash('First and last name are required.', 'error')
                return redirect(url_for('admin_dashboard'))

            base_username = generate_base_username(first_name, middle_name, last_name)
            if base_username == '':
                flash('Invalid name input for username.', 'error')
                return redirect(url_for('admin_dashboard'))

            unique_username = generate_unique_username(base_username)
            default_password = 'welcome'
            hashed_pw = generate_password_hash(default_password)
            user = User(username=unique_username, password=hashed_pw, is_admin=is_admin)
            db.session.add(user)
            db.session.commit()
            flash(f'New user created with UserID: {unique_username} and password: welcome', 'info')
            log_action(current_user.username, "user_created", unique_username)
            return redirect(url_for('admin_dashboard'))

        elif 'manage_user_action' in request.form:
            selected_username = request.form.get('selected_user')
            action = request.form.get('action')
            if not selected_username:
                flash("Please select a user.", 'error')
                return redirect(url_for('admin_dashboard'))

            user = User.query.filter_by(username=selected_username).first()
            if not user:
                flash("User not found.", 'error')
                return redirect(url_for('admin_dashboard'))

            if user.username == current_user.username and action == 'delete':
                flash("You cannot delete yourself.", 'error')
                return redirect(url_for('admin_dashboard'))

            if action == 'info':
                flash(f"User: {user.username}, Admin Rights: {'Yes' if user.is_admin else 'No'}", 'info')
            elif action == 'make_admin':
                if not user.is_admin:
                    user.is_admin = True
                    db.session.commit()
                    flash(f"Admin rights granted to {user.username}.", 'info')
                    log_action(current_user.username, 'change_admin_status', f'granted admin to {user.username}')
            elif action == 'remove_admin':
                if user.is_admin:
                    user.is_admin = False
                    db.session.commit()
                    flash(f"Admin rights removed from {user.username}.", 'info')
                    log_action(current_user.username, 'change_admin_status', f'removed admin from {user.username}')
            elif action == 'delete':
                db.session.delete(user)
                db.session.commit()
                user_folder = os.path.join(db_folder, 'users', user.username)
                if os.path.exists(user_folder):
                    shutil.rmtree(user_folder)
                flash(f"User {user.username} deleted.", 'info')
                log_action(current_user.username, 'delete_user', f'deleted user {user.username}')
            else:
                flash("Invalid action.", 'error')
            return redirect(url_for('admin_dashboard'))

    return render_template('admin/dashboard_admin.html', users=users, activity_logs=activity_logs)

@app.route('/dashboard')
@login_required
def dashboard():
    photos = Photo.query.all()
    users = []
    is_admin_panel = False
    if current_user.is_admin:
        others = User.query.filter(User.username != current_user.username).order_by(User.username.asc()).all()
        users = [current_user] + others
        is_admin_panel = True
    return render_template('dashboard.html', photos=photos, current_user=current_user, users=users, is_admin_panel=is_admin_panel)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        if 'photo' not in request.files:
            flash('No file part', 'error')
            return redirect(request.url)
        file = request.files['photo']
        if file.filename == '':
            flash('No selected file', 'error')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = f"{current_user.username}_{uuid.uuid4().hex}_{secure_filename(file.filename)}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            photo = Photo(filename=filename, uploader_id=current_user.id)
            db.session.add(photo)
            db.session.commit()
            log_action(current_user.username, "upload_photo", f"filename: {filename}")
            flash('Photo uploaded successfully', 'info')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid file type', 'error')
    return render_template('upload.html')

@app.route('/download/<int:photo_id>')
@login_required
def download(photo_id):
    photo = Photo.query.get_or_404(photo_id)
    log_action(current_user.username, "download_photo", f"filename: {photo.filename}")
    return redirect(url_for('static', filename='upload/' + photo.filename))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        os.makedirs(os.path.join(db_folder, 'users', 'system'), exist_ok=True)
        os.makedirs(os.path.join(db_folder, 'users', 'admin'), exist_ok=True)
        if not User.query.filter_by(username='admin').first():
            admin_user = User(
                username='admin',
                password=generate_password_hash('admin'),
                is_admin=True
            )
            db.session.add(admin_user)
            db.session.commit()
            print("Default admin user created: admin/admin")
            log_action("system", "user_created", "[DEFAULT] system created admin")
    app.run(debug=True)
