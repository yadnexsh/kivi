import os
import logging
import shutil

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

from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import uuid
from datetime import datetime

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

    msg = None
    users = User.query.filter(User.username != 'admin').order_by(User.username.asc()).all()

    # Read last 100 entries from masterlog.txt for activity and reverse for newest on top
    activity_logs = []
    if os.path.exists(master_log_file):
        with open(master_log_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            activity_logs = [line.strip() for line in lines[-100:]]
            activity_logs.reverse()

    if request.method == 'POST':
        if 'register_user' in request.form:
            reg_username = request.form.get('username')
            reg_password = request.form.get('password')
            reg_is_admin = bool(request.form.get('is_admin', False))
            if not reg_username or not reg_password:
                msg = 'Please fill out all fields for registration.'
            elif User.query.filter_by(username=reg_username).first():
                msg = 'Username already taken.'
            else:
                hashed_pw = generate_password_hash(reg_password)
                user = User(username=reg_username, password=hashed_pw, is_admin=reg_is_admin)
                db.session.add(user)
                db.session.commit()
                user_log_dir = os.path.join(db_folder, 'users', str(user.username))
                os.makedirs(user_log_dir, exist_ok=True)
                creation_detail = f"created user {user.username} by {current_user.username}"
                log_action(current_user.username, "user_created", creation_detail)
                log_action(current_user.username, "create_user", f"new_username: {reg_username}, is_admin: {reg_is_admin}")
                msg = 'New user created.'
                users = User.query.filter(User.username != 'admin').order_by(User.username.asc()).all()
        elif 'delete_user' in request.form:
            del_username = request.form.get('username')
            if del_username:
                user = User.query.filter_by(username=del_username).first()
                if user:
                    db.session.delete(user)
                    db.session.commit()
                    log_action(current_user.username, "delete_user", f"deleted user {del_username}")
                    user_folder = os.path.join(db_folder, 'users', del_username)
                    if os.path.exists(user_folder):
                        shutil.rmtree(user_folder)
                    msg = f'User {del_username} deleted.'
                    users = User.query.filter(User.username != 'admin').order_by(User.username.asc()).all()
                else:
                    msg = 'User not found.'
            else:
                msg = 'No user selected for deletion.'

        # Refresh activity logs after action
        if os.path.exists(master_log_file):
            with open(master_log_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                activity_logs = [line.strip() for line in lines[-100:]]
                activity_logs.reverse()

    return render_template('admin/dashboard_admin.html', users=users, msg=msg, activity_logs=activity_logs)

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
            flash('No file part')
            return redirect(request.url)
        file = request.files['photo']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = f"{current_user.username}_{uuid.uuid4().hex}_{secure_filename(file.filename)}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            photo = Photo(filename=filename, uploader_id=current_user.id)
            db.session.add(photo)
            db.session.commit()
            log_action(current_user.username, "upload_photo", f"filename: {filename}")
            flash('Photo uploaded successfully')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid file type')
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
 