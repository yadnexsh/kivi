from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import os

# Set up paths
db_folder = 'database'
os.makedirs(db_folder, exist_ok=True)  # Ensure folder exists

app = Flask(__name__)

# Absolute path option (recommended for Windows testing)
db_path = os.path.abspath(os.path.join(db_folder, 'database.db'))
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class Test(db.Model):
    id = db.Column(db.Integer, primary_key=True)

if __name__ == '__main__':
    print("Database URI:", app.config['SQLALCHEMY_DATABASE_URI'])
    print("Database folder exists?", os.path.exists(db_folder))
    print("Target DB path exists?", os.path.exists(db_path))
    with app.app_context():
        db.create_all()
        print(f"database.db created at: {db_path}")
