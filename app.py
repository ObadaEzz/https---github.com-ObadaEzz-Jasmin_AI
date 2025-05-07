from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key_here'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['UPLOAD_FOLDER'] = 'static/uploads'

db = SQLAlchemy(app)
jwt = JWTManager(app)

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    profile_image = db.Column(db.String(200), nullable=True)

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        file = request.files.get('profile_image')

        if User.query.filter_by(email=email).first():
            return jsonify({'message': 'Email already exists'}), 409

        filename = None
        if file:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        hashed_pw = generate_password_hash(password)
        new_user = User(name=name, email=email, password=hashed_pw, profile_image=filename)
        db.session.add(new_user)
        db.session.commit()

        print(f"Welcome {name}! Email sent to {email}")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password, password):
            flash('Invalid credentials', 'danger')
            return redirect(url_for('login'))

        token = create_access_token(identity=user.id)
        session['token'] = token
        session['name'] = user.name
        session['email'] = user.email
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/dashboard')
@jwt_required()
def dashboard():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    return render_template('profile.html', name=user.name, token=session.get('token'), profile=user.profile_image)

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'info')
    return redirect(url_for('login'))

@app.route('/admin/users')
@jwt_required()
def list_users():
    users = User.query.all()
    return render_template('users.html', users=users)

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form['email']
        print(f"Reset link sent to {email}")  # Simulated email
        flash('Password reset link sent (check console).', 'info')
        return redirect(url_for('login'))
    return render_template('reset_password.html')

if __name__ == '__main__':
    if not os.path.exists('users.db'):
        with app.app_context():
            db.create_all()
    app.run(debug=True)
