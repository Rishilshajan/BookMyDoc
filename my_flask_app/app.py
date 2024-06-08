# app.py
from flask import Flask, render_template, url_for, flash, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
from flask_mail import Mail, Message
from config import Config
from models import db, User
from forms import RegistrationForm, LoginForm
from itsdangerous import TimedSerializer as Serializer  # Corrected import

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def send_verification_email(user):
    token = user.get_reset_token()
    msg = Message('Email Verification',
                  sender='noreply@demo.com',
                  recipients=[user.email])
    msg.body = f'''To verify your email, visit the following link:
{url_for('verify_email', token=token, _external=True)}

If you did not make this request then simply ignore this email and no changes will be made.
'''
    mail.send(msg)

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(email=form.email.data, password=hashed_password, role=form.role.data)
        db.session.add(user)
        db.session.commit()
        send_verification_email(user)
        flash('An email has been sent with instructions to verify your email.', 'info')
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)

@app.route("/verify_email/<token>")
def verify_email(token):
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('register'))
    user.email_verified = True
    db.session.commit()
    flash('Your email has been verified! You can now log in.', 'success')
    return redirect(url_for('login'))

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            if user.email_verified:
                login_user(user, remember=form.remember.data)
                next_page = request.args.get('next')
                if user.role == 'Admin':
                    return redirect(next_page) if next_page else redirect(url_for('index_admin'))
                elif user.role == 'Doctor':
                    return redirect(next_page) if next_page else redirect(url_for('index_doctor'))
                elif user.role == 'Patient':
                    return redirect(next_page) if next_page else redirect(url_for('index_patient'))
            else:
                flash('Please verify your email first!', 'warning')
                return redirect(url_for('login'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', form=form)

@app.route("/index_admin")
@login_required
def index_admin():
    if current_user.role != 'Admin':
        return redirect(url_for('login'))
    return render_template('index_admin.html')

@app.route("/index_doctor")
@login_required
def index_doctor():
    if current_user.role != 'Doctor':
        return redirect(url_for('login'))
    return render_template('index_doctor.html')

@app.route("/index_patient")
@login_required
def index_patient():
    if current_user.role != 'Patient':
        return redirect(url_for('login'))
    return render_template('index_patient.html')

if __name__ == '__main__':
    app.run(debug=True)
