from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, current_user
from werkzeug.security import generate_password_hash
from datetime import datetime

from forms import RegistrationForm, LoginForm
from models import db, User, AuthLog
from utils.logger import log_auth_event
from utils.firebase_db import FirebaseDB


auth_bp = Blueprint('auth', __name__)



@auth_bp.route('/')
def index():
    return render_template('index.html')


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.role == 'User':
            return redirect(url_for('user.home'))
        elif current_user.role == 'Admin':
            return redirect(url_for('user.home'))

    form = LoginForm()

    if request.method == 'POST':
        # Form validation errors
        if not form.validate():
            errors = '; '.join([f"{field}: {', '.join(errs)}" for field, errs in form.errors.items()])
            log_auth_event('login_failed', email=form.email.data, details=f'Form validation errors: {errors}')
            flash('Invalid form input. Please check your entries.', 'danger')
            return render_template('auth/login.html', form=form)

        # Check if email exists
        user = User.query.filter_by(email=form.email.data).first()
        if not user:
            log_auth_event('login_failed', email=form.email.data, details='Email not registered')
            flash('Email not registered', 'danger')
            return render_template('auth/login.html', form=form)

        # Check password
        if not user.check_password(form.password.data):
            log_auth_event('login_failed', email=form.email.data, details='Incorrect password')
            flash('Invalid username or password', 'danger')
            return render_template('auth/login.html', form=form)

        # Check if user is suspended
        if user.role == 'Suspended':
            log_auth_event('login_failed', email=form.email.data, details='Account suspended')
            flash('Your account has been suspended. Please contact the administrator.', 'danger')
            return render_template('auth/login.html', form=form)

        # Successful login
        login_user(user)
        log_auth_event('login_success', user=user)
        
        # Sync user to Firebase on login
        FirebaseDB.save_user(user.id, {
            'username': user.username,
            'email': user.email,
            'role': user.role,
            'last_login': datetime.utcnow()
        })
        if user.role == 'User':
            return redirect(url_for('user.home'))
        elif user.role == 'Admin':
            return redirect(url_for('user.home'))

    return render_template('auth/login.html', form=form)


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('user.home'))

    form = RegistrationForm()

    if request.method == 'POST':
        # Capture form validation errors
        if not form.validate():
            errors = '; '.join([f"{field}: {', '.join(errs)}" for field, errs in form.errors.items()])
            log_auth_event('register_failed', email=form.email.data, details=f'Validation errors: {errors}')
            flash('Registration form has errors. Please check and try again.', 'danger')
            return render_template('auth/register.html', form=form)

        # Check if email already exists
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            log_auth_event('register_failed', email=form.email.data, details='Email already registered')
            flash('Email already registered', 'danger')
            return redirect(url_for('auth.register'))

        # Attempt to create new user
        try:
            user = User(
                username=form.username.data,
                email=form.email.data,
                password=generate_password_hash(form.password.data),
                role=form.role.data
            )
            db.session.add(user)
            db.session.commit()
            log_auth_event('register_success', user=user)  # Log successful registration

            # Sync new user to Firebase
            FirebaseDB.save_user(user.id, {
                'username': user.username,
                'email': user.email,
                'role': user.role,
                'created_at': datetime.utcnow()
            })

            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('auth.login'))
        except Exception as e:
            db.session.rollback()
            log_auth_event('register_failed', email=form.email.data, details=f'DB error: {str(e)}')
            flash('Registration failed. Please try again.', 'danger')

    return render_template('auth/register.html', form=form)


@auth_bp.route('/logout')
def logout():
    if current_user.is_authenticated:
        log_auth_event('logout', user=current_user)
    logout_user()
    return redirect(url_for('auth.login'))
