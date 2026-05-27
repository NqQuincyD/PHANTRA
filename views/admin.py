from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from sqlalchemy import func, desc
from forms import AdminUserForm, AddUserForm
from models import db, User, AuthLog
from werkzeug.security import generate_password_hash
from datetime import datetime
import pandas as pd
from utils.firebase_db import FirebaseDB

import os

adm_bp = Blueprint('admin', __name__, url_prefix='/admin')

@adm_bp.context_processor
def inject_notification_count():
    from views.user import get_ml_df
    target_categories = ['anonymous', 'betting', 'hacking', 'money', 'trading', 'porn']
    
    try:
        df = get_ml_df()
        high_risk_df = df[
            (df['risk_level'].isin(['High', 'Critical'])) &
            (df[[f'is_{cat}' for cat in target_categories]].any(axis=1))
        ]
        
        # Filter out read alerts for Admin
        if current_user.is_authenticated:
            from models import UserActivity
            # Admins always use 'Admin Alert Read'
            read_activities = UserActivity.query.filter_by(
                user_id=current_user.id,
                activity_type='Admin Alert Read'
            ).all()
            read_history_ids = {act.details for act in read_activities}
            
            if not high_risk_df.empty:
                high_risk_df = high_risk_df[~high_risk_df['history_id'].astype(str).isin(read_history_ids)]
        
        notification_count = len(high_risk_df)
    except Exception:
        notification_count = 0
        
    return dict(notification_count=notification_count)


@adm_bp.route('/dashboard')
@login_required
def home():
    if current_user.role != 'Admin':
        flash('Access denied', 'danger')
        return redirect(url_for('auth.login'))

    # Total users
    total_users = User.query.count()

    # Users by role
    roles_analysis = db.session.query(
        User.role, func.count(User.id)
    ).group_by(User.role).all()

    roles_labels = [role for role, count in roles_analysis]
    roles_counts = [count for role, count in roles_analysis]

    # Authentication events analysis
    total_auth_events = AuthLog.query.count()
    success_events = AuthLog.query.filter(AuthLog.action.in_(['login_success','register_success'])).count()
    failed_events = AuthLog.query.filter(AuthLog.action.in_(['login_failed','register_failed'])).count()

    auth_labels = ['Successful', 'Possible Intrusion']
    auth_counts = [success_events, failed_events]

    return render_template(
        'admin/home.html',
        total_users=total_users,
        roles_labels=roles_labels,
        roles_counts=roles_counts,
        auth_labels=auth_labels,
        auth_counts=auth_counts,
        total_auth_events=total_auth_events
    )

# @adm_bp.route('/dashboard')
# @login_required
# def home():
#     return render_template('admin/home.html')

@adm_bp.route('/security-console', methods=['GET', 'POST'])
@login_required
def security_console():
   
    if current_user.role != 'Admin':
        flash('Access denied', 'danger')
        return redirect(url_for('auth.login'))

   
    auth_logs = AuthLog.query.order_by(AuthLog.timestamp.desc()).all()

    return render_template(
        'admin/security.html',
        auth_logs=auth_logs
    )

# @adm_bp.route('/security-console', methods=['GET', 'POST'])
# @login_required
# def security_console():
#     return render_template('admin/security.html')


@adm_bp.route('/security-threats')
@login_required
def security_threats():
    if current_user.role != 'Admin':
        flash('Access denied', 'danger')
        return redirect(url_for('auth.login'))
    return render_template('admin/threats.html')


@adm_bp.route('/reports-analytics', methods=['GET', 'POST'])
@login_required
def reports_analytics():
     if current_user.role != 'Admin':
         flash('Access denied', 'danger')
         return redirect(url_for('auth.login'))
     return render_template('admin/reports.html')


# @adm_bp.route('/model-evaluation')
# @login_required
# def model_evaluation():
#     return render_template('admin/model_evaluation.html')

@adm_bp.route('/monitoring-hub', methods=['GET', 'POST'])
@login_required
def monitoring_hub():
    if current_user.role != 'Admin':
        flash('Access denied', 'danger')
        return redirect(url_for('auth.login'))

    # Get local users
    local_users = User.query.order_by(User.id.desc()).all()
    # Get global users from Firebase
    global_users_data = FirebaseDB.get_global_users()
    
    # Create a consolidated list for display
    # We use a dictionary keyed by username to avoid duplicates
    consolidated_users = {u.username: u for u in local_users}
    for gu in global_users_data:
        if gu['username'] not in consolidated_users:
            # Create a mock user object for display if not found locally
            consolidated_users[gu['username']] = gu

    users = consolidated_users.values()
    return render_template('admin/users.html', users=users)

@adm_bp.route('/update-user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def update_user(user_id):
    if current_user.role != 'Admin':
        flash('Access denied', 'danger')
        return redirect(url_for('auth.login'))

    user = User.query.get_or_404(user_id)
    form = AdminUserForm(obj=user)  

    if form.validate_on_submit():
        user.username = form.username.data
        user.email = form.email.data
        user.role = form.role.data
        db.session.commit()
        
        # Sync to Firebase
        try:
            from firebase_admin import firestore
            user_metadata = {
                'username': user.username,
                'email': user.email,
                'role': user.role,
                'last_updated': firestore.SERVER_TIMESTAMP
            }
            FirebaseDB.save_user(user.id, user_metadata)
        except Exception as e:
            print(f"Firebase Sync Error (User update): {e}")

        flash('User updated successfully.', 'success')
        return redirect(url_for('admin.monitoring_hub'))

    return render_template('admin/update.html', form=form, user=user)

@adm_bp.route('/view-user/<int:user_id>')
@login_required
def view_user(user_id):
    if current_user.role != 'Admin':
        flash('Access denied', 'danger')
        return redirect(url_for('auth.login'))

    user = User.query.get_or_404(user_id)
    
    # Gather stats
    from models import AuthLog, UserActivity, Users, BrowserHistory
    total_logins = AuthLog.query.filter_by(user_id=user.id, action='login_success').count()
    last_login = AuthLog.query.filter_by(user_id=user.id, action='login_success').order_by(AuthLog.timestamp.desc()).first()
    
    users_record = Users.query.filter_by(username=user.username).first()
    total_history = 0
    if users_record:
        total_history = BrowserHistory.query.filter_by(user_id=users_record.id).count()
        
    activities = UserActivity.query.filter_by(user_id=user.id).order_by(UserActivity.timestamp.desc()).limit(5).all()
    
    # Fetch from Firebase if available
    cloud_activities = FirebaseDB.get_all_activities(limit=10)
    # Filter cloud activities for this user specifically (if user_id matches)
    # Note: in Firestore we might store user_id as string or int
    cloud_activities = [act for act in cloud_activities if str(act.get('user_id')) == str(user.id)]
    
    return render_template('admin/view_user.html', user=user, total_logins=total_logins, last_login=last_login, total_history=total_history, activities=activities, cloud_activities=cloud_activities)

@adm_bp.route('/toggle-suspend/<int:user_id>', methods=['POST'])
@login_required
def toggle_suspend(user_id):
    if current_user.role != 'Admin':
        return jsonify({'status': 'error', 'message': 'Access denied'}), 403
        
    if current_user.id == user_id:
        return jsonify({'status': 'error', 'message': 'Cannot suspend yourself'}), 400

    user = User.query.get_or_404(user_id)
    if user.role == 'Suspended':
        user.role = 'User'
        action = 'activated'
    else:
        user.role = 'Suspended'
        action = 'suspended'
        
    db.session.commit()
    
    # Sync to Firebase
    try:
        from firebase_admin import firestore
        user_metadata = {
            'username': user.username,
            'role': user.role,
            'last_updated': firestore.SERVER_TIMESTAMP
        }
        FirebaseDB.save_user(user.id, user_metadata)
    except Exception as e:
        print(f"Firebase Sync Error (User suspend): {e}")

    return jsonify({'status': 'success', 'message': f'User {user.username} has been {action}.'})

@adm_bp.route('/delete-user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role != 'Admin':
        return jsonify({'status': 'error', 'message': 'Access denied'}), 403
        
    if current_user.id == user_id:
        return jsonify({'status': 'error', 'message': 'Cannot delete yourself'}), 400

    user = User.query.get_or_404(user_id)
    username = user.username
    
    from models import AuthLog, UserActivity, Anomaly, Users, BrowserHistory
    
    try:
        # 1. Delete AuthLogs
        AuthLog.query.filter_by(user_id=user.id).delete()
        # 2. Delete UserActivities
        UserActivity.query.filter_by(user_id=user.id).delete()
        # 3. Delete Anomalies
        Anomaly.query.filter_by(user_id=user.id).delete()
        
        # 4. Delete BrowserHistory and Users record
        users_record = Users.query.filter_by(username=user.username).first()
        if users_record:
            BrowserHistory.query.filter_by(user_id=users_record.id).delete()
            db.session.delete(users_record)
            
        # 5. Delete User
        db.session.delete(user)
        db.session.commit()
        
        return jsonify({'status': 'success', 'message': f'User {username} deleted permanently.'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500
    if current_user.role != 'Admin':
        flash('Access denied', 'danger')
        return redirect(url_for('auth.login'))

    user = User.query.get_or_404(user_id)
    form = AdminUserForm(obj=user)  

    if form.validate_on_submit():
        user.username = form.username.data
        user.email = form.email.data
        user.role = form.role.data
        db.session.commit()
        flash('User updated successfully.', 'success')
        return redirect(url_for('admin.monitoring_hub'))

    return render_template('admin/update.html', form=form, user=user)

@adm_bp.route('/add-user', methods=['GET', 'POST'])
@login_required
def add_user():
    if current_user.role != 'Admin':
        flash('Access denied', 'danger')
        return redirect(url_for('auth.login'))
    form = AddUserForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('Email already registered', 'danger')
            return redirect(url_for('admin.add_user'))

        user = User(
            username=form.username.data,
            email=form.email.data,
            password=generate_password_hash(form.password.data),
            role=form.role.data
        )
        db.session.add(user)
        db.session.commit()
        flash('User added successfully!', 'success')
        return redirect(url_for('admin.monitoring_hub'))

    return render_template('admin/add.html', form=form)


# @adm_bp.route('/monitoring-hub', methods=['GET', 'POST'])
# @login_required
# def monitoring_hub():
#     return render_template('admin/users.html')

@adm_bp.route('/file-logs', methods=['GET'])
@login_required
def file_logs():
    if current_user.role != 'Admin':
        flash('Access denied', 'danger')
        return redirect(url_for('auth.login'))
        
    from models import FileTransfer
    
    transfers = FileTransfer.query.order_by(FileTransfer.timestamp.desc()).all()
    
    return render_template('admin/file_logs.html', transfers=transfers)
