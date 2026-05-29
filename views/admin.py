from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from sqlalchemy import func
from forms import AdminUserForm, AddUserForm
from werkzeug.security import generate_password_hash
from datetime import datetime
import pandas as pd
from utils.firebase_db import FirebaseDB
from firebase_admin import firestore

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
            # Under purely cloud architecture, we fetch read activities from Firestore
            from firebase_config import db_firestore
            docs = db_firestore.collection('activities') \
                .where('user_id', '==', str(current_user.id)) \
                .where('activity_type', '==', 'Admin Alert Read') \
                .stream()
            read_history_ids = {doc.to_dict().get('details') for doc in docs}
            
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

    # Get global users from Firebase
    global_users = FirebaseDB.get_global_users()
    total_users = len(global_users)

    # Users by role
    roles_counts = {}
    for u in global_users:
        r = u.get('role') or 'User'
        roles_counts[r] = roles_counts.get(r, 0) + 1

    roles_labels = list(roles_counts.keys())
    roles_counts_list = list(roles_counts.values())

    # Authentication events analysis
    auth_logs = FirebaseDB.get_all_auth_logs(limit=500)
    total_auth_events = len(auth_logs)
    success_events = len([log for log in auth_logs if 'success' in log.get('action', '')])
    failed_events = len([log for log in auth_logs if 'failed' in log.get('action', '')])

    auth_labels = ['Successful', 'Possible Intrusion']
    auth_counts = [success_events, failed_events]

    return render_template(
        'admin/home.html',
        total_users=total_users,
        roles_labels=roles_labels,
        roles_counts=roles_counts_list,
        auth_labels=auth_labels,
        auth_counts=auth_counts,
        total_auth_events=total_auth_events
    )


@adm_bp.route('/security-console', methods=['GET', 'POST'])
@login_required
def security_console():
    if current_user.role != 'Admin':
        flash('Access denied', 'danger')
        return redirect(url_for('auth.login'))

    auth_logs = FirebaseDB.get_all_auth_logs(limit=300)

    # Convert timestamp to standard formats if necessary for rendering
    # Jinja2 handles dot notation of dicts seamlessly
    return render_template(
        'admin/security.html',
        auth_logs=auth_logs
    )


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


@adm_bp.route('/model-evaluation')
@login_required
def model_evaluation():
    if current_user.role != 'Admin':
        flash('Access denied', 'danger')
        return redirect(url_for('auth.login'))

    from views.user import get_ml_df
    
    try:
        df = get_ml_df()
        total_records = len(df)
        total_anomalies = int(df['is_anomaly'].sum()) if 'is_anomaly' in df.columns else 0
        anomaly_rate = round((total_anomalies / total_records) * 100, 2) if total_records > 0 else 0.0
        high_critical_count = int(df[df['risk_level'].isin(['High', 'Critical'])].shape[0]) if 'risk_level' in df.columns else 0
        avg_anomaly_score = round(df['anomaly_score'].mean(), 4) if 'anomaly_score' in df.columns and total_records > 0 else 0.0
        
        # Calculate categories counts
        target_categories = ['anonymous', 'betting', 'hacking', 'money', 'trading', 'porn', 'social', 'video', 'shopping', 'job', 'forum', 'cloud']
        category_counts = {}
        for cat in target_categories:
            col = f'is_{cat}'
            if col in df.columns:
                category_counts[cat] = int(df[col].sum())
            else:
                category_counts[cat] = 0
                
        # Risk levels distribution
        risk_dist = {}
        if 'risk_level' in df.columns:
            for rl, count in df['risk_level'].value_counts().items():
                risk_dist[str(rl)] = int(count)
                
        # Browser breakdown
        browser_dist = {}
        if 'Browser' in df.columns:
            for br, count in df['Browser'].value_counts().items():
                browser_dist[str(br)] = int(count)
    except Exception as e:
        print(f"Error compiling live metrics: {e}")
        total_records = 0
        total_anomalies = 0
        anomaly_rate = 0.0
        high_critical_count = 0
        avg_anomaly_score = 0.0
        category_counts = {}
        risk_dist = {}
        browser_dist = {}

    return render_template(
        'admin/model_evaluation.html',
        total_records=total_records,
        total_anomalies=total_anomalies,
        anomaly_rate=anomaly_rate,
        high_critical_count=high_critical_count,
        avg_anomaly_score=avg_anomaly_score,
        category_counts=category_counts,
        risk_dist=risk_dist,
        browser_dist=browser_dist
    )


@adm_bp.route('/model-evaluation/retrain', methods=['POST'])
@login_required
def retrain_model():
    if current_user.role != 'Admin':
        return jsonify({'status': 'error', 'message': 'Access denied'}), 403
        
    from views.user import update_ml_pipeline
    try:
        update_ml_pipeline()
        flash('ML Anomaly Detection Pipeline successfully updated and retrained on current browser history.', 'success')
        return redirect(url_for('admin.model_evaluation'))
    except Exception as e:
        flash(f'Error updating ML pipeline: {str(e)}', 'danger')
        return redirect(url_for('admin.model_evaluation'))


@adm_bp.route('/monitoring-hub', methods=['GET', 'POST'])
@login_required
def monitoring_hub():
    if current_user.role != 'Admin':
        flash('Access denied', 'danger')
        return redirect(url_for('auth.login'))

    # Fetch users exclusively from Firebase
    users = FirebaseDB.get_global_users()
    return render_template('admin/users.html', users=users)


@adm_bp.route('/update-user/<string:user_id>', methods=['GET', 'POST'])
@login_required
def update_user(user_id):
    if current_user.role != 'Admin':
        flash('Access denied', 'danger')
        return redirect(url_for('auth.login'))

    user = FirebaseDB.get_user_by_id(user_id)
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('admin.monitoring_hub'))

    form = AdminUserForm(obj=user)  

    if form.validate_on_submit():
        user_metadata = {
            'username': form.username.data,
            'email': form.email.data,
            'role': form.role.data,
            'last_updated': firestore.SERVER_TIMESTAMP
        }
        FirebaseDB.save_user(user_id, user_metadata)
        flash('User updated successfully.', 'success')
        return redirect(url_for('admin.monitoring_hub'))

    return render_template('admin/update.html', form=form, user=user)


@adm_bp.route('/view-user/<string:user_id>')
@login_required
def view_user(user_id):
    if current_user.role != 'Admin':
        flash('Access denied', 'danger')
        return redirect(url_for('auth.login'))

    user = FirebaseDB.get_user_by_id(user_id)
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('admin.monitoring_hub'))
    
    # Gather stats
    auth_logs = FirebaseDB.get_all_auth_logs(limit=500)
    user_auth_logs = [log for log in auth_logs if str(log.get('user_id')) == str(user.id)]
    
    total_logins = len([log for log in user_auth_logs if log.get('action') == 'login_success'])
    
    # Get last success login
    success_logins = [log for log in user_auth_logs if log.get('action') == 'login_success']
    last_login = success_logins[0] if success_logins else None
    
    global_history = FirebaseDB.get_browser_history_by_username(user.username)
    total_history = len(global_history)
        
    activities = FirebaseDB.get_all_activities(limit=500)
    user_activities = [act for act in activities if str(act.get('user_id')) == str(user.id)]
    
    return render_template(
        'admin/view_user.html', 
        user=user, 
        total_logins=total_logins, 
        last_login=last_login, 
        total_history=total_history, 
        activities=user_activities[:5], 
        cloud_activities=user_activities[:10]
    )


@adm_bp.route('/toggle-suspend/<string:user_id>', methods=['POST'])
@login_required
def toggle_suspend(user_id):
    if current_user.role != 'Admin':
        return jsonify({'status': 'error', 'message': 'Access denied'}), 403
        
    if current_user.id == user_id:
        return jsonify({'status': 'error', 'message': 'Cannot suspend yourself'}), 400

    user = FirebaseDB.get_user_by_id(user_id)
    if not user:
        return jsonify({'status': 'error', 'message': 'User not found'}), 404

    if user.role == 'Suspended':
        new_role = 'User'
        action = 'activated'
    else:
        new_role = 'Suspended'
        action = 'suspended'
        
    FirebaseDB.save_user(user_id, {
        'role': new_role,
        'last_updated': firestore.SERVER_TIMESTAMP
    })

    return jsonify({'status': 'success', 'message': f'User {user.username} has been {action}.'})


@adm_bp.route('/delete-user/<string:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role != 'Admin':
        return jsonify({'status': 'error', 'message': 'Access denied'}), 403
        
    if current_user.id == user_id:
        return jsonify({'status': 'error', 'message': 'Cannot delete yourself'}), 400

    user = FirebaseDB.get_user_by_id(user_id)
    if not user:
        return jsonify({'status': 'error', 'message': 'User not found'}), 404
        
    success = FirebaseDB.delete_user_data(user.username, user_id)
    if success:
        return jsonify({'status': 'success', 'message': f'User {user.username} deleted permanently.'})
    else:
        return jsonify({'status': 'error', 'message': 'Failed to delete user from Firebase'}), 500


@adm_bp.route('/add-user', methods=['GET', 'POST'])
@login_required
def add_user():
    if current_user.role != 'Admin':
        flash('Access denied', 'danger')
        return redirect(url_for('auth.login'))
    form = AddUserForm()
    if form.validate_on_submit():
        existing_user = FirebaseDB.get_user_by_email(form.email.data)
        if existing_user:
            flash('Email already registered', 'danger')
            return redirect(url_for('admin.add_user'))

        from firebase_config import db_firestore
        user_ref = db_firestore.collection('users').document()
        user_metadata = {
            'username': form.username.data,
            'email': form.email.data,
            'password': generate_password_hash(form.password.data),
            'role': form.role.data,
            'created_at': firestore.SERVER_TIMESTAMP
        }
        user_ref.set(user_metadata)
        
        flash('User added successfully!', 'success')
        return redirect(url_for('admin.monitoring_hub'))

    return render_template('admin/add.html', form=form)


@adm_bp.route('/file-logs', methods=['GET'])
@login_required
def file_logs():
    if current_user.role != 'Admin':
        flash('Access denied', 'danger')
        return redirect(url_for('auth.login'))
        
    # Query file transfers from Firestore
    from firebase_config import db_firestore
    try:
        docs = db_firestore.collection('file_transfers') \
            .order_by('timestamp', direction=firestore.Query.DESCENDING) \
            .limit(100) \
            .stream()
        raw_transfers = []
        for doc in docs:
            raw_transfers.append((doc.to_dict(), doc.id))
    except Exception as e:
        print(f"Error fetching file transfers from Firestore: {e}")
        raw_transfers = []
        
    class FirestoreTransferAdapter:
        def __init__(self, data, doc_id):
            self.id = doc_id
            self.filename = data.get('filename')
            self.file_size = data.get('file_size') or 0
            self.is_threat = data.get('is_threat') or False
            self.threat_details = data.get('threat_details') or 'No threats detected'
            
            ts = data.get('timestamp')
            if isinstance(ts, str):
                try:
                    self.timestamp = datetime.strptime(ts, '%Y-%m-%d %H:%M:%S')
                except ValueError:
                    self.timestamp = datetime.utcnow()
            elif ts:
                self.timestamp = ts
            else:
                self.timestamp = datetime.utcnow()
                
            self.status = data.get('status')
            
            class Entity:
                def __init__(self, username, email):
                    self.username = username
                    self.email = email
                    
            self.sender = Entity(data.get('sender_username') or 'Unknown', data.get('sender_email') or 'Unknown')
            self.receiver = Entity(data.get('receiver_username') or 'Unknown', data.get('receiver_email') or 'Unknown')
            
    transfers = [FirestoreTransferAdapter(t[0], t[1]) for t in raw_transfers]
    
    return render_template('admin/file_logs.html', transfers=transfers)
