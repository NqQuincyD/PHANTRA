from flask import request
from utils.firebase_db import FirebaseDB
from firebase_admin import firestore

def log_auth_event(action, user=None, email=None, details=None):
    """
    Logs a user login/registration event exclusively to Firebase.
    """
    log_data = {
        'user_id': user.id if user else None,
        'email': email if email else (user.email if user else None),
        'action': action,
        'ip_address': request.remote_addr,
        'user_agent': request.user_agent.string,
        'details': details 
    }
    
    try:
        # Sync Auth Log to Firebase
        FirebaseDB.save_auth_log(log_data)

        # Sync User Profile last active if present
        if user:
            user_metadata = {
                'username': user.username,
                'email': user.email,
                'role': user.role,
                'last_active': firestore.SERVER_TIMESTAMP
            }
            FirebaseDB.save_user(user.id, user_metadata)
    except Exception as e:
        print(f"Firebase Sync Error: {e}")
