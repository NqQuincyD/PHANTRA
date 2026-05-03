from flask import request
from models import db, AuthLog
from utils.firebase_db import FirebaseDB

def log_auth_event(action, user=None, email=None, details=None):
    """
    Logs a user login/registration event to both SQL and Firebase.
    """
    log_data = {
        'user_id': user.id if user else None,
        'email': email if email else (user.email if user else None),
        'action': action,
        'ip_address': request.remote_addr,
        'user_agent': request.user_agent.string,
        'details': details 
    }
    
    log = AuthLog(**log_data)
    db.session.add(log)
    db.session.commit()

    # Sync to Firebase in a background thread to prevent blocking the UI
    import threading
    def sync_to_cloud(log_data, user_obj):
        try:
            # Sync Auth Log
            FirebaseDB.save_auth_log(log_data)

            # Sync User Profile if present
            if user_obj:
                user_metadata = {
                    'username': user_obj.username,
                    'email': user_obj.email,
                    'role': user_obj.role,
                    'last_active': firestore.SERVER_TIMESTAMP
                }
                FirebaseDB.save_user(user_obj.id, user_metadata)
        except Exception as e:
            print(f"Background Firebase Sync Error: {e}")

    threading.Thread(target=sync_to_cloud, args=(log_data, user), daemon=True).start()

from firebase_admin import firestore
