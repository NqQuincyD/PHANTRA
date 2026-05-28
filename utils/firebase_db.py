from firebase_config import db_firestore
from datetime import datetime
import google.cloud.firestore

class FirebaseDB:
    """Helper class to manage Firestore operations for the Digital Footprint Adjudication System."""

    @staticmethod
    def save_activity(user_id, activity_type, details):
        """Saves a user activity log to Firestore."""
        if db_firestore is None:
            return False
        
        try:
            data = {
                'user_id': user_id,
                'activity_type': activity_type,
                'details': details,
                'timestamp': firestore.SERVER_TIMESTAMP
            }
            db_firestore.collection('activities').add(data)
            return True
        except Exception as e:
            print(f"Firestore error (save_activity): {e}")
            return False

    @staticmethod
    def get_all_activities(limit=100):
        """Retrieves all activities from Firestore, ordered by timestamp."""
        if db_firestore is None:
            return []
        
        try:
            docs = db_firestore.collection('activities') \
                .order_by('timestamp', direction=firestore.Query.DESCENDING) \
                .limit(limit) \
                .stream()
            
            return [doc.to_dict() for doc in docs]
        except Exception as e:
            print(f"Firestore error (get_all_activities): {e}")
            return []

    @staticmethod
    def save_browser_history(user_id, history_list):
        """Saves multiple browser history entries to Firestore."""
        if db_firestore is None:
            return False
        
        try:
            batch = db_firestore.batch()
            for entry in history_list:
                doc_ref = db_firestore.collection('browser_history').document()
                entry['user_id'] = user_id
                entry['uploaded_at'] = firestore.SERVER_TIMESTAMP
                batch.set(doc_ref, entry)
            
            batch.commit()
            return True
        except Exception as e:
            print(f"Firestore error (save_browser_history): {e}")
            return False

    @staticmethod
    def save_anomaly(user_id, anomaly_type, severity, details, doc_id=None):
        """Saves an anomaly/threat detection log to Firestore."""
        if db_firestore is None:
            return False
        
        try:
            data = {
                'user_id': user_id,
                'anomaly_type': anomaly_type,
                'severity': severity,
                'details': details,
                'timestamp': firestore.SERVER_TIMESTAMP
            }
            if doc_id:
                db_firestore.collection('anomalies').document(str(doc_id)).set(data)
            else:
                db_firestore.collection('anomalies').add(data)
            return True
        except Exception as e:
            print(f"Firestore error (save_anomaly): {e}")
            return False

    @staticmethod
    def save_user(user_id, user_data):
        """Saves or updates user metadata in Firestore."""
        if db_firestore is None:
            return False
        try:
            db_firestore.collection('users').document(str(user_id)).set(user_data, merge=True)
            return True
        except Exception as e:
            print(f"Firestore error (save_user): {e}")
            return False

    @staticmethod
    def save_file_transfer(transfer_id, transfer_data):
        """Logs a file transfer event to Firestore."""
        if db_firestore is None:
            return False
        try:
            transfer_data['timestamp'] = firestore.SERVER_TIMESTAMP
            db_firestore.collection('file_transfers').document(str(transfer_id)).set(transfer_data)
            return True
        except Exception as e:
            print(f"Firestore error (save_file_transfer): {e}")
            return False

    @staticmethod
    def save_auth_log(log_data):
        """Logs authentication events (login/logout/register) to Firestore."""
        if db_firestore is None:
            return False
        try:
            log_data['timestamp'] = firestore.SERVER_TIMESTAMP
            db_firestore.collection('auth_logs').add(log_data)
            return True
        except Exception as e:
            print(f"Firestore error (save_auth_log): {e}")
            return False

    @staticmethod
    def save_application_usage(user_id, app_data):
        """Saves application monitoring data to Firestore."""
        if db_firestore is None:
            return False
        try:
            data = {
                'user_id': user_id,
                'apps': app_data,
                'timestamp': firestore.SERVER_TIMESTAMP
            }
            db_firestore.collection('application_usage').add(data)
            return True
        except Exception as e:
            print(f"Firestore error (save_application_usage): {e}")
            return False
    @staticmethod
    def get_global_users():
        """Retrieves the list of all users synchronized to Firebase."""
        if db_firestore is None:
            return []
        try:
            docs = db_firestore.collection('users').stream()
            users_list = []
            for doc in docs:
                u_dict = doc.to_dict()
                try:
                    u_dict['id'] = int(doc.id)
                except (ValueError, TypeError):
                    u_dict['id'] = doc.id
                users_list.append(u_dict)
            return users_list
        except Exception as e:
            print(f"Firestore error (get_global_users): {e}")
            return []

    @staticmethod
    def get_browser_history_by_username(username, limit=300):
        """Retrieves browser history from Firestore by finding the user ID for a username."""
        if db_firestore is None:
            return []
        try:
            # 1. Find user in Firestore by username
            users_docs = db_firestore.collection('users') \
                .where('username', '==', username) \
                .limit(1) \
                .stream()
            
            user_id = None
            for doc in users_docs:
                try:
                    user_id = int(doc.id)
                except (ValueError, TypeError):
                    user_id = doc.id
                break
            
            if user_id is None:
                return []
                
            # 2. Query browser_history by user_id
            history_docs = db_firestore.collection('browser_history') \
                .where('user_id', '==', user_id) \
                .limit(limit) \
                .stream()
                
            return [doc.to_dict() for doc in history_docs]
        except Exception as e:
            print(f"Firestore error (get_browser_history_by_username): {e}")
            return []


# Import firestore here to use constants like SERVER_TIMESTAMP
from firebase_admin import firestore
