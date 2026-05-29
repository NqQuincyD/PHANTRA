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
        """Retrieves browser history from Firestore for a specific username directly."""
        if db_firestore is None:
            return []
        try:
            # 1. Resolve username to user_id via 'users' collection lookup
            user_docs = db_firestore.collection('users') \
                .where('username', '==', username) \
                .limit(1) \
                .stream()
                
            user_id = None
            for doc in user_docs:
                # Firestore doc.id is the user ID string
                user_id = doc.id
                break
                
            if not user_id:
                return []
                
            # Convert to integer for numeric ID lookup
            try:
                user_id_int = int(user_id)
            except (ValueError, TypeError):
                user_id_int = None
                
            results = []
            # 2. To get the most recent uploads first without requiring a composite index:
            # We query the 3,000 most recently uploaded documents overall, then filter in Python.
            try:
                recent_docs = db_firestore.collection('browser_history') \
                    .order_by('uploaded_at', direction=firestore.Query.DESCENDING) \
                    .limit(3000) \
                    .stream()
                    
                for doc in recent_docs:
                    data = doc.to_dict()
                    uid = data.get('user_id')
                    uname = data.get('username')
                    
                    # Match by integer user_id, string user_id, or username
                    if (user_id_int is not None and uid == user_id_int) or \
                       (uid == user_id) or \
                       (uname == username):
                        results.append(data)
                        if len(results) >= limit:
                            break
            except Exception as e:
                print(f"Fallback/Warning: Unfiltered ordered query failed: {e}")
                
            # 3. Fallback: If no recent records found (or query failed/quota limit hit), query by user_id directly
            # (Note: this query doesn't sort by time but works without composite index)
            if not results:
                history_docs_query = db_firestore.collection('browser_history')
                
                if user_id_int is not None:
                    docs = history_docs_query.where('user_id', '==', user_id_int).limit(limit).stream()
                    results = [doc.to_dict() for doc in docs]
                    
                if not results:
                    docs = history_docs_query.where('user_id', '==', user_id).limit(limit).stream()
                    results = [doc.to_dict() for doc in docs]
                    
                if not results:
                    docs = history_docs_query.where('username', '==', username).limit(limit).stream()
                    results = [doc.to_dict() for doc in docs]
                    
            # 4. Sort the final results by 'Last Visit' time to show the latest visits first
            def get_sort_key(x):
                t = x.get('Last Visit') or x.get('last_visit') or x.get('last_visit_time')
                if isinstance(t, str):
                    return t
                return ""
                
            results.sort(key=get_sort_key, reverse=True)
            return results
        except Exception as e:
            print(f"Firestore error (get_browser_history_by_username): {e}")
            return []

    @staticmethod
    def get_user_by_id(user_id):
        """Retrieves a user from Firestore by their string or integer ID."""
        if db_firestore is None:
            return None
        try:
            doc = db_firestore.collection('users').document(str(user_id)).get()
            if doc.exists:
                data = doc.to_dict()
                from models import FirebaseUser
                return FirebaseUser(
                    user_id=doc.id,
                    username=data.get('username'),
                    email=data.get('email'),
                    role=data.get('role'),
                    password_hash=data.get('password')
                )
            return None
        except Exception as e:
            print(f"Firestore error (get_user_by_id): {e}")
            return None

    @staticmethod
    def get_user_by_email(email):
        """Retrieves a user from Firestore by their email address."""
        if db_firestore is None:
            return None
        try:
            docs = db_firestore.collection('users').where('email', '==', email).limit(1).stream()
            for doc in docs:
                data = doc.to_dict()
                from models import FirebaseUser
                return FirebaseUser(
                    user_id=doc.id,
                    username=data.get('username'),
                    email=data.get('email'),
                    role=data.get('role'),
                    password_hash=data.get('password')
                )
            return None
        except Exception as e:
            print(f"Firestore error (get_user_by_email): {e}")
            return None

    @staticmethod
    def get_all_auth_logs(limit=100):
        """Retrieves all authentication logs from Firestore."""
        if db_firestore is None:
            return []
        try:
            docs = db_firestore.collection('auth_logs') \
                .order_by('timestamp', direction=firestore.Query.DESCENDING) \
                .limit(limit) \
                .stream()
            return [doc.to_dict() for doc in docs]
        except Exception as e:
            print(f"Firestore error (get_all_auth_logs): {e}")
            return []

    @staticmethod
    def get_all_browser_history(limit=5000):
        """Retrieves all browser history documents from Firestore."""
        if db_firestore is None:
            return []
        try:
            docs = db_firestore.collection('browser_history').limit(limit).stream()
            return [doc.to_dict() for doc in docs]
        except Exception as e:
            print(f"Firestore error (get_all_browser_history): {e}")
            return []

    @staticmethod
    def delete_user_data(username, user_id):
        """Deletes a user and all their telemetry, activity, and auth logs from Firestore."""
        if db_firestore is None:
            return False
        try:
            batch = db_firestore.collection('users').document(str(user_id)).delete()
            
            # Use batch for atomic deletions
            del_batch = db_firestore.batch()
            
            # Auth logs
            auth_docs = db_firestore.collection('auth_logs').where('user_id', '==', user_id).stream()
            for doc in auth_docs:
                del_batch.delete(doc.reference)
                
            # Activities
            act_docs = db_firestore.collection('activities').where('user_id', '==', user_id).stream()
            for doc in act_docs:
                del_batch.delete(doc.reference)
                
            # Telemetry History (int and str user_id fallback)
            try:
                user_id_int = int(user_id)
            except (ValueError, TypeError):
                user_id_int = None
                
            if user_id_int is not None:
                hist_docs = db_firestore.collection('browser_history').where('user_id', '==', user_id_int).stream()
                for doc in hist_docs:
                    del_batch.delete(doc.reference)
                    
            hist_docs_str = db_firestore.collection('browser_history').where('user_id', '==', str(user_id)).stream()
            for doc in hist_docs_str:
                del_batch.delete(doc.reference)
                
            del_batch.commit()
            return True
        except Exception as e:
            print(f"Firestore error (delete_user_data): {e}")
            return False


# Import firestore here to use constants like SERVER_TIMESTAMP
from firebase_admin import firestore
