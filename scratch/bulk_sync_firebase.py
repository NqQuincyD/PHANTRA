import os
import sys

# Add project root to path
sys.path.append(os.getcwd())

from app import app
from models import db, User, AuthLog, UserActivity, Users, BrowserHistory, FileTransfer, Anomaly
from utils.firebase_db import FirebaseDB

def bulk_sync():
    print("Starting Bulk Sync to Firebase Firestore...")
    
    with app.app_context():
        # 1. Sync Users
        print("Syncing Users...")
        users = User.query.all()
        for u in users:
            FirebaseDB.save_user(u.id, {
                'username': u.username,
                'email': u.email,
                'role': u.role
            })
        print(f"Synced {len(users)} users.")

        # 2. Sync Auth Logs
        print("Syncing Auth Logs...")
        logs = AuthLog.query.all()
        for l in logs:
            FirebaseDB.save_auth_log({
                'user_id': l.user_id,
                'action': l.action,
                'timestamp': l.timestamp.isoformat(),
                'details': l.details
            })
        print(f"Synced {len(logs)} auth logs.")

        # 3. Sync User Activities (App Usage)
        print("Syncing User Activities...")
        activities = UserActivity.query.all()
        for a in activities:
            FirebaseDB.save_application_usage(a.user_id, {
                'process_name': a.activity_type,
                'window_title': a.details,
                'timestamp': a.timestamp.isoformat()
            })
        print(f"Synced {len(activities)} activities.")

        # 4. Sync File Transfers
        print("Syncing File Transfers...")
        transfers = FileTransfer.query.all()
        for t in transfers:
            FirebaseDB.save_file_transfer(t.id, {
                'sender_id': t.sender_id,
                'receiver_id': t.receiver_id,
                'filename': t.filename,
                'file_size': t.file_size,
                'status': t.status,
                'is_threat': t.is_threat,
                'threat_details': t.threat_details,
                'timestamp': t.timestamp.isoformat()
            })
        print(f"Synced {len(transfers)} transfers.")

        # 5. Sync Anomalies
        print("Syncing Anomalies...")
        anomalies = Anomaly.query.all()
        for an in anomalies:
            FirebaseDB.save_anomaly(an.user_id, an.anomaly_type, an.severity, an.details)
        print(f"Synced {len(anomalies)} anomalies.")

    print("Bulk Sync Completed Successfully!")

if __name__ == "__main__":
    bulk_sync()
