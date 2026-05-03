import firebase_admin
from firebase_admin import credentials, firestore
import os

def initialize_firebase():
    """Initializes the Firebase Admin SDK."""
    # Path to the service account key file
    cred_path = os.path.join(os.path.dirname(__file__), 'serviceAccountKey.json')
    
    if not os.path.exists(cred_path):
        print(f"Error: {cred_path} not found. Please place your service account key file in the root directory.")
        return None

    try:
        # Check if already initialized to avoid ValueError
        if not firebase_admin._apps:
            cred = credentials.Certificate(cred_path)
            firebase_admin.initialize_app(cred)
        
        return firestore.client()
    except Exception as e:
        print(f"Failed to initialize Firebase: {e}")
        return None

# Create a global firestore client instance
db_firestore = initialize_firebase()
