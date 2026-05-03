from utils.firebase_db import FirebaseDB
import time

def test_sync():
    print("--- Starting Firebase Integration Test ---")
    
    # 1. Test Activity Save
    print("Testing activity save...")
    success = FirebaseDB.save_activity(
        user_id=999, 
        activity_type="SYSTEM_TEST", 
        details="Automatic verification of cloud synchronization."
    )
    if success:
        print("[OK] Activity saved successfully.")
    else:
        print("[ERROR] Failed to save activity.")

    # 2. Test History Save
    print("\nTesting history batch save...")
    history_sample = [
        {'browser': 'Chrome', 'url': 'https://google.com', 'title': 'Google Search', 'visit_count': 10, 'last_visit_time': '2026-05-03 10:00:00'},
        {'browser': 'Firefox', 'url': 'https://firebase.google.com', 'title': 'Firebase Console', 'visit_count': 5, 'last_visit_time': '2026-05-03 11:00:00'}
    ]
    success = FirebaseDB.save_browser_history(user_id=999, history_list=history_sample)
    if success:
        print("[OK] Browser history saved successfully.")
    else:
        print("[ERROR] Failed to save history.")

    # 3. Test Retrieval
    print("\nTesting data retrieval...")
    activities = FirebaseDB.get_all_activities(limit=5)
    if activities:
        print(f"[OK] Successfully retrieved {len(activities)} activities from Firestore.")
        for act in activities:
            print(f" - [{act.get('activity_type')}] {act.get('details')}")
    else:
        print("[ERROR] No activities found in cloud.")

    print("\n--- Test Complete ---")

if __name__ == "__main__":
    test_sync()
