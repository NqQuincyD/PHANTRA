import os
import sqlite3
import datetime
import glob
from shutil import copyfile

def get_browser_history_paths():
    """Returns paths to browser history files for different OS"""
    paths = []
    
    # Chrome paths
    chrome_paths = {
        'linux': '~/.config/google-chrome/Default/History',
        'windows': '~/AppData/Local/Google/Chrome/User Data/Default/History',
        'mac': '~/Library/Application Support/Google/Chrome/Default/History'
    }
    
    # Firefox paths
    firefox_paths = {
        'linux': '~/.mozilla/firefox/*.default/places.sqlite',
        'windows': '~/AppData/Roaming/Mozilla/Firefox/Profiles/*.default/places.sqlite',
        'mac': '~/Library/Application Support/Firefox/Profiles/*.default/places.sqlite'
    }
    
    # Edge paths
    edge_paths = {
        'windows': '~/AppData/Local/Microsoft/Edge/User Data/Default/History'
    }
    
    # Determine OS
    if os.name == 'nt':  # Windows
        paths.append(('chrome', os.path.expanduser(chrome_paths['windows'])))
        paths.append(('edge', os.path.expanduser(edge_paths['windows'])))
        firefox_path = glob.glob(os.path.expanduser(firefox_paths['windows']))
        if firefox_path:
            paths.append(('firefox', firefox_path[0]))
    else:  # Linux/Mac
        is_mac = 'darwin' in os.uname().sysname.lower()
        browser_os = 'mac' if is_mac else 'linux'
        paths.append(('chrome', os.path.expanduser(chrome_paths[browser_os])))
        firefox_path = glob.glob(os.path.expanduser(firefox_paths[browser_os]))
        if firefox_path:
            paths.append(('firefox', firefox_path[0]))
    
    return paths

def extract_history_from_browser(browser, path, user_id):
    """Extracts history from a specific browser"""
    if not os.path.exists(path):
        return []
    
    # Create temp copy to avoid locking issues
    temp_db = 'temp_history.db'
    copyfile(path, temp_db)
    
    conn = sqlite3.connect(temp_db)
    cursor = conn.cursor()
    history_items = []
    
    try:
        if browser in ['chrome', 'edge']:
            query = """
            SELECT url, title, visit_count, last_visit_time 
            FROM urls 
            ORDER BY last_visit_time DESC
            """
        elif browser == 'firefox':
            query = """
            SELECT moz_places.url, moz_places.title, moz_places.visit_count, 
                   moz_historyvisits.visit_date/1000000
            FROM moz_places
            JOIN moz_historyvisits ON moz_places.id = moz_historyvisits.place_id
            ORDER BY moz_historyvisits.visit_date DESC
            """
        
        cursor.execute(query)
        
        for url, title, visit_count, timestamp in cursor.fetchall():
            # Convert timestamp to datetime
            if browser in ['chrome', 'edge']:
                epoch_start = datetime.datetime(1601, 1, 1)
                delta = datetime.timedelta(microseconds=timestamp)
                visit_time = epoch_start + delta
            else:  # firefox
                visit_time = datetime.datetime.fromtimestamp(timestamp)
            
            history_items.append({
                'user_id': user_id,
                'browser': browser,
                'url': url,
                'title': title,
                'visit_count': visit_count,
                'last_visit_time': visit_time
            })
            
    except sqlite3.Error as e:
        print(f"Error reading {browser} history: {e}")
    finally:
        conn.close()
        if os.path.exists(temp_db):
            os.remove(temp_db)
    
    return history_items