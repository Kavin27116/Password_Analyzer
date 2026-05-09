import re
import secrets
import string
import sqlite3
import hashlib

# --- DATABASE SETUP ---
def setup_db():
    conn = sqlite3.connect('password_history.db')
    cursor = conn.cursor()
    # Store hashed passwords (never store plain text!)
    cursor.execute('''CREATE TABLE IF NOT EXISTS history 
                      (pwd_hash TEXT PRIMARY KEY)''')
    conn.commit()
    return conn

def is_password_reused(password, conn):
    # Hash the input to compare it with stored hashes
    pwd_hash = hashlib.sha256(password.encode()).hexdigest()
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM history WHERE pwd_hash = ?", (pwd_hash,))
    return cursor.fetchone() is not None

def save_password(password, conn):
    pwd_hash = hashlib.sha256(password.encode()).hexdigest()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO history (pwd_hash) VALUES (?)", (pwd_hash,))
        conn.commit()
    except sqlite3.IntegrityError:
        pass # Already exists

# --- ANALYZER LOGIC ---
def analyze_password(password):
    score = 0
    feedback = []
    if len(password) >= 12: score += 2
    elif len(password) >= 8: score += 1
    else: feedback.append("- Password is too short.")
    
    if re.search(r"[A-Z]", password): score += 1
    else: feedback.append("- Add uppercase letters.")
    
    if re.search(r"\d", password): score += 1
    else: feedback.append("- Add numbers.")
    
    if re.search(r"[!@#$%^&*]", password): score += 1
    else: feedback.append("- Add special characters.")
    
    return score, feedback

def suggest_strong_password():
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(chars) for _ in range(16))

# --- MAIN EXECUTION ---
if __name__ == "__main__":
    db_conn = setup_db()
    print("--- Secure Password Analyzer v2.0 ---")
    
    user_pwd = input("Enter password to test: ")
    
    # 1. Check for Reuse first
    if is_password_reused(user_pwd, db_conn):
        print("\n❌ REJECTED: You have used this password before. Please pick a new one.")
    else:
        # 2. Analyze Strength
        s, notes = analyze_password(user_pwd)
        print(f"\nScore: {s}/5")
        
        if s >= 4:
            print("Result: VERY STRONG ✅")
            save_password(user_pwd, db_conn) # Save only if it's good
            print("Password saved to history.")
        else:
            print("Result: WEAK ❌")
            for n in notes: print(n)
            print(f"\nTry this: {suggest_strong_password()}")

    db_conn.close()