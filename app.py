from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from time import sleep


app = Flask(__name__)
app.secret_key = 'your_secret_key'

def init_db():
    with sqlite3.connect('database.db') as conn:
        cursor = conn.cursor()
        
        # Create users table
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            name TEXT,
                            email TEXT UNIQUE,
                            password TEXT)''')

        # Create passwords table
        cursor.execute('''CREATE TABLE IF NOT EXISTS passwords (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            user_id INTEGER,
                            service TEXT,
                            username TEXT,
                            password TEXT,
                            strength TEXT,
                            FOREIGN KEY(user_id) REFERENCES users(id))''')
        
        # Create bankcards table
        cursor.execute('''CREATE TABLE IF NOT EXISTS bankcards(
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            user_id INTEGER,
                            card_number TEXT,
                            cardholder_name TEXT,
                            expiration_date TEXT,
                            cvv TEXT,
                            FOREIGN KEY(user_id) REFERENCES users(id))''')
        
        #create notes table
        cursor.execute('''CREATE TABLE IF NOT EXISTS notes(
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            user_id INTEGER,
                            notes TEXT,
                            FOREIGN KEY(user_id) REFERENCES users(id))''')
        conn.commit()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('username')
        password = request.form.get('password')

        with sqlite3.connect('database.db') as conn:
            cursor = conn.cursor()

            # Print all users to see what's stored
            cursor.execute("SELECT email FROM users")
            all_users = cursor.fetchall()
            print(f"\nDEBUG: All stored emails in DB: {all_users}")

            cursor.execute('SELECT id, name, email, password FROM users WHERE email = ?', (email,))
            user = cursor.fetchone()

            if user:
                stored_hashed_password = user[3]
                print(f"DEBUG: Found user with email {email}")
                if check_password_hash(stored_hashed_password, password):
                    session['user'] = {'id': user[0], 'name': user[1], 'email': user[2]}
                    print("✅ Password matches! Logging in...")
                    return redirect(url_for('dashboard'))
                else:
                    print("❌ Password does not match!")

            else:
                print(f"❌ No user found with email: {email}")

        return "Invalid email or password", 401

    return render_template('login.html')



@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])  # Hash the password

        with sqlite3.connect('database.db') as conn:
            cursor = conn.cursor()
            try:
                cursor.execute('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', (name, email, password))
                conn.commit()
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                return 'User already exists'
    return render_template('registration.html')



@app.route('/add_password', methods=['POST'])

def add_password():

    # Get form data

    url = request.form['url']
    username = request.form['username']
    password = request.form['password']
    strength = password_strength(password)
    # Save data to the SQLite database

    with sqlite3.connect('database.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO passwords (user_id, service, username, password, strength)
            VALUES (?, ?, ?, ?, ?)
        ''', (1, url, username, password, strength))  # Replace `1` with the actual user ID
        conn.commit()
    
    # Provide feedback to the user
    flash('Password added successfully!', 'success')
    sleep(1.3)
    return redirect(url_for('passwords'))

@app.route('/delete_password/<int:id>', methods=['POST'])
def delete_password(id):
    if 'user' not in session:
        return redirect(url_for('login'))

    user_id = session['user']['id']
    with sqlite3.connect('database.db') as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM passwords WHERE id = ? AND user_id = ?', (id, user_id))
        conn.commit()

    return jsonify({"message": "Password deleted successfully"}), 200

@app.route('/reset_password')
def reset_password():
    return render_template('reset_password.html')

######Dashboard Functions 

@app.route('/dashboard')
def dashboard():

    if 'user' not in session:

        print("User not found!!")
        return redirect(url_for('login'))
    
    user_id = session['user']['id']
    print(f"\nDEBUG: Logged-in user ID -> {user_id}")  # Debugging
    
    with sqlite3.connect('database.db') as conn:

        cursor = conn.cursor()

        cursor.execute('SELECT service, username, password FROM passwords WHERE user_id = ?', (user_id,))
        rows = cursor.fetchall()

        cursor.execute('SELECT COUNT(*) FROM passwords WHERE user_id = ?', (user_id,))
        total_passwords = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM passwords WHERE user_id = ? AND strength = 'Strong'", (user_id,))
        strong_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM passwords WHERE user_id = ? AND strength = 'weak'", (user_id,))
        weak_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM bankcards WHERE user_id = ?", (user_id,))
        total_cards = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM notes WHERE user_id = ?", (user_id,))
        total_notes = cursor.fetchone()[0]

        print("\nDEBUG: Retrieved passwords ->", rows)  #  Debugging

    # Convert tuples into dictionaries for better template handling
    passwords = [{'service': row[0], 'username': row[1], 'password': row[2]} for row in rows] 
    
    name = get_name(user_id)
    # Check if passwords are passed to the template
    response = render_template('dashboard.html', 
                            user=session['user'], 
                            passwords=passwords,
                            total_passwords=total_passwords, 
                            strong_count=strong_count, 
                            weak_count=weak_count,
                            total_cards=total_cards,
                            total_notes=total_notes,
                            name=name)
    print("\nDEBUG: Rendering dashboard with passwords ->", passwords) # Debugging
    
    return response
    
def get_name(user_id):

    
    conn = sqlite3.connect("database.db")  # Connect to the database
    cursor = conn.cursor()

    cursor.execute("SELECT name FROM users WHERE id = ?", (user_id,))  # Use user_id from session
    result = cursor.fetchone()  # Fetch one result
    
    conn.close()
    
    return result[0] if result else "Guest"  # Return name or default to "Guest"



@app.route('/passwords')
def passwords():
    return render_template('passwords.html')

@app.route('/cards')
def cards(): 
    return render_template('cards.html')

@app.route('/notes')
def notes(): 
    return render_template('notes.html')

@app.route('/settings')
def settings(): 
    return render_template('settings.html')

@app.route('/help')
def help(): 
    return render_template('help.html')

@app.route('/terms')
def terms(): 
    return render_template('terms.html')

######Dashboard Functions

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))


import string

def password_strength(password):
    
    #established test criteria
    length = len(password) >= 12
    lowercase = any(c.islower() for c in password)
    uppercase = any(c.isupper() for c in password)
    number = any(c.isdigit() for c in password)
    special = any(c in string.punctuation for c in password)
    common_passwords = {
    "password", "123456", "123456789", "12345678", "12345", "1234567", "qwerty", 
    "abc123", "letmein", "monkey", "iloveyou", "trustno1", "dragon", "baseball", 
    "football", "starwars", "123123", "welcome", "admin", "password1", 
    "qwertyuiop", "123321", "superman", "1q2w3e4r", "sunshine", "ashley", 
    "bailey", "passw0rd", "shadow", "master"
    }
    
     # Check for common passwords
    if password in common_passwords:
        return "Very Weak" 

    if length and (lowercase or uppercase or number or special):
        if length >= 12 and lowercase and uppercase and number and special:
            return "Very Strong"
        else:
            return "Strong"

    return "Weak"

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
