import sqlite3
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from bcrypt import hashpw, gensalt, checkpw
from functools import wraps

app = Flask(__name__, static_folder='C:/Users/Denis/Desktop/tuckdash/static')
app.secret_key = 'very_very_super_secret_key'

# Create the login_required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Function to connect to SQLite
def get_db_connection():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn


# Route for login page (renders the HTML template)
@app.route('/')
def index():
    return render_template('login.html')

# Protected route (kitchen menu)
@app.route('/menu')
@login_required
def menu():
    # Fetch and display the kitchen menu
    conn = get_db_connection()
    dishes = conn.execute('SELECT * FROM dishes').fetchall()
    conn.close()

    return render_template('menu.html', dishes=dishes)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password'].encode('utf-8')

        # Connect to the database
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()

        if user is None:
            flash('Invalid email or password.', 'error')
            return redirect(url_for('login'))

        hashed_password = user['hashed_password'].encode('utf-8')

        # Check if password matches
        if checkpw(password, hashed_password):
            session['user_id'] = user['id']
            session['user_email'] = user['email']
            flash('Login successful!', 'success')

            # Redirect to the menu page after successful login
            return redirect(url_for('menu'))
        else:
            flash('Invalid email or password.', 'error')
            return redirect(url_for('login'))

    # If the user is already logged in, redirect them to the menu page
    if 'user_id' in session:
        return redirect(url_for('menu'))

    return render_template('login.html')

# Logout route
@app.route('/logout')
def logout():
    # Clear the session
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))


# Route for registering users (optional, to manually add users)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password'].encode('utf-8')

        # Automatically set the role to 's' during registration
        role = 's'  # 's' stands for student

        # Hash the password for secure storage
        hashed_password = hashpw(password, gensalt())

        # Insert the new user into the database, along with the default role 's'
        conn = get_db_connection()

        # Check if the email is already registered before trying to insert
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()

        if user:
            flash('Email already registered!', 'error')
            conn.close()
            return redirect(url_for('register'))

        try:
            conn.execute('INSERT INTO users (email, hashed_password, role) VALUES (?, ?, ?)',
                         (email, hashed_password.decode('utf-8'), role))
            conn.commit()
            conn.close()

            # Flash a success message after registration
            flash('Your account has been created! You can now log in.', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            flash('Something went wrong during registration.', 'error')
            conn.close()
            return redirect(url_for('register'))

    # If it's a GET request, render the registration form
    return render_template('register.html')

if __name__ == "__main__":
    app.run(debug=True)