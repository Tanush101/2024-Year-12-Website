from flask import Flask, render_template, request, g, session, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os
import re

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Required for session management

# Set up Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = "login"

# Path for storing static images
picFolder = os.path.join('static', 'pics')
app.config['UPLOAD_FOLDER'] = picFolder

DATABASE = 'My_favourite_cars.db'

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    user = query_db('SELECT * FROM User WHERE UserID = ?', [user_id], one=True)
    if user:
        return User(id=user[0], username=user[1])
    return None

# Database connection
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

# Query helper function
def query_db(query, args=(), one=False):
    conn = get_db()
    cur = conn.execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

# Create the User table if it doesn't exist
def create_user_table():
    conn = get_db()
    conn.execute('''CREATE TABLE IF NOT EXISTS User (
        UserID INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    );''')
    conn.commit()

# Insert a new user into the User table with hashed password
def insert_user(username, password):
    conn = get_db()
    hashed_password = generate_password_hash(password)
    try:
        conn.execute('INSERT INTO User (username, password) VALUES (?, ?)', (username, hashed_password))
        conn.commit()
        return None  # Return None for success
    except sqlite3.IntegrityError:
        return "User already exists."

# Validate login
def valid_login(username, password):
    user = query_db('SELECT * FROM User WHERE username = ?', [username], one=True)
    if user and check_password_hash(user[2], password):  # User is stored as (UserID, username, password)
        return user
    return None

# Log in the user
def log_the_user_in(user):
    login_user(user)  # This logs in the user using Flask-Login
    return redirect(url_for('homepage'))

# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

# Home page route
@app.route('/')
def home():
    return render_template('home.html')

# Constants for validation
MIN_USERNAME_LENGTH = 1
MAX_USERNAME_LENGTH = 20
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 100

def is_valid_username(username):
    return (MIN_USERNAME_LENGTH <= len(username) <= MAX_USERNAME_LENGTH) and bool(re.match('^[a-zA-Z0-9]+$', username))

def is_valid_password(password):
    return (MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH) and bool(re.match('^[a-zA-Z0-9@#$%^&+=]+$', password))

# Login page route
@app.route('/login', methods=['POST', 'GET'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not is_valid_username(username):
            error = f"Username must be between {MIN_USERNAME_LENGTH} and {MAX_USERNAME_LENGTH} characters and contain only alphanumeric characters."
        elif not is_valid_password(password):
            error = f"Password must be between {MIN_PASSWORD_LENGTH} and {MAX_PASSWORD_LENGTH} characters and contain only alphanumeric characters or @#$%^&+=."
        else:
            user = valid_login(username, password)
            if user:
                user_obj = User(id=user[0], username=user[1])
                return log_the_user_in(user_obj)
            else:
                error = 'Invalid username/password'
    return render_template('login.html', error=error)

# Register page route
@app.route('/register', methods=['POST', 'GET'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not is_valid_username(username):
            error = f"Username must be between {MIN_USERNAME_LENGTH} and {MAX_USERNAME_LENGTH} characters and contain only alphanumeric characters."
        elif not is_valid_password(password):
            error = f"Password must be between {MIN_PASSWORD_LENGTH} and {MAX_PASSWORD_LENGTH} characters and contain only alphanumeric characters or @#$%^&+=."
        else:
            result = insert_user(username, password)
            if result:
                error = result
            else:
                flash("User registered successfully! Please log in.", "success")
                return redirect(url_for('login'))  # Redirect to login after successful registration
    return render_template('register.html', error=error)

# Protected route for profile page
@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)

# Change username route
@app.route('/change_username', methods=['POST'])
@login_required
def change_username():
    new_username = request.form['new_username']
    
    # Validate the new username
    if not is_valid_username(new_username):
        flash("Username must be between 1 and 20 characters and contain only alphanumeric characters.", "error")
        return redirect(url_for('profile'))
    
    # Update the username in the database
    conn = get_db()
    conn.execute('UPDATE User SET username = ? WHERE UserID = ?', (new_username, current_user.id))
    conn.commit()
    
    flash("Username changed successfully!", "success")
    return redirect(url_for('profile'))

# Change password route
@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    new_password = request.form['new_password']
    
    # Validate the new password
    if not is_valid_password(new_password):
        flash("Password must be between 8 and 100 characters.", "error")
        return redirect(url_for('profile'))

    # Update the password in the database
    hashed_password = generate_password_hash(new_password)
    conn = get_db()
    conn.execute('UPDATE User SET password = ? WHERE UserID = ?', (hashed_password, current_user.id))
    conn.commit()
    
    flash("Password changed successfully!", "success")
    return redirect(url_for('profile'))

# Delete account route
@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    user_id = current_user.id
    delete_user(user_id)  # Call the function to delete the user
    logout_user()  # Log the user out after deletion
    flash("Your account has been deleted.", "success")
    return redirect(url_for('home'))

# Function to delete a user from the database
def delete_user(user_id):
    conn = get_db()
    conn.execute('DELETE FROM User WHERE UserID = ?', (user_id,))
    conn.commit()

# Homepage route
@app.route('/homepage')
@login_required
def homepage():
    Cars = os.path.join(app.config['UPLOAD_FOLDER'], 'Cars.jpg')
    return render_template('homepage.html', user_image=Cars, title="Homepage")

# Cars page route
@app.route('/cars')
@login_required
def cars():
    Ferrari = os.path.join(app.config['UPLOAD_FOLDER'], 'Ferrari.jpg')
    cars = get_cars()  # Fetch car data including image filenames
    return render_template('cars.html', cars=cars, user_image=Ferrari, title="Cars")

# Engine specs route
@app.route('/engines')
@login_required
def engine_specs():
    Engine = os.path.join(app.config['UPLOAD_FOLDER'], 'Engine.jpg')
    engines = get_engines()
    return render_template('engines.html', engines=engines, user_image=Engine, title="Engines")

# Pricing info route
@app.route('/pricing')
@login_required
def pricing_info():
    Pricing = os.path.join(app.config['UPLOAD_FOLDER'], 'Pricing.jpg')
    pricing = get_pricing()
    return render_template('pricing.html', pricing=pricing, user_image=Pricing, title="Pricing")

# Fetch cars including their image filenames
def get_cars(query=None):
    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()

    if query:
        cur.execute("SELECT Make, Model, Year, CountryOfOrigin, ImageFileName FROM Cars WHERE Make LIKE ? OR Model LIKE ?", ('%' + query + '%', '%' + query + '%'))
    else:
        cur.execute('SELECT Make, Model, Year, CountryOfOrigin, ImageFileName FROM Cars')

    cars = cur.fetchall()
    cur.close()
    return cars

# Fetch engine specs related to a specific car
def get_engines(model=None):
    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()
    
    if model:
        cur.execute("SELECT EngineType, HorsePower, TorqueNm, ZeroToSixty FROM EngineSpecs WHERE CarID = (SELECT CarID FROM Cars WHERE Model = ?)", (model,))
    else:
        cur.execute("SELECT * FROM EngineSpecs")

    engines = cur.fetchall()
    cur.close()
    return engines

# Fetch pricing info related to a specific car
def get_pricing(model=None):
    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()
    
    if model:
        cur.execute("SELECT Price FROM Pricing WHERE CarID = (SELECT CarID FROM Cars WHERE Model = ?)", (model,))
    else:
        cur.execute("SELECT * FROM Pricing")

    pricing = cur.fetchall()
    cur.close()
    return pricing

# Search route
@app.route('/search', methods=['GET'])
@login_required
def search():
    query = request.args.get('query')
    cars = get_cars(query)
    return render_template('cars.html', cars=cars, title="Search Results")

# Error handler for 404
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# Before request to handle database connections
@app.before_request
def before_request():
    create_user_table()

# After request to close the database connection
@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

if __name__ == '__main__':
    app.run(debug=True)
