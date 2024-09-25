import sqlite3
from flask import Flask, render_template, request, g, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Required for session management

# Path for storing static images
picFolder = os.path.join('static', 'pics')
app.config['UPLOAD_FOLDER'] = picFolder

DATABASE = 'My_favourite_cars.db'

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
    except sqlite3.IntegrityError:
        return "User already exists."

# Validate login
def valid_login(username, password):
    user = query_db('SELECT * FROM User WHERE username = ?', [username], one=True)
    if user and check_password_hash(user[2], password):  # User is stored as (UserID, username, password)
        return True
    return False

# Log in the user
def log_the_user_in(username):
    session['username'] = username  # Store the username in the session
    return redirect(url_for('homepage'))  # Redirect to the homepage after login

# Logout route
@app.route('/logout')
def logout():
    session.clear()  # Clear the user session
    return redirect(url_for('home'))  # Redirect to the home page

# Home page route that gives option to login or register
@app.route('/')
def home():
    return render_template('home.html')

# Login page route
@app.route('/login', methods=['POST', 'GET'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if valid_login(username, password):
            return log_the_user_in(username)
        else:
            error = 'Invalid username/password'
    return render_template('login.html', error=error)

# Route to register a new user
@app.route('/register', methods=['POST', 'GET'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        result = insert_user(username, password)
        if result:
            error = result
        else:
            return "User registered successfully!"
    return render_template('register.html', error=error)

# Fetch cars
def get_cars():
    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()
    cur.execute('SELECT Make, Model, Year, CountryOfOrigin FROM Cars')
    cars = cur.fetchall()
    conn.close()
    return cars

# Fetch engine specs
def get_engines():
    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()
    cur.execute('SELECT Make, Model, EngineType, HorsePower, TorqueNm, ZeroToSixty FROM EngineSpecs')
    engines = cur.fetchall()
    conn.close()
    return engines

# Fetch pricing details
def get_pricing():
    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()
    cur.execute('SELECT Make, Model, Price FROM Pricing')
    pricing = cur.fetchall()
    conn.close()
    return pricing

# Cars page route
@app.route('/cars')
def cars():  # Changed from index to cars
    Ferrari = os.path.join(app.config['UPLOAD_FOLDER'], 'Ferrari.jpg')
    cars = get_cars()
    return render_template('cars.html', cars=cars, user_image=Ferrari)  # Updated to render cars.html

# Home page route after login
@app.route('/homepage')
def homepage():
    return render_template('homepage.html')  # Render homepage.html

# Engine specs route
@app.route('/engines')
def engine_specs():
    engines = get_engines()
    return render_template('engines.html', engines=engines)

# Pricing info route
@app.route('/pricing')
def pricing_info():
    pricing = get_pricing()
    return render_template('pricing.html', pricing=pricing)

# Close database connection
@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# Run the Flask app
if __name__ == '__main__':
    # Create the User table on app startup
    with app.app_context():
        create_user_table()
    app.run(debug=True)
