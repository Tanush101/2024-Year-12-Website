from flask import Flask, render_template, request, g, session, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os

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

# Login page route
@app.route('/login', methods=['POST', 'GET'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
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
        result = insert_user(username, password)
        if result:
            error = result
        else:
            return "User registered successfully!"
    return render_template('register.html', error=error)

# Protected route for profile page
@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)

# Homepage route (protected)
@app.route('/homepage')
@login_required
def homepage():
    Cars = os.path.join(app.config['UPLOAD_FOLDER'], 'Cars.jpg')
    return render_template('homepage.html', user_image=Cars, title="Homepage")

# Cars page route (protected)
@app.route('/cars')
@login_required
def cars():
    Ferrari = os.path.join(app.config['UPLOAD_FOLDER'], 'Ferrari.jpg')
    cars = get_cars()
    return render_template('cars.html', cars=cars, user_image=Ferrari, title="Cars")

# Engine specs route (protected)
@app.route('/engines')
@login_required
def engine_specs():
    Engine = os.path.join(app.config['UPLOAD_FOLDER'], 'Engine.jpg')
    engines = get_engines()
    return render_template('engines.html', engines=engines, user_image=Engine, title="Engines")

# Pricing info route (protected)
@app.route('/pricing')
@login_required
def pricing_info():
    Pricing = os.path.join(app.config['UPLOAD_FOLDER'], 'Pricing.jpg')
    pricing = get_pricing()
    return render_template('pricing.html', pricing=pricing, user_image=Pricing, title="Pricing")

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

# Search route
@app.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    query = ''
    car_results = []
    engine_results = []
    pricing_results = []
    
    if request.method == 'POST':
        query = request.form.get('query')
        if query:
            # Search through cars
            car_results = query_db('SELECT Make, Model, Year, CountryOfOrigin FROM Cars WHERE Make LIKE ? OR Model LIKE ?', ['%' + query + '%', '%' + query + '%'])
            # Search through engines
            engine_results = query_db('SELECT Make, Model, EngineType, HorsePower, TorqueNm, ZeroToSixty FROM EngineSpecs WHERE Make LIKE ? OR Model LIKE ?', ['%' + query + '%', '%' + query + '%'])
            # Search through pricing
            pricing_results = query_db('SELECT Make, Model, Price FROM Pricing WHERE Make LIKE ? OR Model LIKE ?', ['%' + query + '%', '%' + query + '%'])
    
    return render_template('search_results.html', query=query, car_results=car_results, engine_results=engine_results, pricing_results=pricing_results)

# Close database connection
@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# Run the Flask app
if __name__ == '__main__':
    with app.app_context():
        create_user_table()
    app.run(debug=True)
