import sqlite3
from flask import Flask, render_template
import os

app = Flask(__name__)

picFolder = os.path.join('static','pics')

app.config['UPLOAD_FOLDER'] = picFolder

DATABASE = 'My_favourite_cars.db'

def get_cars():
    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()
    cur.execute('SELECT Make, Model, Year, CountryOfOrigin FROM Cars')
    cars = cur.fetchall()
    conn.close()
    return cars


def get_engines():
    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()
    cur.execute('SELECT Make, Model, EngineType, HorsePower, TorqueNm, ZeroToSixty FROM EngineSpecs')
    engines = cur.fetchall()
    conn.close()
    return engines

def get_pricing():
    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()
    cur.execute('SELECT Make, Model, Price FROM Pricing')
    pricing = cur.fetchall()
    conn.close()
    return pricing

@app.route('/')
def index():
    Ferrari = os.path.join(app.config['UPLOAD_FOLDER'], 'Ferrari.jpg')
    cars = get_cars()
    return render_template('index.html', cars=cars, user_image = Ferrari)

@app.route('/engines')
def engine_specs():
    engines = get_engines()
    return render_template('engines.html', engines=engines)

@app.route('/pricing')
def pricing_info():
    pricing = get_pricing()
    return render_template('pricing.html', pricing=pricing)

if __name__ == '__main__':
    app.run(debug=True)
