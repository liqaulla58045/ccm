from flask import Flask, render_template, request, redirect, url_for, session, g, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask_mail import Mail, Message

app = Flask(__name__)
app.secret_key = 'your_secret_key'
DATABASE = 'database.db'

# Email configuration for Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.example.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email@example.com'
app.config['MAIL_PASSWORD'] = 'your_email_password'
mail = Mail(app)

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

def execute_db(query, args=()):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(query, args)
    conn.commit()
    return cur.lastrowid

def login_required(role=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            if role and session.get('role') != role:
                return "Unauthorized", 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        role = 'patient'  # Only patients can register
        existing_user = query_db('SELECT * FROM users WHERE email = ?', [email], one=True)
        if existing_user:
            return render_template('register.html', error="Email already registered")
        execute_db('INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
                   (username, email, hashed_password, role))
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = query_db('SELECT * FROM users WHERE email = ?', [email], one=True)
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            if user['role'] == 'patient':
                return redirect(url_for('dashboard'))
            elif user['role'] == 'doctor':
                return redirect(url_for('doctor_dashboard'))
        else:
            return render_template('login.html', error="Invalid credentials")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required(role='patient')
def dashboard():
    user_id = session['user_id']
    appointments = query_db('''
        SELECT a.id, a.date, a.time, u.username as doctor_name
        FROM appointments a JOIN users u ON a.doctor_id = u.id
        WHERE a.patient_id = ?
        ORDER BY a.date, a.time
    ''', [user_id])
    doctors = query_db('SELECT id, username FROM users WHERE role = "doctor"')
    # Convert sqlite3.Row objects to dicts for JSON serialization
    appointments_list = [dict(appt) for appt in appointments]
    return render_template('dashboard_v2.html', appointments=appointments_list, doctors=doctors)

@app.route('/book_appointment', methods=['GET', 'POST'])
@login_required(role='patient')
def book_appointment():
    if request.method == 'POST':
        patient_id = session['user_id']
        doctor_id = request.form['doctor_id']
        date = request.form['date']
        time = request.form['time']
        execute_db('INSERT INTO appointments (patient_id, doctor_id, date, time) VALUES (?, ?, ?, ?)',
                   (patient_id, doctor_id, date, time))
        return redirect(url_for('dashboard'))
    doctors = query_db('SELECT id, username FROM users WHERE role = "doctor"')
    return render_template('book_appointment.html', doctors=doctors)

@app.route('/view_appointments')
@login_required()
def view_appointments():
    user_id = session['user_id']
    role = session['role']
    if role == 'patient':
        appointments = query_db('''
            SELECT a.id, a.date, a.time, u.username as doctor_name
            FROM appointments a JOIN users u ON a.doctor_id = u.id
            WHERE a.patient_id = ?
            ORDER BY a.date, a.time
        ''', [user_id])
    elif role == 'doctor':
        appointments = query_db('''
            SELECT a.id, a.date, a.time, u.username as patient_name
            FROM appointments a JOIN users u ON a.patient_id = u.id
            WHERE a.doctor_id = ?
            ORDER BY a.date, a.time
        ''', [user_id])
    else:
        appointments = []
    return render_template('view_appointments.html', appointments=appointments, role=role)

@app.route('/doctor_dashboard')
@login_required(role='doctor')
def doctor_dashboard():
    user_id = session['user_id']
    appointments = query_db('''
        SELECT a.id, a.date, a.time, u.username as patient_name
        FROM appointments a JOIN users u ON a.patient_id = u.id
        WHERE a.doctor_id = ?
        ORDER BY a.date, a.time
    ''', [user_id])
    # Convert sqlite3.Row objects to dicts for JSON serialization
    appointments_list = [dict(appt) for appt in appointments]
    return render_template('doctor_dashboard_v4.html', appointments=appointments_list)

def init_db():
    with app.app_context():
        db = get_db()
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                role TEXT NOT NULL
            )
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS appointments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                patient_id INTEGER NOT NULL,
                doctor_id INTEGER NOT NULL,
                date TEXT NOT NULL,
                time TEXT NOT NULL,
                FOREIGN KEY(patient_id) REFERENCES users(id),
                FOREIGN KEY(doctor_id) REFERENCES users(id)
            )
        ''')
        db.commit()

@app.route('/profile', methods=['GET', 'POST'])
@login_required()
def profile():
    user_id = session['user_id']
    user = query_db('SELECT id, username, email FROM users WHERE id = ?', [user_id], one=True)
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        # Check if email is already used by another user
        existing_user = query_db('SELECT * FROM users WHERE email = ? AND id != ?', [email, user_id], one=True)
        if existing_user:
            flash('Email is already registered by another user.', 'danger')
            return redirect(url_for('profile'))
        execute_db('UPDATE users SET username = ?, email = ? WHERE id = ?', (username, email, user_id))
        flash('Profile updated successfully.', 'success')
        return redirect(url_for('profile'))
    return render_template('profile.html', user=user)

@app.route('/cancel_appointment/<int:appointment_id>', methods=['POST'])
@login_required(role='patient')
def cancel_appointment(appointment_id):
    user_id = session['user_id']
    # Verify appointment belongs to user
    appointment = query_db('SELECT * FROM appointments WHERE id = ? AND patient_id = ?', (appointment_id, user_id), one=True)
    if appointment:
        execute_db('DELETE FROM appointments WHERE id = ?', (appointment_id,))
        flash('Appointment cancelled successfully.', 'success')
    else:
        flash('Appointment not found or unauthorized.', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/reschedule_appointment/<int:appointment_id>', methods=['GET', 'POST'])
@login_required(role='patient')
def reschedule_appointment(appointment_id):
    user_id = session['user_id']
    appointment = query_db('SELECT * FROM appointments WHERE id = ? AND patient_id = ?', (appointment_id, user_id), one=True)
    if not appointment:
        flash('Appointment not found or unauthorized.', 'danger')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        new_date = request.form['date']
        new_time = request.form['time']
        execute_db('UPDATE appointments SET date = ?, time = ? WHERE id = ?', (new_date, new_time, appointment_id))
        flash('Appointment rescheduled successfully.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('reschedule_appointment.html', appointment=appointment)

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
