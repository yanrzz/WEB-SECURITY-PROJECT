from flask import Flask, render_template, request, redirect, url_for, session, flash
import bcrypt, sqlite3, time
from functools import wraps

app = Flask(__name__)
app.secret_key = 'ganti_dengan_kunci_rahasia_yang_sangat_panjang_dan_acak'

# Konfigurasi proteksi brute force
MAX_ATTEMPTS = 5
LOCKOUT_TIME = 900  # 15 menit dalam detik
login_attempts = {}  # {username: {'count': int, 'last_attempt': float}}

def get_db():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL)''')

def is_locked_out(username):
    if username not in login_attempts:
        return False, 0
    data = login_attempts[username]
    if data['count'] >= MAX_ATTEMPTS:
        elapsed = time.time() - data['last_attempt']
        if elapsed < LOCKOUT_TIME:
            return True, int((LOCKOUT_TIME - elapsed) / 60)
        login_attempts[username] = {'count': 0, 'last_attempt': 0}
    return False, 0

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        locked, minutes_left = is_locked_out(username)
        if locked:
            flash(f'Akun terkunci. Coba lagi dalam {minutes_left} menit.')
            return render_template('login.html')
        # Parameterized query - aman dari SQL Injection
        with get_db() as conn:
            user = conn.execute(
                'SELECT * FROM users WHERE username = ?', (username,)
            ).fetchone()
        if user and bcrypt.checkpw(password.encode(), user['password_hash'].encode()):
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            if username in login_attempts:
                del login_attempts[username]
            return redirect(url_for('dashboard'))
        else:
            if username not in login_attempts:
                login_attempts[username] = {'count': 0, 'last_attempt': 0}
            login_attempts[username]['count'] += 1
            login_attempts[username]['last_attempt'] = time.time()
            remaining = MAX_ATTEMPTS - login_attempts[username]['count']
            flash(f'Login gagal. Sisa percobaan: {remaining}')
    return render_template('login.html')

from functools import wraps

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=session['username'])

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not username or not password:
            flash('Username dan password tidak boleh kosong!')
            return render_template('register.html')
        # Hash password dengan bcrypt
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(12)).decode()
        try:
            with get_db() as conn:
                conn.execute(
                    'INSERT INTO users (username, password_hash) VALUES (?, ?)',
                    (username, hashed))
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username sudah digunakan.')
    return render_template('register.html')

if __name__ == '__main__':
    init_db()
    app.run(debug=True)