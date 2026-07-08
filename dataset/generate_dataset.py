"""
Dataset Generator for AI Code Review
Generates labeled training data with code smells, vulnerabilities, and style issues.
"""

import json
import random
import csv
import os

# ─────────────────────────────────────────────
# CATEGORY 1: SQL INJECTION VULNERABILITIES
# ─────────────────────────────────────────────
SQL_INJECTION_BAD = [
    {
        "code": """def get_user(username):
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()""",
        "label": "vulnerability",
        "category": "sql_injection",
        "severity": "critical",
        "message": "SQL Injection: String concatenation used in SQL query. Use parameterized queries.",
        "fix": """def get_user(username):
    query = "SELECT * FROM users WHERE username = %s"
    cursor.execute(query, (username,))
    return cursor.fetchone()"""
    },
    {
        "code": """def search_products(name, category):
    sql = f"SELECT * FROM products WHERE name LIKE '%{name}%' AND category='{category}'"
    db.execute(sql)
    return db.fetchall()""",
        "label": "vulnerability",
        "category": "sql_injection",
        "severity": "critical",
        "message": "SQL Injection: f-string interpolation in SQL query is dangerous.",
        "fix": """def search_products(name, category):
    sql = "SELECT * FROM products WHERE name LIKE %s AND category=%s"
    db.execute(sql, (f'%{name}%', category))
    return db.fetchall()"""
    },
    {
        "code": """def delete_record(table, record_id):
    query = "DELETE FROM " + table + " WHERE id = " + str(record_id)
    conn.execute(query)
    conn.commit()""",
        "label": "vulnerability",
        "category": "sql_injection",
        "severity": "critical",
        "message": "SQL Injection: Dynamic table name and record_id via concatenation. Use allowlists for table names.",
        "fix": """ALLOWED_TABLES = {'users', 'products', 'orders'}

def delete_record(table, record_id):
    if table not in ALLOWED_TABLES:
        raise ValueError(f"Invalid table: {table}")
    query = f"DELETE FROM {table} WHERE id = %s"
    conn.execute(query, (record_id,))
    conn.commit()"""
    },
    {
        "code": """@app.route('/login', methods=['POST'])
def login():
    user = request.form['user']
    pwd  = request.form['password']
    res  = db.execute("SELECT * FROM users WHERE user='" + user + "' AND password='" + pwd + "'")
    if res.fetchone():
        return redirect('/dashboard')
    return 'Invalid credentials', 401""",
        "label": "vulnerability",
        "category": "sql_injection",
        "severity": "critical",
        "message": "SQL Injection in login: classic OR 1=1 attack vector. Use parameterized queries and password hashing.",
        "fix": """@app.route('/login', methods=['POST'])
def login():
    user = request.form['user']
    pwd  = request.form['password']
    res  = db.execute("SELECT * FROM users WHERE user=%s", (user,))
    row  = res.fetchone()
    if row and bcrypt.checkpw(pwd.encode(), row['password_hash']):
        return redirect('/dashboard')
    return 'Invalid credentials', 401"""
    },
    {
        "code": """def get_orders(user_id, status=None):
    base = "SELECT * FROM orders WHERE user_id=" + str(user_id)
    if status:
        base += " AND status='" + status + "'"
    return db.execute(base).fetchall()""",
        "label": "vulnerability",
        "category": "sql_injection",
        "severity": "critical",
        "message": "SQL Injection: Dynamic query building with string concatenation.",
        "fix": """def get_orders(user_id, status=None):
    params = [user_id]
    base = "SELECT * FROM orders WHERE user_id=%s"
    if status:
        base += " AND status=%s"
        params.append(status)
    return db.execute(base, params).fetchall()"""
    },
]

SQL_INJECTION_GOOD = [
    {
        "code": """def get_user(username):
    query = "SELECT * FROM users WHERE username = %s"
    cursor.execute(query, (username,))
    return cursor.fetchone()""",
        "label": "clean",
        "category": "sql_injection",
        "severity": "none",
        "message": "Parameterized query used correctly.",
        "fix": ""
    },
    {
        "code": """def get_orders(user_id, status=None):
    params = [user_id]
    base = "SELECT * FROM orders WHERE user_id = %s"
    if status:
        base += " AND status = %s"
        params.append(status)
    return db.execute(base, params).fetchall()""",
        "label": "clean",
        "category": "sql_injection",
        "severity": "none",
        "message": "Safe parameterized query building.",
        "fix": ""
    },
    {
        "code": """from sqlalchemy.orm import Session

def find_product(db: Session, product_id: int):
    return db.query(Product).filter(Product.id == product_id).first()""",
        "label": "clean",
        "category": "sql_injection",
        "severity": "none",
        "message": "ORM-based query is safe from SQL injection.",
        "fix": ""
    },
]

# ─────────────────────────────────────────────
# CATEGORY 2: XSS VULNERABILITIES
# ─────────────────────────────────────────────
XSS_BAD = [
    {
        "code": """@app.route('/greet')
def greet():
    name = request.args.get('name', '')
    return f'<h1>Hello, {name}!</h1>'""",
        "label": "vulnerability",
        "category": "xss",
        "severity": "high",
        "message": "XSS: User input directly embedded in HTML response without escaping.",
        "fix": """from markupsafe import escape

@app.route('/greet')
def greet():
    name = escape(request.args.get('name', ''))
    return f'<h1>Hello, {name}!</h1>'"""
    },
    {
        "code": """def render_comment(comment_text):
    return '<div class="comment">' + comment_text + '</div>'""",
        "label": "vulnerability",
        "category": "xss",
        "severity": "high",
        "message": "XSS: Unsanitized user-generated content inserted into HTML.",
        "fix": """from markupsafe import escape

def render_comment(comment_text):
    safe = escape(comment_text)
    return f'<div class="comment">{safe}</div>'"""
    },
    {
        "code": """# React component
function UserProfile({ user }) {
  return (
    <div dangerouslySetInnerHTML={{ __html: user.bio }} />
  );
}""",
        "label": "vulnerability",
        "category": "xss",
        "severity": "high",
        "message": "XSS: dangerouslySetInnerHTML with unsanitized user input.",
        "fix": """import DOMPurify from 'dompurify';

function UserProfile({ user }) {
  const cleanBio = DOMPurify.sanitize(user.bio);
  return (
    <div dangerouslySetInnerHTML={{ __html: cleanBio }} />
  );
}"""
    },
    {
        "code": """@app.route('/search')
def search():
    q = request.args.get('q', '')
    results = search_db(q)
    html = f'<p>Results for: {q}</p>'
    for r in results:
        html += f'<div>{r["title"]}</div>'
    return html""",
        "label": "vulnerability",
        "category": "xss",
        "severity": "high",
        "message": "XSS: Search query reflected directly in HTML response.",
        "fix": """from markupsafe import escape
from flask import render_template_string

@app.route('/search')
def search():
    q = request.args.get('q', '')
    results = search_db(q)
    return render_template('search.html', query=q, results=results)"""
    },
    {
        "code": """document.getElementById('output').innerHTML = location.search.substring(1);""",
        "label": "vulnerability",
        "category": "xss",
        "severity": "critical",
        "message": "DOM-based XSS: URL parameter directly assigned to innerHTML.",
        "fix": """const params = new URLSearchParams(location.search);
const value = params.get('q') || '';
document.getElementById('output').textContent = value;"""
    },
]

XSS_GOOD = [
    {
        "code": """from markupsafe import escape

@app.route('/greet')
def greet():
    name = escape(request.args.get('name', ''))
    return f'<h1>Hello, {name}!</h1>'""",
        "label": "clean",
        "category": "xss",
        "severity": "none",
        "message": "Input properly escaped before HTML rendering.",
        "fix": ""
    },
    {
        "code": """function renderMessage(text) {
  const el = document.createElement('p');
  el.textContent = text;  // Safe: textContent never executes HTML
  return el;
}""",
        "label": "clean",
        "category": "xss",
        "severity": "none",
        "message": "textContent used instead of innerHTML — XSS safe.",
        "fix": ""
    },
]

# ─────────────────────────────────────────────
# CATEGORY 3: CODE SMELLS
# ─────────────────────────────────────────────
CODE_SMELLS_BAD = [
    {
        "code": """def process(d, x, y, z, flag, opt, mode, retries, timeout, limit, offset):
    if flag:
        if mode == 1:
            for i in range(len(d)):
                if d[i] > x:
                    if d[i] < y:
                        if z:
                            result = d[i] * 2
                            if result > limit:
                                result = limit
                            return result
    return None""",
        "label": "code_smell",
        "category": "deep_nesting",
        "severity": "medium",
        "message": "Deep nesting (>4 levels): reduces readability. Refactor using early returns or helper functions.",
        "fix": """def process(d, x, y, z, flag, opt, mode, retries, timeout, limit, offset):
    if not flag or mode != 1 or not z:
        return None
    for value in d:
        if x < value < y:
            return min(value * 2, limit)
    return None"""
    },
    {
        "code": """def do_everything(user_id, product_id, qty, promo, addr, payment, notify):
    # fetch user
    user = db.query("SELECT * FROM users WHERE id=%s", user_id)
    # validate product
    product = db.query("SELECT * FROM products WHERE id=%s", product_id)
    if product['stock'] < qty:
        raise ValueError("Out of stock")
    # apply promo
    price = product['price'] * qty
    if promo:
        discount = db.query("SELECT discount FROM promos WHERE code=%s", promo)
        price *= (1 - discount / 100)
    # charge card
    charge_result = payment_gateway.charge(payment, price)
    if not charge_result['success']:
        raise Exception("Payment failed")
    # create order
    order_id = db.execute("INSERT INTO orders ...", ...)
    # update stock
    db.execute("UPDATE products SET stock=stock-%s WHERE id=%s", qty, product_id)
    # send email
    if notify:
        send_email(user['email'], f"Order #{order_id} confirmed!")
    return order_id""",
        "label": "code_smell",
        "category": "god_function",
        "severity": "high",
        "message": "God function: does too many things. Split into validate_order, process_payment, update_inventory, notify_user.",
        "fix": "Split into smaller single-responsibility functions."
    },
    {
        "code": """x = 86400
y = 3600
z = 60
timeout = 300
max_items = 100
retry_limit = 3

def calc(t):
    return t * 86400 + 3600""",
        "label": "code_smell",
        "category": "magic_numbers",
        "severity": "low",
        "message": "Magic numbers: Replace numeric literals with named constants for readability.",
        "fix": """SECONDS_PER_DAY = 86400
SECONDS_PER_HOUR = 3600
SECONDS_PER_MINUTE = 60
REQUEST_TIMEOUT = 300
MAX_ITEMS_PER_PAGE = 100
MAX_RETRY_ATTEMPTS = 3

def calc(t):
    return t * SECONDS_PER_DAY + SECONDS_PER_HOUR"""
    },
    {
        "code": """def get_data():
    try:
        result = fetch_from_api()
        return result
    except:
        pass""",
        "label": "code_smell",
        "category": "empty_except",
        "severity": "high",
        "message": "Bare except clause swallows all exceptions silently. Catch specific exceptions and log/re-raise.",
        "fix": """import logging

def get_data():
    try:
        result = fetch_from_api()
        return result
    except requests.Timeout as e:
        logging.error(f"API timeout: {e}")
        raise
    except requests.RequestException as e:
        logging.error(f"API error: {e}")
        return None"""
    },
    {
        "code": """class UserManager:
    def __init__(self):
        self.users = []
        self.admins = []
        self.banned = []
        self.premium = []
        self.verified = []

    def add_user(self, user):
        self.users.append(user)

    def add_admin(self, user):
        self.admins.append(user)
        self.users.append(user)

    def add_premium(self, user):
        self.premium.append(user)
        self.users.append(user)""",
        "label": "code_smell",
        "category": "data_clumps",
        "severity": "medium",
        "message": "Data clumps: User roles stored in separate lists. Use a User model with a roles field.",
        "fix": """from enum import Enum
from dataclasses import dataclass, field

class Role(Enum):
    USER = 'user'
    ADMIN = 'admin'
    PREMIUM = 'premium'
    VERIFIED = 'verified'

@dataclass
class User:
    id: int
    name: str
    roles: set = field(default_factory=set)

class UserManager:
    def __init__(self):
        self.users: dict[int, User] = {}

    def add_user(self, user: User):
        self.users[user.id] = user

    def grant_role(self, user_id: int, role: Role):
        self.users[user_id].roles.add(role)"""
    },
    {
        "code": """def calculate_area(shape, a, b, c, d, r):
    if shape == 'rectangle':
        return a * b
    elif shape == 'triangle':
        return 0.5 * a * b
    elif shape == 'circle':
        return 3.14159 * r * r
    elif shape == 'trapezoid':
        return 0.5 * (a + b) * c
    elif shape == 'ellipse':
        return 3.14159 * a * b
    else:
        raise ValueError(f"Unknown shape: {shape}")""",
        "label": "code_smell",
        "category": "long_if_chain",
        "severity": "medium",
        "message": "Long if-elif chain on type: Replace with polymorphism or a dispatch dictionary.",
        "fix": """import math
from abc import ABC, abstractmethod

class Shape(ABC):
    @abstractmethod
    def area(self) -> float: ...

class Rectangle(Shape):
    def __init__(self, width, height): self.w, self.h = width, height
    def area(self): return self.w * self.h

class Circle(Shape):
    def __init__(self, radius): self.r = radius
    def area(self): return math.pi * self.r ** 2"""
    },
    {
        "code": """def a(x):
    b = x * 2
    c = b + 10
    d = c / 3
    return d

def p(u, s):
    r = a(s)
    u.bal += r
    return u""",
        "label": "code_smell",
        "category": "poor_naming",
        "severity": "medium",
        "message": "Cryptic variable and function names: Use descriptive names that express intent.",
        "fix": """def calculate_bonus(sales_amount):
    doubled_sales = sales_amount * 2
    adjusted_sales = doubled_sales + 10
    bonus = adjusted_sales / 3
    return bonus

def apply_bonus_to_user(user, sales_amount):
    bonus = calculate_bonus(sales_amount)
    user.balance += bonus
    return user"""
    },
    {
        "code": """def is_valid_email(email):
    if '@' in email:
        parts = email.split('@')
        if len(parts) == 2:
            if parts[0] != '':
                if parts[1] != '':
                    if '.' in parts[1]:
                        return True
    return False""",
        "label": "code_smell",
        "category": "deep_nesting",
        "severity": "low",
        "message": "Deeply nested conditionals for validation. Use early returns or regex.",
        "fix": """import re

def is_valid_email(email: str) -> bool:
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))"""
    },
]

CODE_SMELLS_GOOD = [
    {
        "code": """def calculate_discount(price: float, discount_pct: float) -> float:
    \"\"\"Apply a percentage discount to a price.\"\"\"
    if not 0 <= discount_pct <= 100:
        raise ValueError(f"Discount must be 0-100, got {discount_pct}")
    return price * (1 - discount_pct / 100)""",
        "label": "clean",
        "category": "code_smell",
        "severity": "none",
        "message": "Well-named function with type hints and validation.",
        "fix": ""
    },
    {
        "code": """import logging
logger = logging.getLogger(__name__)

def fetch_user(user_id: int):
    try:
        return db.get(User, user_id)
    except DatabaseError as e:
        logger.exception("Failed to fetch user %s", user_id)
        raise""",
        "label": "clean",
        "category": "code_smell",
        "severity": "none",
        "message": "Specific exception handling with proper logging.",
        "fix": ""
    },
]

# ─────────────────────────────────────────────
# CATEGORY 4: SECURITY VULNERABILITIES
# ─────────────────────────────────────────────
SECURITY_BAD = [
    {
        "code": """import hashlib

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()""",
        "label": "vulnerability",
        "category": "weak_crypto",
        "severity": "critical",
        "message": "MD5 is cryptographically broken. Use bcrypt, argon2, or scrypt for passwords.",
        "fix": """import bcrypt

def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))

def verify_password(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed)"""
    },
    {
        "code": """SECRET_KEY = "mysecretkey123"
DB_PASSWORD = "admin123"
API_KEY = "sk-abc123def456"
JWT_SECRET = "jwt_secret_do_not_share"

app = Flask(__name__)
app.secret_key = SECRET_KEY""",
        "label": "vulnerability",
        "category": "hardcoded_secrets",
        "severity": "critical",
        "message": "Hardcoded credentials in source code. Use environment variables or a secrets manager.",
        "fix": """import os
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.environ['SECRET_KEY']
DB_PASSWORD = os.environ['DB_PASSWORD']
API_KEY     = os.environ['API_KEY']
JWT_SECRET  = os.environ['JWT_SECRET']

app = Flask(__name__)
app.secret_key = SECRET_KEY"""
    },
    {
        "code": """import subprocess

def run_command(user_input):
    result = subprocess.run(user_input, shell=True, capture_output=True)
    return result.stdout.decode()""",
        "label": "vulnerability",
        "category": "command_injection",
        "severity": "critical",
        "message": "Command injection: shell=True with user input allows arbitrary command execution.",
        "fix": """import subprocess
import shlex

ALLOWED_COMMANDS = {'ls', 'echo', 'date'}

def run_command(command: str, args: list[str]) -> str:
    if command not in ALLOWED_COMMANDS:
        raise ValueError(f"Command not allowed: {command}")
    result = subprocess.run([command] + args, shell=False, capture_output=True, timeout=10)
    return result.stdout.decode()"""
    },
    {
        "code": """import pickle

@app.route('/load', methods=['POST'])
def load_data():
    data = request.get_data()
    obj = pickle.loads(data)
    return jsonify(obj)""",
        "label": "vulnerability",
        "category": "insecure_deserialization",
        "severity": "critical",
        "message": "Insecure deserialization: pickle.loads on user data allows arbitrary code execution.",
        "fix": """import json

@app.route('/load', methods=['POST'])
def load_data():
    data = request.get_json(force=True)
    # Validate schema strictly
    validated = validate_schema(data)
    return jsonify(validated)"""
    },
    {
        "code": """@app.route('/file')
def serve_file():
    filename = request.args.get('name')
    path = '/var/www/files/' + filename
    with open(path) as f:
        return f.read()""",
        "label": "vulnerability",
        "category": "path_traversal",
        "severity": "critical",
        "message": "Path traversal: ../../../etc/passwd attack possible. Use os.path.realpath and validate.",
        "fix": """import os
from flask import abort

SAFE_DIR = '/var/www/files'

@app.route('/file')
def serve_file():
    filename = request.args.get('name', '')
    # Resolve and validate path stays within safe directory
    safe_path = os.path.realpath(os.path.join(SAFE_DIR, filename))
    if not safe_path.startswith(SAFE_DIR + os.sep):
        abort(403)
    with open(safe_path) as f:
        return f.read()"""
    },
    {
        "code": """def verify_token(token):
    import jwt
    payload = jwt.decode(token, options={"verify_signature": False})
    return payload""",
        "label": "vulnerability",
        "category": "broken_auth",
        "severity": "critical",
        "message": "JWT signature verification disabled: allows token forgery.",
        "fix": """def verify_token(token: str) -> dict:
    import jwt
    payload = jwt.decode(
        token,
        key=os.environ['JWT_SECRET'],
        algorithms=['HS256'],
        options={"require": ["exp", "iat", "sub"]}
    )
    return payload"""
    },
    {
        "code": """@app.route('/reset', methods=['POST'])
def reset_password():
    email = request.form['email']
    token = str(random.randint(100000, 999999))
    send_reset_email(email, token)
    db.set(f'reset:{email}', token, ex=3600)
    return 'Reset email sent'""",
        "label": "vulnerability",
        "category": "weak_random",
        "severity": "high",
        "message": "Weak random for security token: random.randint is predictable. Use secrets module.",
        "fix": """import secrets

@app.route('/reset', methods=['POST'])
def reset_password():
    email = request.form['email']
    token = secrets.token_urlsafe(32)
    send_reset_email(email, token)
    db.set(f'reset:{email}', token, ex=3600)
    return 'Reset email sent'"""
    },
]

SECURITY_GOOD = [
    {
        "code": """import bcrypt

def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))

def verify_password(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode(), hashed)""",
        "label": "clean",
        "category": "security",
        "severity": "none",
        "message": "Strong password hashing with bcrypt.",
        "fix": ""
    },
    {
        "code": """import os
import secrets

SECRET_KEY = os.environ['SECRET_KEY']
DB_PASSWORD = os.environ['DB_PASSWORD']

def generate_token():
    return secrets.token_urlsafe(32)""",
        "label": "clean",
        "category": "security",
        "severity": "none",
        "message": "Secrets from env vars and cryptographically secure token generation.",
        "fix": ""
    },
]

# ─────────────────────────────────────────────
# CATEGORY 5: PERFORMANCE ISSUES
# ─────────────────────────────────────────────
PERFORMANCE_BAD = [
    {
        "code": """def get_user_emails(user_ids):
    emails = []
    for uid in user_ids:
        user = db.query("SELECT email FROM users WHERE id=%s", uid)
        emails.append(user['email'])
    return emails""",
        "label": "performance",
        "category": "n_plus_1_query",
        "severity": "high",
        "message": "N+1 query: fetching each user separately in a loop. Use a single IN query.",
        "fix": """def get_user_emails(user_ids: list[int]) -> list[str]:
    if not user_ids:
        return []
    placeholders = ','.join(['%s'] * len(user_ids))
    rows = db.query(f"SELECT email FROM users WHERE id IN ({placeholders})", user_ids)
    return [row['email'] for row in rows]"""
    },
    {
        "code": """def find_duplicates(items):
    duplicates = []
    for i in range(len(items)):
        for j in range(len(items)):
            if i != j and items[i] == items[j]:
                if items[i] not in duplicates:
                    duplicates.append(items[i])
    return duplicates""",
        "label": "performance",
        "category": "inefficient_algorithm",
        "severity": "high",
        "message": "O(n³) algorithm for duplicate detection. Use a Counter or set for O(n).",
        "fix": """from collections import Counter

def find_duplicates(items: list) -> list:
    return [item for item, count in Counter(items).items() if count > 1]"""
    },
    {
        "code": """def load_all_users():
    users = db.execute("SELECT * FROM users").fetchall()
    return users  # returns millions of rows""",
        "label": "performance",
        "category": "missing_pagination",
        "severity": "high",
        "message": "Loading entire table into memory: add LIMIT/OFFSET or cursor-based pagination.",
        "fix": """def load_users(page: int = 1, page_size: int = 100):
    offset = (page - 1) * page_size
    return db.execute(
        "SELECT * FROM users ORDER BY id LIMIT %s OFFSET %s",
        (page_size, offset)
    ).fetchall()"""
    },
    {
        "code": """def sum_squares(n):
    return sum([x**2 for x in range(n)])""",
        "label": "performance",
        "category": "unnecessary_list",
        "severity": "low",
        "message": "List comprehension creates an unnecessary list: use a generator expression.",
        "fix": """def sum_squares(n: int) -> int:
    return sum(x**2 for x in range(n))"""
    },
    {
        "code": """import time

@app.route('/heavy')
def heavy_computation():
    time.sleep(0)  # simulates expensive op every request
    result = expensive_function()
    return jsonify(result)""",
        "label": "performance",
        "category": "missing_cache",
        "severity": "medium",
        "message": "Expensive computation on every request: add caching with TTL.",
        "fix": """from functools import lru_cache
from flask_caching import Cache

cache = Cache(config={'CACHE_TYPE': 'RedisCache', 'CACHE_DEFAULT_TIMEOUT': 300})

@app.route('/heavy')
@cache.cached(timeout=300)
def heavy_computation():
    result = expensive_function()
    return jsonify(result)"""
    },
]

PERFORMANCE_GOOD = [
    {
        "code": """from collections import Counter

def find_duplicates(items: list) -> list:
    return [item for item, count in Counter(items).items() if count > 1]""",
        "label": "clean",
        "category": "performance",
        "severity": "none",
        "message": "O(n) duplicate detection using Counter.",
        "fix": ""
    },
    {
        "code": """def get_user_emails(user_ids: list[int]) -> list[str]:
    if not user_ids:
        return []
    rows = db.query(
        "SELECT email FROM users WHERE id = ANY(%s)", (user_ids,)
    )
    return [row['email'] for row in rows]""",
        "label": "clean",
        "category": "performance",
        "severity": "none",
        "message": "Batch query avoids N+1 problem.",
        "fix": ""
    },
]

# ─────────────────────────────────────────────
# CATEGORY 6: STYLE VIOLATIONS
# ─────────────────────────────────────────────
STYLE_BAD = [
    {
        "code": """def   calculateTotalPrice( items,tax_rate,discount=0 ):
    total=0
    for i in items:
        total=total+i['price']
    total=total*(1+tax_rate)
    total=total*(1-discount)
    return(total)""",
        "label": "style",
        "category": "pep8_violation",
        "severity": "low",
        "message": "PEP 8 violations: extra spaces, missing spaces around operators, inconsistent formatting.",
        "fix": """def calculate_total_price(items, tax_rate, discount=0):
    total = sum(item['price'] for item in items)
    total *= (1 + tax_rate)
    total *= (1 - discount)
    return total"""
    },
    {
        "code": """def process_user_data(user_data_dict_from_database_with_all_fields, enable_email_notification_flag=True, maximum_retry_count_for_failed_operations=3):
    pass""",
        "label": "style",
        "category": "long_line",
        "severity": "low",
        "message": "Line exceeds 79 characters (PEP 8). Break long signatures.",
        "fix": """def process_user_data(
    user_data: dict,
    enable_notifications: bool = True,
    max_retries: int = 3,
) -> None:
    pass"""
    },
    {
        "code": """def foo(x):
    y = x + 1
    z = y * 2
    return z

def bar(): return 42

class myClass:
    def __init__(self):
        self.Value=10""",
        "label": "style",
        "category": "naming_convention",
        "severity": "low",
        "message": "Class name should be CamelCase; attributes should use snake_case; add docstrings.",
        "fix": """def foo(x: int) -> int:
    \"\"\"Double the successor of x.\"\"\"
    return (x + 1) * 2

def bar() -> int:
    \"\"\"Return the answer.\"\"\"
    return 42

class MyClass:
    \"\"\"Represent a thing with a value.\"\"\"
    def __init__(self):
        self.value = 10"""
    },
]

STYLE_GOOD = [
    {
        "code": """def calculate_total(items: list[dict], tax_rate: float = 0.1) -> float:
    \"\"\"Calculate total price including tax.

    Args:
        items: List of items with 'price' key.
        tax_rate: Tax rate as a decimal (default 10%).

    Returns:
        Total price after tax.
    \"\"\"
    subtotal = sum(item['price'] for item in items)
    return subtotal * (1 + tax_rate)""",
        "label": "clean",
        "category": "style",
        "severity": "none",
        "message": "Well-formatted function with type hints and docstring.",
        "fix": ""
    },
]

# ─────────────────────────────────────────────
# ASSEMBLE FULL DATASET
# ─────────────────────────────────────────────
ALL_SAMPLES = (
    SQL_INJECTION_BAD + SQL_INJECTION_GOOD +
    XSS_BAD + XSS_GOOD +
    CODE_SMELLS_BAD + CODE_SMELLS_GOOD +
    SECURITY_BAD + SECURITY_GOOD +
    PERFORMANCE_BAD + PERFORMANCE_GOOD +
    STYLE_BAD + STYLE_GOOD
)

def save_dataset(output_dir: str = "."):
    os.makedirs(output_dir, exist_ok=True)

    # Add unique IDs
    for i, sample in enumerate(ALL_SAMPLES):
        sample['id'] = f"sample_{i:04d}"

    # JSON dataset
    json_path = os.path.join(output_dir, "code_review_dataset.json")
    with open(json_path, 'w') as f:
        json.dump(ALL_SAMPLES, f, indent=2)
    print(f"Saved {len(ALL_SAMPLES)} samples → {json_path}")

    # CSV dataset (without 'fix' for cleaner tabular view)
    csv_path = os.path.join(output_dir, "code_review_dataset.csv")
    fieldnames = ['id', 'label', 'category', 'severity', 'message', 'code']
    with open(csv_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(ALL_SAMPLES)
    print(f"Saved CSV → {csv_path}")

    # Summary
    from collections import Counter
    label_counts = Counter(s['label'] for s in ALL_SAMPLES)
    cat_counts   = Counter(s['category'] for s in ALL_SAMPLES)
    print("\n=== Dataset Summary ===")
    print("Labels:    ", dict(label_counts))
    print("Categories:", dict(cat_counts))

if __name__ == '__main__':
    save_dataset(os.path.dirname(os.path.abspath(__file__)))
