import hmac
import json
import os
from datetime import timedelta
from decimal import Decimal, InvalidOperation
from flask import Flask, Response, request, redirect, url_for, render_template_string, flash, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-change-me")
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.permanent_session_lifetime = timedelta(hours=12)
db_url = os.environ.get("DATABASE_URL", "sqlite:///local.db")
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}
db = SQLAlchemy(app)

class PurchaseOrder(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # sequential PO number
    vendor = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False, default="")
    amount = db.Column(db.Numeric(12, 2), nullable=False)
    created_at = db.Column(db.DateTime, server_default=func.now())

with app.app_context():
    db.create_all()

BASE = """
<!doctype html><html><head><meta charset="utf-8"><title>PO Tracker</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#1f6feb">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-title" content="PO Tracker">
<link rel="manifest" href="{{ url_for('manifest') }}">
<link rel="apple-touch-icon" href="{{ url_for('icon') }}">
<style>body{font-family:sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem}
table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #ddd;padding:.4rem;text-align:left}
.flash{color:#b00}.total{font-size:1.4rem;font-weight:bold}input,textarea{width:100%;padding:.4rem;margin:.2rem 0 .8rem}
button,a.btn{padding:.5rem 1rem;text-decoration:none}</style></head><body>
<h1>PO Tracker</h1>
<p><a class="btn" href="{{ url_for('index') }}">Dashboard</a> <a class="btn" href="{{ url_for('new_po') }}">New PO</a>{% if session.get('authenticated') %} <a class="btn" href="{{ url_for('logout') }}">Log out</a>{% endif %}</p>
{% for m in get_flashed_messages() %}<p class="flash">{{ m }}</p>{% endfor %}
{{ body|safe }}
<script>if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js');</script>
</body></html>
"""

INDEX = """
<p class="total">Total: ${{ "{:,.2f}".format(total) }} ({{ count }} POs)</p>
<table><tr><th>PO #</th><th>Vendor</th><th>Description</th><th>Amount</th><th>Created</th></tr>
{% for po in pos %}<tr><td>PO-{{ po.id }}</td><td>{{ po.vendor }}</td><td>{{ po.description }}</td>
<td>${{ "{:,.2f}".format(po.amount) }}</td><td>{{ po.created_at.strftime('%Y-%m-%d') if po.created_at else '' }}</td></tr>
{% else %}<tr><td colspan="5">No purchase orders yet.</td></tr>{% endfor %}</table>
"""

FORM = """
<form method="post">
<label>Vendor<input name="vendor" required maxlength="200"></label>
<label>Description<textarea name="description" rows="3"></textarea></label>
<label>Amount (USD)<input name="amount" required inputmode="decimal" placeholder="0.00"></label>
<button type="submit">Create PO</button>
</form>
"""

LOGIN = """
<form method="post">
<input type="hidden" name="next" value="{{ next_url }}">
<label>Password<input type="password" name="password" required autofocus autocomplete="current-password"></label>
<button type="submit">Sign in</button>
</form>
"""

def render(template, **ctx):
    return render_template_string(BASE, body=render_template_string(template, **ctx))

PUBLIC_ENDPOINTS = {"login", "logout", "healthz", "manifest", "icon", "sw", "static"}

def safe_next(target):
    # Only allow same-site relative paths to prevent open redirects.
    if target and target.startswith("/") and not target.startswith("//") and "\\" not in target:
        return target
    return "/"

@app.before_request
def require_login():
    if request.endpoint is None or request.endpoint in PUBLIC_ENDPOINTS:
        return None
    if not session.get("authenticated"):
        return redirect(url_for("login", next=request.path))
    return None

@app.route("/login", methods=["GET", "POST"])
def login():
    next_url = safe_next(request.values.get("next", ""))
    if request.method == "POST":
        expected = os.environ.get("APP_PASSWORD", "")
        submitted = request.form.get("password", "")
        # If APP_PASSWORD is unset or empty, login always fails.
        if expected and hmac.compare_digest(submitted.encode(), expected.encode()):
            session.clear()
            session.permanent = True
            session["authenticated"] = True
            return redirect(next_url)
        flash("Incorrect password.")
    return render(LOGIN, next_url=next_url)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/")
def index():
    pos = PurchaseOrder.query.order_by(PurchaseOrder.id.desc()).all()
    total = sum((po.amount for po in pos), Decimal("0"))
    return render(INDEX, pos=pos, total=total, count=len(pos))

@app.route("/new", methods=["GET", "POST"])
def new_po():
    if request.method == "POST":
        vendor = request.form.get("vendor", "").strip()
        description = request.form.get("description", "").strip()
        try:
            amount = Decimal(request.form.get("amount", "").strip()).quantize(Decimal("0.01"))
        except (InvalidOperation, ValueError):
            amount = None
        if not vendor:
            flash("Vendor is required.")
        elif amount is None or amount <= 0:
            flash("Enter a valid amount greater than zero.")
        else:
            po = PurchaseOrder(vendor=vendor, description=description, amount=amount)
            db.session.add(po)
            db.session.commit()
            flash(f"Created PO-{po.id}.")
            return redirect(url_for("index"))
    return render(FORM)

@app.route("/manifest.webmanifest")
def manifest():
    data = {
        "name": "PO Tracker",
        "short_name": "POs",
        "start_url": "/",
        "display": "standalone",
        "background_color": "#ffffff",
        "theme_color": "#1f6feb",
        "icons": [
            {"src": url_for("icon"), "sizes": "any", "type": "image/svg+xml"},
        ],
    }
    return Response(json.dumps(data), mimetype="application/manifest+json")

ICON_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">'
    '<rect width="512" height="512" rx="96" fill="#1f6feb"/>'
    '<text x="256" y="340" font-family="sans-serif" font-size="240" '
    'font-weight="bold" text-anchor="middle" fill="#fff">PO</text></svg>'
)

@app.route("/icon.svg")
def icon():
    return Response(ICON_SVG, mimetype="image/svg+xml")

SW_JS = """
self.addEventListener('install', function (event) { self.skipWaiting(); });
self.addEventListener('activate', function (event) { event.waitUntil(self.clients.claim()); });
self.addEventListener('fetch', function (event) { event.respondWith(fetch(event.request)); });
"""

@app.route("/sw.js")
def sw():
    return Response(SW_JS, mimetype="application/javascript")

@app.route("/healthz")
def healthz():
    return "ok", 200
