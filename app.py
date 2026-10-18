import os
from decimal import Decimal, InvalidOperation
from flask import Flask, request, redirect, url_for, render_template_string, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-change-me")
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
<style>body{font-family:sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem}
table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #ddd;padding:.4rem;text-align:left}
.flash{color:#b00}.total{font-size:1.4rem;font-weight:bold}input,textarea{width:100%;padding:.4rem;margin:.2rem 0 .8rem}
button,a.btn{padding:.5rem 1rem;text-decoration:none}</style></head><body>
<h1>PO Tracker</h1>
<p><a class="btn" href="{{ url_for('index') }}">Dashboard</a> <a class="btn" href="{{ url_for('new_po') }}">New PO</a></p>
{% for m in get_flashed_messages() %}<p class="flash">{{ m }}</p>{% endfor %}
{{ body|safe }}
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

def render(template, **ctx):
    return render_template_string(BASE, body=render_template_string(template, **ctx))

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

@app.route("/healthz")
def healthz():
    return "ok", 200
