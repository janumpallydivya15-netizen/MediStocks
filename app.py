from flask import Flask, request, session, redirect, url_for, render_template, flash
import boto3
from boto3.dynamodb.conditions import Attr
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
import os
import uuid
from dotenv import load_dotenv
from functools import wraps

# =================================================
# ENV + APP SETUP
# =================================================
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev_secret")

AWS_REGION = os.getenv("AWS_REGION", "ap-south-1")
MEDICINES_TABLE = os.getenv("DYNAMODB_TABLE_MEDICINES", "MediStock_Medicines")
USERS_TABLE = os.getenv("DYNAMODB_TABLE_USERS", "MediStock_Users")

SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SENDER_EMAIL = os.getenv("SENDER_EMAIL")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")

dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
medicines_table = dynamodb.Table(MEDICINES_TABLE)
users_table = dynamodb.Table(USERS_TABLE)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# =================================================
# GLOBAL SAFETY NET (NO stats ERROR EVER)
# =================================================
@app.context_processor
def inject_stats():
    """
    Global safety net so `stats` is NEVER undefined in templates
    """
    return {
        "stats": {
            "total_medicines": 0,
            "total_value": 0,
            "low_stock": 0,
            "expired": 0
        }
    }


# =================================================
# HELPERS
# =================================================
def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrap


def send_low_stock_email(name, qty, threshold, to_email):
    if not SENDER_EMAIL or not SENDER_PASSWORD:
        return

    msg = MIMEMultipart()
    msg["From"] = SENDER_EMAIL
    msg["To"] = to_email
    msg["Subject"] = f"LOW STOCK ALERT: {name}"

    body = f"""
Medicine: {name}
Current Stock: {qty}
Threshold: {threshold}

Please restock immediately.
"""
    msg.attach(MIMEText(body, "plain"))

    server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
    server.starttls()
    server.login(SENDER_EMAIL, SENDER_PASSWORD)
    server.send_message(msg)
    server.quit()

# =================================================
# AUTH ROUTES
# =================================================
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        res = users_table.scan(FilterExpression=Attr("email").eq(email))
        users = res.get("Items", [])

        if not users or not check_password_hash(users[0]["password"], password):
            flash("Invalid login", "danger")
            return render_template("login.html")

        user = users[0]
        session["user_id"] = user["user_id"]
        session["email"] = user["email"]

        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        uid = str(uuid.uuid4())
        users_table.put_item(
            Item={
                "user_id": uid,
                "email": request.form["email"],
                "password": generate_password_hash(request.form["password"]),
                "created_at": datetime.now().isoformat()
            }
        )
        flash("Account created. Please login.", "success")
        return redirect(url_for("login"))

    return render_template("signup.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# =================================================
# DASHBOARD
# =================================================
@app.route("/dashboard")
@login_required
def dashboard():
    stats = {
        "total_medicines": 0,
        "low_stock": 0,
        "expired": 0,
        "total_value": 0
    }

    res = medicines_table.scan(
        FilterExpression=Attr("user_id").eq(session["user_id"])
    )
    medicines = res.get("Items", [])

    today = datetime.now().date()

    for m in medicines:
        stats["total_medicines"] += 1

        qty = int(m.get("quantity", 0))
        threshold = int(m.get("threshold", 0))

        if qty <= threshold:
            stats["low_stock"] += 1

        exp = m.get("expiration_date")
        if exp and datetime.strptime(exp, "%Y-%m-%d").date() < today:
            stats["expired"] += 1

    return render_template("dashboard.html", stats=stats)

# =================================================
# MEDICINES
# =================================================
@app.route("/medicines")
@login_required
def medicines():
    res = medicines_table.scan(
        FilterExpression=Attr("user_id").eq(session["user_id"])
    )
    return render_template("medicines.html", medicines=res.get("Items", []))


@app.route("/medicines/add", methods=["GET", "POST"])
@login_required
def add_medicine():
    if request.method == "POST":
        qty = int(request.form["quantity"])
        threshold = int(request.form["threshold"])

        medicines_table.put_item(
            Item={
                "medicine_id": str(uuid.uuid4()),
                "user_id": session["user_id"],
                "name": request.form["name"],
                "category": request.form["category"],
                "quantity": qty,
                "threshold": threshold,
                "expiration_date": request.form["expiration_date"],
                "created_at": datetime.now().isoformat()
            }
        )

        if qty <= threshold:
            send_low_stock_email(
                request.form["name"],
                qty,
                threshold,
                session["email"]
            )

        flash("Medicine added successfully", "success")
        return redirect(url_for("medicines"))

    return render_template("add_medicine.html")


@app.route("/medicines/edit/<medicine_id>", methods=["GET", "POST"])
@login_required
def edit_medicine(medicine_id):
    res = medicines_table.get_item(Key={"medicine_id": medicine_id})
    medicine = res.get("Item")

    if not medicine or medicine["user_id"] != session["user_id"]:
        flash("Unauthorized", "danger")
        return redirect(url_for("medicines"))

    if request.method == "POST":
        qty = int(request.form["quantity"])
        threshold = int(request.form["threshold"])

        medicines_table.update_item(
            Key={"medicine_id": medicine_id},
            UpdateExpression="""
                SET #n=:n, category=:c, quantity=:q,
                    threshold=:t, expiration_date=:e
            """,
            ExpressionAttributeNames={"#n": "name"},
            ExpressionAttributeValues={
                ":n": request.form["name"],
                ":c": request.form["category"],
                ":q": qty,
                ":t": threshold,
                ":e": request.form["expiration_date"]
            }
        )

        if qty <= threshold:
            send_low_stock_email(
                request.form["name"],
                qty,
                threshold,
                session["email"]
            )

        flash("Medicine updated successfully", "success")
        return redirect(url_for("medicines"))

    return render_template("edit_medicine.html", medicine=medicine)
# =================================================
# ALERTS PAGE
# =================================================
@app.route("/alerts")
@login_required
def alerts():
    try:
        res = medicines_table.scan(
            FilterExpression=Attr("user_id").eq(session["user_id"])
        )
        medicines = res.get("Items", [])

        low_stock = []
        expiring_soon = []
        today = datetime.now().date()

        for m in medicines:
            qty = int(m.get("quantity", 0))
            threshold = int(m.get("threshold", 0))

            # Low stock
            if qty <= threshold:
                low_stock.append(m)

            # Expiring within 30 days
            expiry = m.get("expiration_date")
            if expiry:
                try:
                    exp_date = datetime.strptime(expiry, "%Y-%m-%d").date()
                    days_left = (exp_date - today).days
                    if 0 <= days_left <= 30:
                        m["days_remaining"] = days_left
                        expiring_soon.append(m)
                except ValueError:
                    pass

        expiring_soon.sort(key=lambda x: x.get("days_remaining", 999))

        return render_template(
            "alerts.html",
            low_stock=low_stock,
            expiring_soon=expiring_soon
        )

    except Exception as e:
        logger.error(f"Alerts error: {e}")
        flash("Unable to load alerts", "danger")
        return render_template("alerts.html", low_stock=[], expiring_soon=[])
# =================================================
# REPORTS PAGE
# =================================================
@app.route("/reports")
@login_required
def reports():
    res = medicines_table.scan(
        FilterExpression=Attr("user_id").eq(session["user_id"])
    )
    medicines = res.get("Items", [])

    total_medicines = len(medicines)
    low_stock = sum(
        1 for m in medicines
        if int(m.get("quantity", 0)) <= int(m.get("threshold", 0))
    )
    out_of_stock = sum(
        1 for m in medicines
        if int(m.get("quantity", 0)) == 0
    )

    return render_template(
        "reports.html",
        medicines=medicines,
        total_medicines=total_medicines,
        low_stock=low_stock,
        out_of_stock=out_of_stock
    )

# RUN
# =================================================
if __name__ == "__main__":
    app.run(debug=True)
