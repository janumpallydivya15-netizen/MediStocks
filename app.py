# MUST BE FIRST
import os
os.environ["AWS_DEFAULT_REGION"] = "ap-south-1"

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import boto3
from decimal import Decimal
from boto3.dynamodb.conditions import Attr
from datetime import datetime, timedelta
from functools import wraps
import logging
import uuid
from dotenv import load_dotenv

# =================================================
# LOAD ENV
# =================================================
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev_secret")

AWS_REGION = "ap-south-1"

MEDICINES_TABLE = os.getenv("DYNAMODB_TABLE_MEDICINES", "MediStock_Medicines")
USERS_TABLE = os.getenv("DYNAMODB_TABLE_USERS", "MediStock_Users")

# ================= SNS CONFIG (FIXED) =================
SNS_TOPIC_ARN = "arn:aws:sns:ap-south-1:120121146931:MediStockAlerts"

sns_client = boto3.client(
    "sns",
    region_name=AWS_REGION
)

# ================= DYNAMODB =================
dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
medicines_table = dynamodb.Table(MEDICINES_TABLE)
users_table = dynamodb.Table(USERS_TABLE)

# ================= LOGGING =================
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


# ================= EMAIL FUNCTION (ADD HERE) =================
def send_low_stock_email(message):
    response = sns_client.publish(
        TopicArn=SNS_TOPIC_ARN,
        Message=message,
        Subject="⚠️ Low Medicine Stock Alert"
    )
    logger.info(f"SNS sent: {response['MessageId']}")

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
def dashboard():
    response = medicines_table.scan()
    medicines = response.get("Items", [])

    total_medicines = len(medicines)
    total_value = 0
    low_stock = 0
    expired = 0

    today = datetime.today().date()

    for med in medicines:
        qty = int(med.get("quantity", 0))
        price = float(med.get("price", 0))
        total_value += qty * price

        if qty < 10:
            low_stock += 1

        expiry_str = med.get("expiry_date")
        if expiry_str:
            expiry_date = datetime.strptime(expiry_str, "%Y-%m-%d").date()
            if expiry_date < today:
                expired += 1

    # 👇 THIS is what your template expects
    stats = {
        "total_medicines": total_medicines,
        "total_value": round(total_value, 2),
        "low_stock": low_stock,
        "expired": expired
    }

    print("STATS DEBUG:", stats)  # temporary debug

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
def get_medicine_by_id(med_id):
    response = medicines_table.get_item(
        Key={
            'medicine_id': med_id
        }
    )
    return response.get('Item')

@app.route("/edit_medicine/<medicine_id>", methods=["POST"])
def edit_medicine(medicine_id):
    medicine_name = request.form.get("medicine_name")
    quantity = request.form.get("quantity")

    if not medicine_name or not quantity:
        flash("Medicine name and quantity are required", "danger")
        return redirect(url_for("dashboard"))

    medicines_table.update_item(
        Key={"medicine_id": medicine_id},
        UpdateExpression="SET #n = :name, quantity = :qty",
        ExpressionAttributeNames={
            "#n": "name"
        },
        ExpressionAttributeValues={
            ":name": medicine_name,
            ":qty": int(quantity)
        }
    )

    flash("Medicine updated successfully", "success")
    return redirect(url_for("dashboard"))

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
    app.run(host="0.0.0.0", port=5000, debug=True)



