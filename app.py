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
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")

sns_client = boto3.client("sns", region_name=AWS_REGION)

def send_low_stock_email(medicine_name, quantity):
    if not SNS_TOPIC_ARN:
        print("❌ SNS_TOPIC_ARN is not set")
        return

    message = (
        f"⚠️ LOW STOCK ALERT ⚠️\n\n"
        f"Medicine: {medicine_name}\n"
        f"Remaining Quantity: {quantity}\n\n"
        f"Please restock immediately."
    )

    response = sns_client.publish(
        TopicArn=SNS_TOPIC_ARN,
        Message=message,
        Subject="Low Medicine Stock Alert"
    )

    print("✅ SNS message sent:", response["MessageId"])

MEDICINES_TABLE = os.getenv("DYNAMODB_TABLE_MEDICINES", "MediStock_Medicines")
USERS_TABLE = os.getenv("DYNAMODB_TABLE_USERS", "MediStock_Users")

# ================= SNS CONFIG (FIXED) =================
SNS_TOPIC_ARN = "arn:aws:sns:ap-south-1:120121146931:MediStockAlerts"

sns_client = boto3.client(
    "sns",
    region_name=AWS_REGION
)

# ================= DYNAMODB =================
# ================= DYNAMODB SETUP =================
dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)

medicines_table = dynamodb.Table(MEDICINES_TABLE)
users_table = dynamodb.Table(USERS_TABLE)

# ================= LOGGING =================
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# =================================================
# GLOBAL SAFETY NET (NO stats ERROR EVER)
# =================================================
@app.route("/stats")
def stats():
    low_stock = get_low_stock()
    expired = get_expired_medicines()

    stats = {
        "low_stock": low_stock,
        "expired": expired
    }

    return jsonify(stats)


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
def send_low_stock_alert(medicine_name, quantity):
    message = (
        f"⚠️ LOW STOCK ALERT\n\n"
        f"Medicine: {medicine_name}\n"
        f"Available Quantity: {quantity}\n\n"
        f"Please restock immediately."
    )

    sns_client.publish(
        TopicArn=SNS_TOPIC_ARN,
        Message=message,
        Subject="⚠️ Low Medicine Stock Alert"
    )

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
    low_stock = 0
    expired = 0

    today = datetime.today().date()

    # Calculate total value
    total_value = sum(
        int(item.get("quantity", 0)) * float(item.get("price", 0))
        for item in medicines
    )

    # Stats dictionary for template
    stats = {
        "total_medicines": total_medicines,
        "total_value": round(total_value, 2),
        "low_stock": low_stock,
        "expired": expired
    }

    print("STATS DEBUG:", stats)

    return render_template("dashboard.html", stats=stats)
@app.route("/update_stock", methods=["POST"])
def update_stock():
    data = request.json

    med_id = data.get("id")
    qty = int(data.get("quantity", 0))

    med = get_medicine_by_id(med_id)
    if not med:
        return jsonify({"error": "Medicine not found"}), 404

    expiry_str = med.get("expiry_date")

    # Low stock alert
    if qty < 10:
        send_low_stock_email(med)

    # Expiry alert
    if expiry_str:
        expiry_date = datetime.strptime(expiry_str, "%Y-%m-%d").date()
        if expiry_date <= date.today() + timedelta(days=30):
            send_expiry_alert_email(med)

    return jsonify({"status": "updated"})

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


import uuid
from decimal import Decimal

from decimal import Decimal
import uuid

@app.route("/add_medicine", methods=["GET", "POST"])
def add_medicine():
    if request.method == "POST":
        data = request.form

        medicine = {
            "medicine_id": str(uuid.uuid4()),  # ✅ MUST MATCH TABLE KEY
            "name": data.get("name"),
            "quantity": int(data.get("quantity", 0)),
            "price": Decimal(data.get("price", "0")),
            "expiry_date": data.get("expiry_date")
        }

        medicines_table.put_item(Item=medicine)

        return redirect(url_for("medicines"))

    return render_template("add_medicine.html")
from decimal import Decimal

@app.route('/edit_medicine/<medicine_id>', methods=['GET', 'POST'])
@login_required
def edit_medicine(medicine_id):

    if request.method == 'POST':
        medicine_name = request.form.get('medicine_name')
        quantity = int(request.form.get('quantity', 0))
        price = Decimal(request.form.get('price', '0'))
        threshold = int(request.form.get('threshold', 0))

        medicines_table.update_item(
            Key={
                'medicine_id': medicine_id   # ✅ MUST be primary key
            },
            UpdateExpression="""
                SET medicine_name = :name,
                    quantity = :qty,
                    price = :price,
                    threshold = :th
            """,
            ExpressionAttributeValues={
                ':name': medicine_name,
                ':qty': quantity,
                ':price': price,
                ':th': threshold
            }
        )

        # 🔔 Low stock email
        if quantity <= threshold:
            message = f"{medicine_name} stock is low ({quantity})"
            send_low_stock_email(session['email'], message)

        flash("Medicine updated successfully")
        return redirect(url_for('medicines'))

    # GET request – load existing data
    response = medicines_table.get_item(
        Key={'medicine_id': medicine_id}
    )

    medicine = response.get('Item')
    return render_template('edit_medicine.html', medicine=medicine)

    # ---------- GET REQUEST ----------
    response = medicines_table.get_item(
        Key={"medicine_id": medicine_id}
    )

    medicine = response.get("Item")

    if not medicine:
        flash("Medicine not found", "danger")
        return redirect(url_for("medicines"))

    return render_template("edit_medicine.html", medicine=medicine)

@app.route("/delete_medicine/<medicine_id>")
def delete_medicine(medicine_id):
    medicines_table.delete_item(
        Key={"medicine_id": medicine_id}
    )
    return redirect(url_for("medicines"))

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



