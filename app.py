from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from functools import wraps
import boto3
from boto3.dynamodb.conditions import Attr
from decimal import Decimal
from datetime import datetime, timedelta
import uuid
import os

# --------------------------------------------------
# Flask App Setup
# --------------------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "medistocks_secret_key")

# --------------------------------------------------
# AWS Configuration (EC2 IAM Role)
# --------------------------------------------------
AWS_REGION = "ap-south-1"

dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
sns_client = boto3.client("sns", region_name=AWS_REGION)

# --------------------------------------------------
# DynamoDB Table Names
# --------------------------------------------------
MEDICINE_TABLE = "MediStock_Medicines"
USERS_TABLE = "MediStock_Users"
ALERT_LOGS_TABLE = "MediStock_AlertLogs"

# --------------------------------------------------
# SNS Topic ARN
# --------------------------------------------------
SNS_TOPIC_ARN = os.environ.get(
    "SNS_TOPIC_ARN",
    "arn:aws:sns:ap-south-1:120121146931:MediStockAlerts"
)

# --------------------------------------------------
# Utility Functions
# --------------------------------------------------
def decimal_to_float(obj):
    if isinstance(obj, Decimal):
        return float(obj)
    if isinstance(obj, dict):
        return {k: decimal_to_float(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [decimal_to_float(i) for i in obj]
    return obj


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please login first", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


# --------------------------------------------------
# Initialize DynamoDB Tables
# --------------------------------------------------
def init_tables():
    client = dynamodb.meta.client

    def create_table(name, key):
        try:
            dynamodb.create_table(
                TableName=name,
                KeySchema=[{"AttributeName": key, "KeyType": "HASH"}],
                AttributeDefinitions=[{"AttributeName": key, "AttributeType": "S"}],
                BillingMode="PAY_PER_REQUEST"
            ).wait_until_exists()
            print(f"Created table: {name}")
        except client.exceptions.ResourceInUseException:
            print(f"Table already exists: {name}")

    create_table(MEDICINE_TABLE, "medicine_id")
    create_table(USERS_TABLE, "user_id")
    create_table(ALERT_LOGS_TABLE, "alert_id")


# --------------------------------------------------
# SNS Alert Logic
# --------------------------------------------------
def send_stock_alert(medicine, current_qty, threshold):
    message = (
        f"⚠️ MEDISTOCK LOW STOCK ALERT\n\n"
        f"Medicine: {medicine['medicine_name']}\n"
        f"Current Stock: {current_qty}\n"
        f"Threshold: {threshold}\n"
        f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )

    sns_client.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject="MediStock Low Inventory Alert",
        Message=message
    )

    log_alert(medicine, current_qty, threshold)


def log_alert(medicine, current_qty, threshold):
    table = dynamodb.Table(ALERT_LOGS_TABLE)
    table.put_item(Item={
        "alert_id": str(uuid.uuid4()),
        "medicine_id": medicine["medicine_id"],
        "medicine_name": medicine["medicine_name"],
        "current_stock": Decimal(str(current_qty)),
        "threshold": Decimal(str(threshold)),
        "timestamp": datetime.now().isoformat(),
        "status": "SENT"
    })


# --------------------------------------------------
# Routes
# --------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        table = dynamodb.Table(USERS_TABLE)
        res = table.scan(FilterExpression=Attr("username").eq(username))

        if res["Items"] and res["Items"][0]["password"] == password:
            user = res["Items"][0]
            session["user_id"] = user["user_id"]
            session["username"] = user["username"]
            flash("Login successful", "success")
            return redirect(url_for("dashboard"))

        flash("Invalid credentials", "danger")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out", "info")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    table = dynamodb.Table(MEDICINE_TABLE)
    meds = decimal_to_float(table.scan().get("Items", []))

    low_stock = sum(1 for m in meds if m["current_quantity"] <= m["threshold_quantity"])
    expired = sum(1 for m in meds if datetime.fromisoformat(m["expiry_date"]) < datetime.now())

    return render_template(
        "dashboard.html",
        total=len(meds),
        low_stock=low_stock,
        expired=expired,
        username=session.get("username")
    )


@app.route("/inventory")
@login_required
def inventory():
    table = dynamodb.Table(MEDICINE_TABLE)
    medicines = decimal_to_float(table.scan().get("Items", []))
    medicines.sort(key=lambda x: x["medicine_name"])
    return render_template("inventory.html", medicines=medicines)


@app.route("/add_medicine", methods=["GET", "POST"])
@login_required
def add_medicine():
    if request.method == "POST":
        table = dynamodb.Table(MEDICINE_TABLE)

        item = {
            "medicine_id": str(uuid.uuid4()),
            "medicine_name": request.form["medicine_name"],
            "category": request.form["category"],
            "current_quantity": Decimal(request.form["current_quantity"]),
            "threshold_quantity": Decimal(request.form["threshold_quantity"]),
            "expiry_date": request.form["expiry_date"],
            "added_by": session["username"],
            "added_date": datetime.now().isoformat()
        }

        table.put_item(Item=item)
        flash("Medicine added successfully", "success")
        return redirect(url_for("inventory"))

    return render_template("add_medicine.html")


@app.route("/update_stock/<medicine_id>", methods=["POST"])
@login_required
def update_stock(medicine_id):
    table = dynamodb.Table(MEDICINE_TABLE)
    qty = Decimal(request.form["quantity"])

    med = table.get_item(Key={"medicine_id": medicine_id})["Item"]
    new_qty = med["current_quantity"] + qty

    table.update_item(
        Key={"medicine_id": medicine_id},
        UpdateExpression="SET current_quantity=:q",
        ExpressionAttributeValues={":q": new_qty}
    )

    if new_qty <= med["threshold_quantity"]:
        send_stock_alert(med, float(new_qty), float(med["threshold_quantity"]))

    flash("Stock updated", "success")
    return redirect(url_for("inventory"))


@app.route("/alert_logs")
@login_required
def alert_logs():
    table = dynamodb.Table(ALERT_LOGS_TABLE)
    alerts = decimal_to_float(table.scan().get("Items", []))
    alerts.sort(key=lambda x: x["timestamp"], reverse=True)
    return render_template("alert_logs.html", alerts=alerts)


# --------------------------------------------------
# App Start
# --------------------------------------------------
if __name__ == "__main__":
    init_tables()
    app.run(host="0.0.0.0", port=5000, debug=True)
