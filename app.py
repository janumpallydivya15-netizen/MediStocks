from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from functools import wraps
import boto3
from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError
from decimal import Decimal
from datetime import datetime, timedelta
import uuid
import os
import hashlib

# --------------------------------------------------
# Flask App Setup
# --------------------------------------------------
app = Flask(__name__)
app.secret_key = "medistock-secret-key"
app.secret_key = os.environ.get("SECRET_KEY", "medistocks_secret_key_change_in_production")

# --------------------------------------------------
# AWS Configuration (EC2 IAM Role)
# --------------------------------------------------
AWS_REGION = "ap-south-1"

dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
sns_client = boto3.client("sns", region_name=AWS_REGION)

# ---------- DynamoDB Table Names ----------
MEDICINES_TABLE = "MediStock_Medicines"
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
    """Convert DynamoDB Decimal types to float for JSON serialization"""
    if isinstance(obj, Decimal):
        return float(obj)
    if isinstance(obj, dict):
        return {k: decimal_to_float(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [decimal_to_float(i) for i in obj]
    return obj


def hash_password(password):
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()


def login_required(f):
    """Decorator to protect routes that require authentication"""
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
    """Create DynamoDB tables if they don't exist"""
    client = dynamodb.meta.client

    def create_table(name, key):
        try:
            dynamodb.create_table(
                TableName=name,
                KeySchema=[{"AttributeName": key, "KeyType": "HASH"}],
                AttributeDefinitions=[{"AttributeName": key, "AttributeType": "S"}],
                BillingMode="PAY_PER_REQUEST"
            ).wait_until_exists()
            print(f"✓ Created table: {name}")
        except client.exceptions.ResourceInUseException:
            print(f"✓ Table already exists: {name}")
        except Exception as e:
            print(f"✗ Error creating table {name}: {str(e)}")

    create_table(MEDICINES_TABLE, "medicine_id")
    create_table(USERS_TABLE, "user_id")
    create_table(ALERT_LOGS_TABLE, "alert_id")


def init_default_user():
    """Create default admin user if no users exist"""
    try:
        table = dynamodb.Table(USERS_TABLE)
        response = table.scan(Limit=1)
        
        if not response.get("Items"):
            table.put_item(Item={
                "user_id": str(uuid.uuid4()),
                "username": "admin",
                "password": hash_password("admin123"),
                "email": "admin@medistock.com",
                "role": "admin",
                "created_date": datetime.now().isoformat()
            })
            print("✓ Default admin user created (username: admin, password: admin123)")
    except Exception as e:
        print(f"✗ Error creating default user: {str(e)}")


# --------------------------------------------------
# SNS Alert Logic
# --------------------------------------------------
def send_stock_alert(medicine, current_qty, threshold):
    """Send low stock alert via SNS and log the alert"""
    try:
        message = (
            f"⚠️ MEDISTOCK LOW STOCK ALERT\n\n"
            f"Medicine: {medicine['medicine_name']}\n"
            f"Category: {medicine.get('category', 'N/A')}\n"
            f"Current Stock: {current_qty}\n"
            f"Threshold: {threshold}\n"
            f"Action Required: Please restock immediately\n"
            f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )

        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject="MediStock Low Inventory Alert",
            Message=message
        )

        log_alert(medicine, current_qty, threshold)
        print(f"✓ Alert sent for {medicine['medicine_name']}")
    except Exception as e:
        print(f"✗ Error sending alert: {str(e)}")


def log_alert(medicine, current_qty, threshold):
    """Log alert to DynamoDB"""
    try:
        table = dynamodb.Table(ALERT_LOGS_TABLE)
        table.put_item(Item={
            "alert_id": str(uuid.uuid4()),
            "medicine_id": medicine["medicine_id"],
            "medicine_name": medicine["medicine_name"],
            "category": medicine.get("category", "N/A"),
            "current_stock": Decimal(str(current_qty)),
            "threshold": Decimal(str(threshold)),
            "timestamp": datetime.now().isoformat(),
            "status": "SENT",
            "severity": "HIGH" if current_qty == 0 else "MEDIUM"
        })
    except Exception as e:
        print(f"✗ Error logging alert: {str(e)}")
def create_table(table_name, primary_key):
    try:
        table = dynamodb.Table(table_name)
        table.load()
        print(f"Table already exists: {table_name}")
        return
    except Exception:
        pass

    print(f"Creating table: {table_name}")

    table = dynamodb.create_table(
        TableName=table_name,
        KeySchema=[
            {"AttributeName": primary_key, "KeyType": "HASH"}
        ],
        AttributeDefinitions=[
            {"AttributeName": primary_key, "AttributeType": "S"}
        ],
        BillingMode="PAY_PER_REQUEST"
    )

    table.wait_until_exists()

MEDICINES_TABLE = "MediStock_Medicines"

def get_all_medicines():
    table = dynamodb.Table(MEDICINES_TABLE)
    response = table.scan()
    items = response.get("Items", [])

    # Handle DynamoDB pagination
    while "LastEvaluatedKey" in response:
        response = table.scan(
            ExclusiveStartKey=response["LastEvaluatedKey"]
        )
        items.extend(response.get("Items", []))

    return items

# --------------------------------------------------
# Routes - Authentication
# --------------------------------------------------
@app.route("/")
def index():
    """Landing page"""
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        table = dynamodb.Table(USERS_TABLE)

        response = table.scan(
            FilterExpression="email = :e",
            ExpressionAttributeValues={":e": email}
        )

        users = response.get("Items", [])

        if users:
            user = users[0]

            if user.get("password") == password:  # (plain text for now)
                # ✅ SET SESSION
                session["user_id"] = user["user_id"]
                session["email"] = user["email"]

                # ✅ REDIRECT TO DASHBOARD
                return redirect(url_for("dashboard"))

        # ❌ Login failed
        return render_template(
            "login.html",
            error="Invalid email or password"
        )

    return render_template("login.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    """User registration"""
    if "user_id" in session:
        return redirect(url_for("dashboard"))
        
    if request.method == "POST":
        try:
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            email = request.form.get("email", "").strip()

            if not all([username, password, email]):
                flash("All fields are required", "danger")
                return render_template("signup.html")

            # Check if username already exists
            table = dynamodb.Table(USERS_TABLE)
            res = table.scan(FilterExpression=Attr("username").eq(username))

            if res["Items"]:
                flash("Username already exists", "danger")
                return render_template("signup.html")

            # Create new user
            table.put_item(Item={
                "user_id": str(uuid.uuid4()),
                "username": username,
                "password": hash_password(password),
                "email": email,
                "role": "user",
                "created_date": datetime.now().isoformat()
            })

            flash("Account created successfully! Please login.", "success")
            return redirect(url_for("login"))

        except Exception as e:
            flash(f"Registration error: {str(e)}", "danger")

    return render_template("signup.html")


@app.route("/logout")
def logout():
    """User logout"""
    username = session.get("username", "User")
    session.clear()
    flash(f"Goodbye, {username}!", "info")
    return redirect(url_for("login"))


# --------------------------------------------------
# Routes - Dashboard
# --------------------------------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    meds = get_all_medicines()

    total_medicines = len(meds)
    total_value = 0.0
    low_stock = 0
    expired = 0

    today = datetime.today().date()

    for m in meds:
        try:
            qty = int(m.get("current_quantity", 0))
        except:
            qty = 0

        try:
            threshold = int(m.get("threshold_quantity", 0))
        except:
            threshold = 0

        try:
            price = float(m.get("price", 0))
        except:
            price = 0.0

        # TOTAL VALUE (shared across all users)
        total_value += qty * price

        # LOW STOCK
        if qty <= threshold:
            low_stock += 1

        # EXPIRED
        expiry = m.get("expiry_date")
        if expiry:
            try:
                expiry_date = datetime.strptime(expiry, "%Y-%m-%d").date()
                if expiry_date < today:
                    expired += 1
            except:
                pass

    stats = {
        "total_medicines": total_medicines,
        "total_value": round(total_value, 2),
        "low_stock": low_stock,
        "expired": expired
    }

    return render_template(
        "dashboard.html",
        stats=stats,
        meds=meds
    )

# --------------------------------------------------
# Routes - Medicines/Inventory
# --------------------------------------------------
@app.route("/medicines")
@login_required
def medicines():
    """View all medicines in inventory (same as inventory)"""
    return redirect(url_for("inventory"))


@app.route("/inventory")
@login_required
def inventory():
    """View all medicines in inventory"""
    try:
        table = dynamodb.Table(MEDICINE_TABLE)
        medicines = decimal_to_float(table.scan().get("Items", []))
        medicines.sort(key=lambda x: x.get("medicine_name", ""))
        
        # Add status to each medicine
        today = datetime.now()
        for med in medicines:
            # Stock status
            if med["current_quantity"] == 0:
                med["stock_status"] = "Out of Stock"
                med["stock_class"] = "danger"
            elif med["current_quantity"] <= med["threshold_quantity"]:
                med["stock_status"] = "Low Stock"
                med["stock_class"] = "warning"
            else:
                med["stock_status"] = "In Stock"
                med["stock_class"] = "success"
            
            # Expiry status
            try:
                exp_date = datetime.fromisoformat(med["expiry_date"])
                if exp_date < today:
                    med["expiry_status"] = "Expired"
                    med["expiry_class"] = "danger"
                elif exp_date < today + timedelta(days=30):
                    med["expiry_status"] = "Expiring Soon"
                    med["expiry_class"] = "warning"
                else:
                    med["expiry_status"] = "Valid"
                    med["expiry_class"] = "success"
            except:
                med["expiry_status"] = "Unknown"
                med["expiry_class"] = "secondary"
        
        return render_template("medicines.html", medicines=medicines, username=session.get("username"))
    except Exception as e:
        flash(f"Error loading inventory: {str(e)}", "danger")
        return render_template("medicines.html", medicines=[], username=session.get("username"))


import uuid
from flask import request, redirect, url_for, render_template
from datetime import datetime

@app.route("/add_medicine", methods=["GET", "POST"])
@login_required
def add_medicine():
    if request.method == "POST":
        table = dynamodb.Table(MEDICINES_TABLE)

        qty = request.form.get("current_quantity", "0")
        threshold = request.form.get("threshold_quantity", "0")
        price = request.form.get("price", "0")

        item = {
            "medicine_id": str(uuid.uuid4()),
            "medicine_name": request.form.get("medicine_name", "").strip(),

            # FORCE VALID NUMERIC VALUES
            "current_quantity": str(int(qty) if qty else 0),
            "threshold_quantity": str(int(threshold) if threshold else 0),
            "price": str(float(price) if price else 0),
        }

        expiry_date = request.form.get("expiry_date")
        if expiry_date:
            item["expiry_date"] = expiry_date  # YYYY-MM-DD

        table.put_item(Item=item)

        return redirect(url_for("dashboard"))

    return render_template("add_medicine.html")

@app.route("/edit_medicine/<medicine_id>", methods=["GET", "POST"])
@login_required
def edit_medicine(medicine_id):
    """Edit existing medicine details"""
    try:
        table = dynamodb.Table(MEDICINE_TABLE)
        
        if request.method == "POST":
            # Update medicine
            medicine_name = request.form.get("medicine_name", "").strip()
            category = request.form.get("category", "").strip()
            current_quantity = request.form.get("current_quantity", "0")
            threshold_quantity = request.form.get("threshold_quantity", "0")
            expiry_date = request.form.get("expiry_date", "")
            batch_number = request.form.get("batch_number", "").strip()
            manufacturer = request.form.get("manufacturer", "").strip()
            unit_price = request.form.get("unit_price", "0")

            if not all([medicine_name, category, expiry_date]):
                flash("Medicine name, category, and expiry date are required", "danger")
                return redirect(url_for("edit_medicine", medicine_id=medicine_id))

            table.update_item(
                Key={"medicine_id": medicine_id},
                UpdateExpression="""SET medicine_name = :name, category = :cat, 
                                   current_quantity = :curr, threshold_quantity = :thresh,
                                   expiry_date = :exp, batch_number = :batch,
                                   manufacturer = :mfr, unit_price = :price""",
                ExpressionAttributeValues={
                    ":name": medicine_name,
                    ":cat": category,
                    ":curr": Decimal(current_quantity),
                    ":thresh": Decimal(threshold_quantity),
                    ":exp": expiry_date,
                    ":batch": batch_number if batch_number else "N/A",
                    ":mfr": manufacturer if manufacturer else "N/A",
                    ":price": Decimal(unit_price) if unit_price else Decimal("0")
                }
            )

            flash(f"Medicine '{medicine_name}' updated successfully", "success")
            return redirect(url_for("inventory"))
        
        # GET request - fetch medicine details
        response = table.get_item(Key={"medicine_id": medicine_id})
        
        if "Item" not in response:
            flash("Medicine not found", "danger")
            return redirect(url_for("inventory"))
        
        medicine = decimal_to_float(response["Item"])
        return render_template("edit_medicine.html", medicine=medicine)
        
    except Exception as e:
        flash(f"Error editing medicine: {str(e)}", "danger")
        return redirect(url_for("inventory"))


@app.route("/update_stock/<medicine_id>", methods=["POST"])
@login_required
def update_stock(medicine_id):
    """Update stock quantity for a medicine"""
    try:
        table = dynamodb.Table(MEDICINE_TABLE)
        qty_change = Decimal(request.form.get("quantity", "0"))
        action = request.form.get("action", "add")  # add or subtract

        # Get current medicine details
        response = table.get_item(Key={"medicine_id": medicine_id})
        
        if "Item" not in response:
            flash("Medicine not found", "danger")
            return redirect(url_for("inventory"))

        med = response["Item"]
        
        if action == "subtract":
            new_qty = med["current_quantity"] - abs(qty_change)
        else:
            new_qty = med["current_quantity"] + abs(qty_change)

        # Prevent negative stock
        if new_qty < 0:
            flash("Stock cannot be negative", "danger")
            return redirect(url_for("inventory"))

        # Update stock
        table.update_item(
            Key={"medicine_id": medicine_id},
            UpdateExpression="SET current_quantity = :q",
            ExpressionAttributeValues={":q": new_qty}
        )

        # Check if alert needs to be sent
        if new_qty <= med["threshold_quantity"]:
            send_stock_alert(med, float(new_qty), float(med["threshold_quantity"]))
            flash(f"Stock updated. Low stock alert sent for {med['medicine_name']}", "warning")
        else:
            flash("Stock updated successfully", "success")

    except ValueError:
        flash("Invalid quantity value", "danger")
    except Exception as e:
        flash(f"Error updating stock: {str(e)}", "danger")

    return redirect(url_for("inventory"))


@app.route("/delete_medicine/<medicine_id>", methods=["POST"])
@login_required
def delete_medicine(medicine_id):
    """Delete a medicine from inventory"""
    try:
        table = dynamodb.Table(MEDICINE_TABLE)
        
        # Get medicine name before deleting
        response = table.get_item(Key={"medicine_id": medicine_id})
        medicine_name = response.get("Item", {}).get("medicine_name", "Medicine")
        
        table.delete_item(Key={"medicine_id": medicine_id})
        flash(f"{medicine_name} deleted successfully", "success")
    except Exception as e:
        flash(f"Error deleting medicine: {str(e)}", "danger")
    
    return redirect(url_for("inventory"))


# --------------------------------------------------
# Routes - Alerts
# --------------------------------------------------
@app.route("/alerts")
@login_required
def alerts():
    """View all alert logs (same as alert_logs)"""
    return redirect(url_for("alert_logs"))


@app.route("/alert_logs")
@login_required
def alert_logs():
    """View all alert logs"""
    try:
        table = dynamodb.Table(ALERT_LOGS_TABLE)
        alerts = decimal_to_float(table.scan().get("Items", []))
        alerts.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        
        # Format timestamps for display
        for alert in alerts:
            try:
                dt = datetime.fromisoformat(alert["timestamp"])
                alert["formatted_time"] = dt.strftime("%Y-%m-%d %H:%M:%S")
            except:
                alert["formatted_time"] = alert.get("timestamp", "Unknown")
        
        return render_template("alerts.html", alerts=alerts, username=session.get("username"))
    except Exception as e:
        flash(f"Error loading alert logs: {str(e)}", "danger")
        return render_template("alerts.html", alerts=[], username=session.get("username"))


# --------------------------------------------------
# Routes - Reports
# --------------------------------------------------
@app.route("/reports")
@login_required
def reports():
    """Generate inventory reports"""
    try:
        table = dynamodb.Table(MEDICINE_TABLE)
        medicines = decimal_to_float(table.scan().get("Items", []))
        
        # Category-wise stock summary
        category_summary = {}
        for med in medicines:
            cat = med.get("category", "Uncategorized")
            if cat not in category_summary:
                category_summary[cat] = {
                    "total_items": 0,
                    "total_quantity": 0,
                    "low_stock_items": 0
                }
            
            category_summary[cat]["total_items"] += 1
            category_summary[cat]["total_quantity"] += med["current_quantity"]
            if med["current_quantity"] <= med["threshold_quantity"]:
                category_summary[cat]["low_stock_items"] += 1
        
        # Expired and expiring medicines
        today = datetime.now()
        expired_medicines = []
        expiring_medicines = []
        
        for med in medicines:
            try:
                exp_date = datetime.fromisoformat(med["expiry_date"])
                if exp_date < today:
                    expired_medicines.append(med)
                elif exp_date < today + timedelta(days=30):
                    expiring_medicines.append(med)
            except:
                pass
        
        # Low stock medicines
        low_stock_medicines = [m for m in medicines if m["current_quantity"] <= m["threshold_quantity"]]
        
        return render_template(
            "reports.html",
            category_summary=category_summary,
            expired_medicines=expired_medicines,
            expiring_medicines=expiring_medicines,
            low_stock_medicines=low_stock_medicines,
            total_medicines=len(medicines),
            username=session.get("username")
        )
    except Exception as e:
        flash(f"Error generating reports: {str(e)}", "danger")
        return render_template("reports.html", category_summary={}, expired_medicines=[], 
                             expiring_medicines=[], low_stock_medicines=[], username=session.get("username"))


# --------------------------------------------------
# API Routes
# --------------------------------------------------
@app.route("/api/stats")
@login_required
def api_stats():
    """API endpoint for dashboard statistics"""
    try:
        table = dynamodb.Table(MEDICINE_TABLE)
        meds = decimal_to_float(table.scan().get("Items", []))

        low_stock = sum(1 for m in meds if m["current_quantity"] <= m["threshold_quantity"])
        out_of_stock = sum(1 for m in meds if m["current_quantity"] == 0)
        
        expired = 0
        expiring_soon = 0
        today = datetime.now()
        
        for m in meds:
            try:
                exp_date = datetime.fromisoformat(m["expiry_date"])
                if exp_date < today:
                    expired += 1
                elif exp_date < today + timedelta(days=30):
                    expiring_soon += 1
            except:
                pass

        return jsonify({
            "success": True,
            "total": len(meds),
            "low_stock": low_stock,
            "out_of_stock": out_of_stock,
            "expired": expired,
            "expiring_soon": expiring_soon
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/medicines")
@login_required
def api_medicines():
    """API endpoint to get all medicines"""
    try:
        table = dynamodb.Table(MEDICINE_TABLE)
        medicines = decimal_to_float(table.scan().get("Items", []))
        return jsonify({"success": True, "medicines": medicines})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# --------------------------------------------------
# Error Handlers
# --------------------------------------------------
@app.errorhandler(404)
def not_found(e):
    """Handle 404 errors"""
    return render_template("404.html"), 404


@app.errorhandler(500)
def internal_error(e):
    """Handle 500 errors"""
    return render_template("500.html"), 500


# --------------------------------------------------
# App Start
# --------------------------------------------------
if __name__ == "__main__":
    print("=" * 60)
    print(" " * 15 + "MediStock - Hospital Inventory System")
    print("=" * 60)
    print("\nInitializing database tables...")
    init_tables()
    print("\nCreating default user...")
    init_default_user()
    print("=" * 60)
    print("\n✓ Application ready!")
    print("✓ Server starting on http://0.0.0.0:5000")
    print("✓ Default Login -> Username: admin | Password: admin123")
    print("=" * 60 + "\n")
    app.run(host="0.0.0.0", port=5000, debug=True)
