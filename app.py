from flask import Flask, render_template, request, redirect, url_for, session
import boto3
from boto3.dynamodb.conditions import Attr
from decimal import Decimal
from datetime import datetime
import uuid

app = Flask(__name__)
app.secret_key = "super-secret-key"

# ================= DYNAMODB (GLOBAL – DO NOT MOVE) =================
dynamodb = boto3.resource(
    "dynamodb",
    region_name="ap-south-1"
)

MEDICINE_TABLE = dynamodb.Table("MediStock_Medicines")
USER_TABLE = dynamodb.Table("MediStock_Users")
print("MEDICINE_TABLE OBJECT:", MEDICINE_TABLE)

# ==================================================================
# ================= SNS CONFIG (FIXED) =================
SNS_TOPIC_ARN = "arn:aws:sns:ap-south-1:120121146931:MediStockAlerts"

sns_client = boto3.client(
    "sns",
    region_name=AWS_REGION
)
from boto3.dynamodb.conditions import Attr

def get_user_medicines(user_id):
    response = table.scan(
        FilterExpression=Attr("user_id").eq(user_id)
    )

    items = response.get("Items", [])

    while "LastEvaluatedKey" in response:
        response = table.scan(
            FilterExpression=Attr("user_id").eq(user_id),
            ExclusiveStartKey=response["LastEvaluatedKey"]
        )
        items.extend(response.get("Items", []))

    return items


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
    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = session["user_id"]

    medicines = get_user_medicines(user_id)

    total_medicines = len(medicines)
    total_value = Decimal("0")
    low_stock = 0
    expired = 0

    today = datetime.today().date()

    for med in medicines:
        qty = int(med.get("quantity", 0))
        price = Decimal(str(med.get("price", "0")))
        threshold = int(med.get("threshold", 10))

        total_value += price * qty

        if qty < threshold:
            low_stock += 1

        expiry = med.get("expiry_date")
        if expiry:
            expiry_date = datetime.strptime(expiry, "%Y-%m-%d").date()
            if expiry_date < today:
                expired += 1

    return render_template(
        "dashboard.html",
        stats={
            "total_medicines": total_medicines,
            "total_value": total_value,
            "low_stock": low_stock,
            "expired": expired
        }
    )
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
            print("UPDATED:", medicine_id, data.get("quantity"))


    return jsonify({"status": "updated"})

# =================================================
# MEDICINES
# =================================================
@app.route("/medicines")
def medicines():
    user_id = session["user_id"]

    response = medicines_table.scan(
        FilterExpression=Attr("user_id").eq(user_id)
    )

    return render_template(
        "medicines.html",
        medicines=response.get("Items", [])
    )

@app.route("/add-medicine", methods=["GET"])
def add_medicine_page():
    if "user_id" not in session:
        return redirect(url_for("login"))

    return render_template("add_medicine.html")


@app.route("/add-medicine", methods=["POST"])
def add_medicine():
    MEDICINE_TABLE.put_item(
        Item={
            "medicine_id": str(uuid.uuid4()),
            "user_id": session["user_id"],
            "name": data.get("name"),
            "price": Decimal(str(data.get("price", "0"))),
            "quantity": int(data.get("quantity", 0)),
            "threshold": int(data.get("threshold", 10)),
            "expiry_date": data.get("expiry_date")
        }
    )

    return redirect(url_for("dashboard"))

@app.route("/edit_medicine/<medicine_id>", methods=["GET", "POST"])
def edit_medicine(medicine_id):
    if request.method == "POST":
        data = request.form

        medicines_table.update_item(
            Key={
                "medicine_id": medicine_id   # ✅ MUST MATCH TABLE KEY
            },
            UpdateExpression="""
                SET #n = :name,
                    quantity = :qty,
                    price = :price,
                    expiry_date = :expiry
            """,
            ExpressionAttributeNames={
                "#n": "name"
            },
            ExpressionAttributeValues={
                ":name": data.get("name"),
                ":qty": int(data.get("quantity", 0)),
                ":price": Decimal(data.get("price", "0")),
                ":expiry": data.get("expiry_date")
            }
        )

        return redirect(url_for("medicines"))

    response = medicines_table.get_item(
        Key={"medicine_id": medicine_id}
    )
    medicine = response.get("Item")

    return render_template("edit_medicine.html", medicine=medicine)

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



