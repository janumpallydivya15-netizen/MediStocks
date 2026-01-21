from flask import Flask, request, session, redirect, url_for, render_template, flash, jsonify
import boto3
from boto3.dynamodb.conditions import Attr
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
import os
import uuid
from dotenv import load_dotenv
from functools import wraps
from decimal import Decimal

# Load environment variables
load_dotenv()

# ---------------------------------------
# Flask App Initialization
# ---------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'temporary_key_for_development')

# Add context processor for datetime
@app.context_processor
def inject_now():
    return {'now': datetime.now()}

# ---------------------------------------
# App Configuration
# ---------------------------------------
AWS_REGION_NAME = os.environ.get('AWS_REGION', 'ap-south-1')

# Email Configuration
SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
SENDER_EMAIL = os.environ.get('SENDER_EMAIL')
SENDER_PASSWORD = os.environ.get('SENDER_PASSWORD')
ENABLE_EMAIL = os.environ.get('ENABLE_EMAIL', 'True').lower() == 'true'

# Table Names from .env
MEDICINES_TABLE_NAME = os.environ.get('DYNAMODB_TABLE_MEDICINES', 'MediStock_Medicines')
USERS_TABLE_NAME = os.environ.get('DYNAMODB_TABLE_USERS', 'MediStock_Users')

# SNS Configuration
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN', 'arn:aws:sns:ap-south-1:120121146931:MediStockAlerts')
ENABLE_SNS = os.environ.get('ENABLE_SNS', 'True').lower() == 'true'

print("=" * 50)
print("AWS CONFIGURATION")
print("=" * 50)
print(f"AWS Region: {AWS_REGION_NAME}")
print(f"Medicines Table: {MEDICINES_TABLE_NAME}")
print(f"Users Table: {USERS_TABLE_NAME}")
print(f"Email Enabled: {ENABLE_EMAIL}")
print(f"SNS Enabled: {ENABLE_SNS}")
print("=" * 50)

# ---------------------------------------
# AWS Resources
# ---------------------------------------
dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION_NAME)
sns_client = boto3.client('sns', region_name=AWS_REGION_NAME)

# DynamoDB Tables
medicines_table = dynamodb.Table(MEDICINES_TABLE_NAME)
users_table = dynamodb.Table(USERS_TABLE_NAME)

# ---------------------------------------
# Logging
# ---------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("medistock.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ---------------------------------------
# Helper Functions
# ---------------------------------------
def float_to_decimal(obj):
    """Convert float to Decimal for DynamoDB"""
    if isinstance(obj, float):
        return Decimal(str(obj))
    elif isinstance(obj, dict):
        return {k: float_to_decimal(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [float_to_decimal(i) for i in obj]
    return obj

def is_logged_in():
    """Check if user is logged in"""
    return 'user_id' in session

def login_required(f):
    """Decorator for login required routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_logged_in():
            flash('Please log in to access this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def send_email(to_email, subject, body):
    """Send email via SMTP"""
    if not ENABLE_EMAIL:
        logger.info(f"[Email Skipped] Subject: {subject} to {to_email}")
        return False

    if not SENDER_EMAIL or not SENDER_PASSWORD:
        logger.warning("Email credentials not configured")
        return False

    try:
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, to_email, msg.as_string())
        server.quit()

        logger.info(f"✅ Email sent to {to_email}")
        return True
    except Exception as e:
        logger.error(f"❌ Email sending failed: {e}")
        return False

def publish_to_sns(message, subject="MediStock Notification"):
    """Publish message to SNS topic"""
    if not ENABLE_SNS:
        logger.info(f"[SNS Skipped] Message: {message}")
        return False

    if not SNS_TOPIC_ARN:
        logger.warning("SNS Topic ARN not configured")
        return False

    try:
        response = sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Message=message,
            Subject=subject
        )
        logger.info(f"✅ SNS published: {response['MessageId']}")
        return True
    except Exception as e:
        logger.error(f"❌ SNS publish failed: {e}")
        return False

def send_low_stock_alert(medicine_name, current_stock, threshold, user_email=None):
    """Send low stock alert via SNS and email"""
    message = f"""
LOW STOCK ALERT

Medicine: {medicine_name}
Current Stock: {current_stock}
Threshold: {threshold}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Action Required: Please restock {medicine_name} as soon as possible.
"""
    
    logger.warning(f"🔔 LOW STOCK ALERT: {medicine_name} (Stock: {current_stock}, Threshold: {threshold})")
    
    # Send to SNS topic (all subscribers)
    publish_to_sns(message, f"LOW STOCK ALERT: {medicine_name}")
    
    # Send direct email if user email provided
    if user_email and ENABLE_EMAIL:
        send_email(user_email, f"LOW STOCK ALERT: {medicine_name}", message)

def send_expiry_alert(medicine_name, expiry_date, days_remaining, user_email=None):
    """Send expiry alert notification via SNS and email"""
    message = f"""
EXPIRY ALERT

Medicine: {medicine_name}
Expiry Date: {expiry_date}
Days Remaining: {days_remaining}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Action Required: Remove or use {medicine_name} before expiration.
"""
    
    logger.warning(f"⚠️ EXPIRY ALERT: {medicine_name} (Days remaining: {days_remaining})")
    
    # Send to SNS topic
    publish_to_sns(message, f"EXPIRY ALERT: {medicine_name}")
    
    # Send direct email
    if user_email and ENABLE_EMAIL:
        send_email(user_email, f"EXPIRY WARNING: {medicine_name}", message)

def send_welcome_notification(email, username):
    """Send welcome email to new user"""
    message = f"""
Welcome to MediStock, {username}!

Your account has been successfully created.
You will receive important alerts about:
- Low stock notifications
- Medicine expiry warnings
- System updates

Email: {email}
Registered: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Thank you for using MediStock!

Best regards,
MediStock Team
"""
    
    if ENABLE_EMAIL:
        send_email(email, "Welcome to MediStock", message)
        logger.info(f"Welcome email sent to {email}")

def subscribe_user_to_alerts(email):
    """Subscribe user email to SNS topic for alerts"""
    if not ENABLE_SNS or not SNS_TOPIC_ARN:
        logger.info(f"[SNS Skipped] Subscription for {email}")
        return None
        
    try:
        response = sns_client.subscribe(
            TopicArn=SNS_TOPIC_ARN,
            Protocol='email',
            Endpoint=email,
            ReturnSubscriptionArn=True
        )
        subscription_arn = response.get('SubscriptionArn', 'pending confirmation')
        logger.info(f"✅ User {email} subscribed. ARN: {subscription_arn}")
        return subscription_arn
    except Exception as e:
        logger.error(f"❌ Subscription error: {e}")
        return None

def check_and_alert_expiring_medicines(user_id, user_email=None):
    """Check for medicines expiring soon and send alerts"""
    try:
        response = medicines_table.scan(
            FilterExpression=Attr('user_id').eq(user_id)
        )
        
        medicines = response.get('Items', [])
        today = datetime.now()
        alert_sent = False
        
        for med in medicines:
            if 'expiration_date' in med and med['expiration_date']:
                try:
                    expiry = datetime.strptime(med['expiration_date'], '%Y-%m-%d')
                    days_remaining = (expiry - today).days
                    
                    # Alert if expiring within 30 days
                    if 0 < days_remaining <= 30:
                        send_expiry_alert(
                            med['name'],
                            med['expiration_date'],
                            days_remaining,
                            user_email
                        )
                        alert_sent = True
                except (ValueError, TypeError) as e:
                    logger.warning(f"Invalid date format for medicine: {med.get('name')} - {e}")
        
        return alert_sent
    except Exception as e:
        logger.error(f"Expiry check error: {e}")
        return False

# ---------------------------------------
# Routes
# ---------------------------------------

# Home Page
@app.route('/')
def index():
    if is_logged_in():
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# Registration Page
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if is_logged_in():
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        # Form validation
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        role = request.form.get('role', 'staff')
        
        if not all([username, email, password, confirm_password]):
            flash('All fields are required', 'danger')
            return render_template('signup.html')
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('signup.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters', 'danger')
            return render_template('signup.html')

        try:
            # Check if user already exists
            response = users_table.scan(FilterExpression=Attr('email').eq(email))
            if response.get('Items'):
                flash('Email already registered. Please log in.', 'danger')
                return redirect(url_for('login'))

            # Hash the password
            hashed_password = generate_password_hash(password)
            
            # Generate unique user ID
            user_id = str(uuid.uuid4())

            # Store user in DynamoDB
            users_table.put_item(
                Item={
                    'user_id': user_id,
                    'username': username,
                    'email': email,
                    'password': hashed_password,
                    'role': role,
                    'created_at': datetime.now().isoformat(),
                    'subscription_arn': '',
                    'login_count': 0
                }
            )

            # Subscribe user to SNS alerts
            subscription_arn = subscribe_user_to_alerts(email)
            if subscription_arn:
                users_table.update_item(
                    Key={'user_id': user_id},
                    UpdateExpression="SET subscription_arn = :arn",
                    ExpressionAttributeValues={':arn': subscription_arn}
                )

            # Send welcome email
            send_welcome_notification(email, username)
            
            logger.info(f"New user registered: {username} ({email})")
            flash('Account created successfully! You can now log in.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            logger.error(f"Registration error: {e}")
            flash(f'Error creating account: {str(e)}', 'danger')
            return render_template('signup.html')
        
    return render_template('signup.html')

# Login Page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if is_logged_in():
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        if not email or not password:
            flash('Email and password are required', 'danger')
            return render_template('login.html')

        try:
            # Fetch user data from DynamoDB
            response = users_table.scan(FilterExpression=Attr('email').eq(email))
            users = response.get('Items', [])

            if not users:
                flash('Invalid email or password', 'danger')
                return render_template('login.html')

            user = users[0]
            
            # Verify password
            if not check_password_hash(user['password'], password):
                flash('Invalid email or password', 'danger')
                return render_template('login.html')

            # Store user info in session
            session['user_id'] = user['user_id']
            session['username'] = user['username']
            session['email'] = user['email']
            session['role'] = user.get('role', 'staff')
            
            # Update login count
            try:
                users_table.update_item(
                    Key={'user_id': user['user_id']},
                    UpdateExpression='SET login_count = if_not_exists(login_count, :zero) + :inc',
                    ExpressionAttributeValues={':inc': 1, ':zero': 0}
                )
            except Exception as e:
                logger.error(f"Failed to update login count: {e}")
            
            logger.info(f"User logged in: {user['username']} ({email})")
            flash(f'Welcome back, {user["username"]}!', 'success')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            logger.error(f"Login error: {e}")
            flash('An error occurred. Please try again.', 'danger')
            return render_template('login.html')
        
    return render_template('login.html')

# Logout route
@app.route('/logout')
def logout():
    username = session.get('username', 'User')
    session.clear()
    logger.info(f"User logged out: {username}")
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('index'))

# Dashboard Page
@app.route('/dashboard')
@login_required
def dashboard():
    response = medicines_table.scan(
        FilterExpression=Attr('user_id').eq(session['user_id'])
    )
    medicines = response.get('Items', [])

    total_medicines = len(medicines)
    low_stock = sum(
        1 for m in medicines
        if int(m.get('quantity', 0)) <= int(m.get('threshold', 0))
    )
    out_of_stock = sum(
        1 for m in medicines
        if int(m.get('quantity', 0)) == 0
    )

    stats = {
        "total_medicines": total_medicines,
        "low_stock": low_stock,
        "out_of_stock": out_of_stock
    }

    return render_template(
        'dashboard.html',
        medicines=medicines,
        stats=stats   # 🔴 THIS LINE FIXES EVERYTHING
    )

# Medicines List Page
@app.route('/medicines')
@login_required
def medicines():
    try:
        # Get user's medicines from DynamoDB
        response = medicines_table.scan(
            FilterExpression=Attr('user_id').eq(session['user_id'])
        )
        medicines_list = response.get('Items', [])
        
        # Sort medicines by name
        medicines_list.sort(key=lambda x: x.get('name', '').lower())
        
        return render_template('medicines.html', medicines=medicines_list)
    except Exception as e:
        logger.error(f"Error fetching medicines: {e}")
        flash('An error occurred loading medicines.', 'danger')
        return render_template('medicines.html', medicines=[])

# Add Medicine Page
@app.route('/medicines/add', methods=['GET', 'POST'])
@login_required
def add_medicine():
    if request.method == 'POST':
        # Form validation
        name = request.form.get('name', '').strip()
        category = request.form.get('category', '').strip()
        quantity = request.form.get('quantity', '0')
        threshold = request.form.get('threshold', '0')
        expiration_date = request.form.get('expiration_date', '')
        
        if not all([name, category, quantity, threshold, expiration_date]):
            flash('All fields are required', 'danger')
            return render_template('add_medicine.html')
        
        try:
            quantity_int = int(quantity)
            threshold_int = int(threshold)
            
            if quantity_int < 0 or threshold_int < 0:
                flash('Quantity and threshold must be positive numbers', 'danger')
                return render_template('add_medicine.html')
            
            # Generate unique medicine ID
            medicine_id = str(uuid.uuid4())
            
            # Store medicine in DynamoDB
            medicines_table.put_item(
                Item={
                    'medicine_id': medicine_id,
                    'user_id': session['user_id'],
                    'name': name,
                    'category': category,
                    'quantity': quantity_int,
                    'threshold': threshold_int,
                    'expiration_date': expiration_date,
                    'created_at': datetime.now().isoformat()
                }
            )
            
            logger.info(f"Medicine added: {name} by {session['username']}")
            
            # Check if stock is low immediately after adding
            if quantity_int <= threshold_int:
                send_low_stock_alert(name, quantity_int, threshold_int, session.get('email'))
            
            flash(f"Medicine '{name}' added successfully!", 'success')
            return redirect(url_for('medicines'))
            
        except ValueError:
            flash('Quantity and threshold must be valid numbers', 'danger')
            return render_template('add_medicine.html')
        except Exception as e:
            logger.error(f"Error adding medicine: {e}")
            flash('An error occurred while adding the medicine. Please try again.', 'danger')
            return render_template('add_medicine.html')
        
    return render_template('add_medicine.html')

# Edit Medicine Page
@app.route('/medicines/edit/<medicine_id>', methods=['GET', 'POST'])
@login_required
def edit_medicine(medicine_id):
    try:
        # Get medicine details from DynamoDB
        response = medicines_table.get_item(Key={'medicine_id': medicine_id})
        medicine = response.get('Item')
        
        if not medicine:
            flash('Medicine not found!', 'danger')
            return redirect(url_for('medicines'))
        
        # Security check - verify the logged-in user owns this medicine
        if medicine.get('user_id') != session['user_id']:
            flash('You are not authorized to edit this medicine.', 'danger')
            return redirect(url_for('medicines'))
        
        if request.method == 'POST':
            # Form validation
            name = request.form.get('name', '').strip()
            category = request.form.get('category', '').strip()
            quantity = request.form.get('quantity', '0')
            threshold = request.form.get('threshold', '0')
            expiration_date = request.form.get('expiration_date', '')
            
            if not all([name, category, quantity, threshold]):
                flash('All fields are required', 'danger')
                return render_template('edit_medicine.html', medicine=medicine)
            
            try:
                old_quantity = int(medicine.get('quantity', 0))
                new_quantity = int(quantity)
                new_threshold = int(threshold)
                
                if new_quantity < 0 or new_threshold < 0:
                    flash('Quantity and threshold must be positive numbers', 'danger')
                    return render_template('edit_medicine.html', medicine=medicine)
                
                # Update medicine in DynamoDB
                medicines_table.update_item(
                    Key={'medicine_id': medicine_id},
                    UpdateExpression="""
                        SET #name = :name, 
                            category = :category, 
                            quantity = :quantity, 
                            threshold = :threshold, 
                            expiration_date = :expiration_date,
                            updated_at = :updated_at
                    """,
                    ConditionExpression='attribute_exists(medicine_id)',
                    ExpressionAttributeNames={
                        '#name': 'name'
                    },
                    ExpressionAttributeValues={
                        ':name': name,
                        ':category': category,
                        ':quantity': new_quantity,
                        ':threshold': new_threshold,
                        ':expiration_date': expiration_date,
                        ':updated_at': datetime.now().isoformat()
                    }
                )

                logger.info(f"Medicine updated: {name} (ID: {medicine_id}) by {session['username']}")
                
                # Check if stock is low after update
                if new_quantity <= new_threshold:
                    # Only send alert if quantity decreased or is newly below threshold
                    if new_quantity < old_quantity or old_quantity > medicine.get('threshold', 0):
                        send_low_stock_alert(name, new_quantity, new_threshold, session.get('email'))

                flash(f"Medicine '{name}' updated successfully!", 'success')
                return redirect(url_for('medicines'))
                
            except ValueError:
                flash('Quantity and threshold must be valid numbers', 'danger')
                return render_template('edit_medicine.html', medicine=medicine)
            except medicines_table.meta.client.exceptions.ConditionalCheckFailedException:
                flash('Medicine not found. Update failed.', 'danger')
                return redirect(url_for('medicines'))
            except Exception as e:
                logger.error(f"Error updating medicine: {e}")
                flash(f"Error updating medicine: {str(e)}", 'danger')
                return render_template('edit_medicine.html', medicine=medicine)
            
        return render_template('edit_medicine.html', medicine=medicine)
    except Exception as e:
        logger.error(f"Error in edit_medicine: {e}")
        flash('An error occurred. Please try again.', 'danger')
        return redirect(url_for('medicines'))

# Delete Medicine Route
@app.route('/medicines/delete/<medicine_id>', methods=['POST'])
@login_required
def delete_medicine(medicine_id):
    try:
        # Get medicine details before deletion
        response = medicines_table.get_item(Key={'medicine_id': medicine_id})
        medicine = response.get('Item')
        
        if not medicine:
            flash('Medicine not found.', 'danger')
            return redirect(url_for('medicines'))
        
        # Security check - verify the logged-in user owns this medicine
        if medicine.get('user_id') != session['user_id']:
            flash('You are not authorized to delete this medicine.', 'danger')
            return redirect(url_for('medicines'))
        
        medicine_name = medicine.get('name', 'Unknown')
        
        # Delete medicine from DynamoDB
        medicines_table.delete_item(Key={'medicine_id': medicine_id})
        
        logger.info(f"Medicine deleted: {medicine_name} (ID: {medicine_id}) by {session['username']}")
        flash(f"Medicine '{medicine_name}' deleted successfully.", 'success')
    except Exception as e:
        logger.error(f"Error deleting medicine: {e}")
        flash('An error occurred while deleting the medicine.', 'danger')
    
    return redirect(url_for('medicines'))

# Alerts Page
@app.route('/alerts')
@login_required
def alerts():
    try:
        response = medicines_table.scan(
            FilterExpression=Attr('user_id').eq(session['user_id'])
        )
        all_medicines = response.get('Items', [])
        
        # Filter low stock items
        low_stock_medicines = [
            m for m in all_medicines 
            if int(m.get('quantity', 0)) <= int(m.get('threshold', 0))
        ]
        
        # Filter expiring soon (within 30 days)
        expiring_soon = []
        today = datetime.now()
        
        for m in all_medicines:
            if m.get('expiration_date'):
                try:
                    expiry_date = datetime.strptime(m['expiration_date'], '%Y-%m-%d')
                    days_diff = (expiry_date - today).days
                    
                    if 0 <= days_diff <= 30:
                        m['days_remaining'] = days_diff
                        expiring_soon.append(m)
                except (ValueError, TypeError):
                    pass
        
        # Sort by days remaining
        expiring_soon.sort(key=lambda x: x.get('days_remaining', 999))
        
        return render_template('alerts.html', 
                             low_stock=low_stock_medicines,
                             expiring_soon=expiring_soon)
    except Exception as e:
        logger.error(f"Error loading alerts: {e}")
        flash('Error loading alerts', 'danger')
        return render_template('alerts.html', low_stock=[], expiring_soon=[])

# Update Stock (Quick Update via AJAX)
@app.route('/medicines/update-stock/<medicine_id>', methods=['POST'])
@login_required
def update_stock(medicine_id):
    try:
        quantity_change = int(request.form.get('quantity_change', 0))
        action = request.form.get('action')  # 'add' or 'remove'
        
        # Get current medicine data
        response = medicines_table.get_item(Key={'medicine_id': medicine_id})
        medicine = response.get('Item')
        
        if not medicine:
            return jsonify({'success': False, 'message': 'Medicine not found'})
        
        # Security check
        if medicine.get('user_id') != session['user_id']:
            return jsonify({'success': False, 'message': 'Unauthorized'})
        
        current_quantity = int(medicine['quantity'])
        threshold = int(medicine['threshold'])
        medicine_name = medicine['name']
        
        # Calculate new quantity
        if action == 'add':
            new_quantity = current_quantity + quantity_change
        elif action == 'remove':
            new_quantity = max(0, current_quantity - quantity_change)
        else:
            return jsonify({'success': False, 'message': 'Invalid action'})
        
        # Update quantity
        medicines_table.update_item(
            Key={'medicine_id': medicine_id},
            UpdateExpression='SET quantity = :quantity, updated_at = :updated',
            ExpressionAttributeValues={
                ':quantity': new_quantity,
                ':updated': datetime.now().isoformat()
            }
        )
        
        logger.info(f"Stock updated: {medicine_name} - {action} {quantity_change} (New: {new_quantity})")
        
        # Check for low stock alert
        if new_quantity <= threshold and new_quantity < current_quantity:
            send_low_stock_alert(medicine_name, new_quantity, threshold, session.get('email'))
        
        return jsonify({
            'success': True, 
            'message': 'Stock updated successfully',
            'new_quantity': new_quantity,
            'low_stock': new_quantity <= threshold
        })
        
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid quantity'})
    except Exception as e:
        logger.error(f"Stock update error: {e}")
        return jsonify({'success': False, 'message': str(e)})

# Reports Page
@app.route('/reports')
@login_required
def reports():
    try:
        response = medicines_table.scan(
            FilterExpression=Attr('user_id').eq(session['user_id'])
        )
        medicines = response.get('Items', [])

        total_medicines = len(medicines)
        low_stock = sum(
            1 for m in medicines
            if int(m.get('quantity', 0)) <= int(m.get('threshold', 0))
        )
        out_of_stock = sum(
            1 for m in medicines
            if int(m.get('quantity', 0)) == 0
        )
        
        # Calculate total stock value (if you add price field later)
        total_stock = sum(int(m.get('quantity', 0)) for m in medicines)

        return render_template(
            'reports.html',
            medicines=medicines,
            total_medicines=total_medicines,
            low_stock=low_stock,
            out_of_stock=out_of_stock,
            total_stock=total_stock
        )
    except Exception as e:
        logger.error(f"Reports error: {e}")
        flash('Error loading reports', 'danger')
        return render_template('reports.html', medicines=[], 
                             total_medicines=0, low_stock=0, 
                             out_of_stock=0, total_stock=0)

# User Profile Page
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    try:
        # Get user details from DynamoDB
        response = users_table.get_item(Key={'user_id': session['user_id']})
        user = response.get('Item', {})
        
        if request.method == 'POST':
