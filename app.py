from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from functools import wraps
import boto3
from boto3.dynamodb.conditions import Key, Attr
from decimal import Decimal
from datetime import datetime, timedelta
import json
import uuid
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

# AWS Service Configuration
# Uses IAM roles attached to EC2 instance - no credentials needed
dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
sns_client = boto3.client('sns', region_name='us-east-1')

# DynamoDB Tables
MEDICINE_TABLE = 'MedicineInventory'
USERS_TABLE = 'PharmacyUsers'
ALERT_LOGS_TABLE = 'AlertLogs'

# SNS Topic ARN (to be configured)
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN', 'arn:aws:sns:us-east-1:ACCOUNT_ID:MediStockAlerts')

# Helper function to convert float to Decimal for DynamoDB
def convert_to_decimal(obj):
    if isinstance(obj, float):
        return Decimal(str(obj))
    elif isinstance(obj, dict):
        return {k: convert_to_decimal(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_to_decimal(i) for i in obj]
    return obj

# Helper function to convert Decimal to float for JSON serialization
def decimal_to_float(obj):
    if isinstance(obj, Decimal):
        return float(obj)
    elif isinstance(obj, dict):
        return {k: decimal_to_float(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [decimal_to_float(i) for i in obj]
    return obj

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Initialize DynamoDB Tables
def init_tables():
    """Initialize DynamoDB tables if they don't exist"""
    try:
        # Medicine Inventory Table
        try:
            table = dynamodb.create_table(
                TableName=MEDICINE_TABLE,
                KeySchema=[
                    {'AttributeName': 'medicine_id', 'KeyType': 'HASH'}
                ],
                AttributeDefinitions=[
                    {'AttributeName': 'medicine_id', 'AttributeType': 'S'}
                ],
                BillingMode='PAY_PER_REQUEST'
            )
            table.wait_until_exists()
            print(f"Created table: {MEDICINE_TABLE}")
        except dynamodb.meta.client.exceptions.ResourceInUseException:
            print(f"Table {MEDICINE_TABLE} already exists")

        # Users Table
        try:
            table = dynamodb.create_table(
                TableName=USERS_TABLE,
                KeySchema=[
                    {'AttributeName': 'user_id', 'KeyType': 'HASH'}
                ],
                AttributeDefinitions=[
                    {'AttributeName': 'user_id', 'AttributeType': 'S'}
                ],
                BillingMode='PAY_PER_REQUEST'
            )
            table.wait_until_exists()
            print(f"Created table: {USERS_TABLE}")
        except dynamodb.meta.client.exceptions.ResourceInUseException:
            print(f"Table {USERS_TABLE} already exists")

        # Alert Logs Table
        try:
            table = dynamodb.create_table(
                TableName=ALERT_LOGS_TABLE,
                KeySchema=[
                    {'AttributeName': 'alert_id', 'KeyType': 'HASH'}
                ],
                AttributeDefinitions=[
                    {'AttributeName': 'alert_id', 'AttributeType': 'S'}
                ],
                BillingMode='PAY_PER_REQUEST'
            )
            table.wait_until_exists()
            print(f"Created table: {ALERT_LOGS_TABLE}")
        except dynamodb.meta.client.exceptions.ResourceInUseException:
            print(f"Table {ALERT_LOGS_TABLE} already exists")

    except Exception as e:
        print(f"Error initializing tables: {str(e)}")

# SNS Alert Function
def send_stock_alert(medicine_name, current_stock, threshold, medicine_id):
    """Send SNS notification for low stock"""
    try:
        message = f"""
        ⚠️ MEDISTOCK ALERT - LOW INVENTORY WARNING ⚠️
        
        Medicine: {medicine_name}
        Medicine ID: {medicine_id}
        Current Stock: {current_stock} units
        Threshold Level: {threshold} units
        Status: CRITICAL - Immediate Restocking Required
        
        Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        
        Please take immediate action to reorder this medicine.
        """
        
        response = sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f'MediStock Alert: {medicine_name} - Low Stock',
            Message=message
        )
        
        # Log alert in DynamoDB
        log_alert(medicine_id, medicine_name, current_stock, threshold)
        
        return response['MessageId']
    except Exception as e:
        print(f"Error sending SNS alert: {str(e)}")
        return None

def log_alert(medicine_id, medicine_name, current_stock, threshold):
    """Log alert to DynamoDB"""
    try:
        table = dynamodb.Table(ALERT_LOGS_TABLE)
        alert_id = str(uuid.uuid4())
        
        table.put_item(Item={
            'alert_id': alert_id,
            'medicine_id': medicine_id,
            'medicine_name': medicine_name,
            'current_stock': Decimal(str(current_stock)),
            'threshold': Decimal(str(threshold)),
            'timestamp': datetime.now().isoformat(),
            'status': 'SENT'
        })
    except Exception as e:
        print(f"Error logging alert: {str(e)}")

# Routes
@app.route('/')
def index():
    """Home page"""
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Simple authentication (in production, use proper password hashing)
        table = dynamodb.Table(USERS_TABLE)
        try:
            response = table.scan(
                FilterExpression=Attr('username').eq(username)
            )
            
            if response['Items'] and response['Items'][0]['password'] == password:
                user = response['Items'][0]
                session['user_id'] = user['user_id']
                session['username'] = user['username']
                session['role'] = user['role']
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid credentials', 'danger')
        except Exception as e:
            flash(f'Login error: {str(e)}', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """User logout"""
    session.clear()
    flash('Logged out successfully', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard showing inventory overview"""
    try:
        table = dynamodb.Table(MEDICINE_TABLE)
        response = table.scan()
        medicines = decimal_to_float(response['Items'])
        
        # Calculate statistics
        total_medicines = len(medicines)
        low_stock_count = sum(1 for m in medicines if m['current_quantity'] <= m['threshold_quantity'])
        expired_count = sum(1 for m in medicines if datetime.fromisoformat(m['expiry_date']) < datetime.now())
        
        stats = {
            'total_medicines': total_medicines,
            'low_stock': low_stock_count,
            'expired': expired_count,
            'healthy_stock': total_medicines - low_stock_count - expired_count
        }
        
        return render_template('dashboard.html', stats=stats, username=session.get('username'))
    except Exception as e:
        flash(f'Error loading dashboard: {str(e)}', 'danger')
        return render_template('dashboard.html', stats={}, username=session.get('username'))

@app.route('/inventory')
@login_required
def inventory():
    """View all inventory"""
    try:
        table = dynamodb.Table(MEDICINE_TABLE)
        response = table.scan()
        medicines = decimal_to_float(response['Items'])
        
        # Sort by medicine name
        medicines.sort(key=lambda x: x['medicine_name'])
        
        return render_template('inventory.html', medicines=medicines)
    except Exception as e:
        flash(f'Error loading inventory: {str(e)}', 'danger')
        return render_template('inventory.html', medicines=[])

@app.route('/add_medicine', methods=['GET', 'POST'])
@login_required
def add_medicine():
    """Add new medicine to inventory"""
    if request.method == 'POST':
        try:
            table = dynamodb.Table(MEDICINE_TABLE)
            medicine_id = str(uuid.uuid4())
            
            item = {
                'medicine_id': medicine_id,
                'medicine_name': request.form.get('medicine_name'),
                'category': request.form.get('category'),
                'batch_number': request.form.get('batch_number'),
                'current_quantity': Decimal(request.form.get('current_quantity')),
                'threshold_quantity': Decimal(request.form.get('threshold_quantity')),
                'unit': request.form.get('unit'),
                'manufacturer': request.form.get('manufacturer'),
                'expiry_date': request.form.get('expiry_date'),
                'unit_price': Decimal(request.form.get('unit_price')),
                'location': request.form.get('location', 'Main Pharmacy'),
                'added_by': session.get('username'),
                'added_date': datetime.now().isoformat(),
                'last_updated': datetime.now().isoformat()
            }
            
            table.put_item(Item=item)
            flash(f'Medicine {item["medicine_name"]} added successfully!', 'success')
            return redirect(url_for('inventory'))
            
        except Exception as e:
            flash(f'Error adding medicine: {str(e)}', 'danger')
    
    return render_template('add_medicine.html')

@app.route('/update_stock/<medicine_id>', methods=['GET', 'POST'])
@login_required
def update_stock(medicine_id):
    """Update medicine stock quantity"""
    table = dynamodb.Table(MEDICINE_TABLE)
    
    if request.method == 'POST':
        try:
            action = request.form.get('action')
            quantity = Decimal(request.form.get('quantity'))
            
            # Get current medicine data
            response = table.get_item(Key={'medicine_id': medicine_id})
            medicine = response['Item']
            
            if action == 'add':
                new_quantity = medicine['current_quantity'] + quantity
            else:  # subtract
                new_quantity = medicine['current_quantity'] - quantity
                if new_quantity < 0:
                    flash('Insufficient stock!', 'danger')
                    return redirect(url_for('inventory'))
            
            # Update quantity
            table.update_item(
                Key={'medicine_id': medicine_id},
                UpdateExpression='SET current_quantity = :qty, last_updated = :updated',
                ExpressionAttributeValues={
                    ':qty': new_quantity,
                    ':updated': datetime.now().isoformat()
                }
            )
            
            # Check if alert needs to be sent
            if new_quantity <= medicine['threshold_quantity']:
                send_stock_alert(
                    medicine['medicine_name'],
                    float(new_quantity),
                    float(medicine['threshold_quantity']),
                    medicine_id
                )
                flash(f'Stock updated and alert sent for {medicine["medicine_name"]}!', 'warning')
            else:
                flash('Stock updated successfully!', 'success')
            
            return redirect(url_for('inventory'))
            
        except Exception as e:
            flash(f'Error updating stock: {str(e)}', 'danger')
    
    # GET request - show current medicine details
    try:
        response = table.get_item(Key={'medicine_id': medicine_id})
        medicine = decimal_to_float(response['Item'])
        return render_template('update_stock.html', medicine=medicine)
    except Exception as e:
        flash(f'Error loading medicine: {str(e)}', 'danger')
        return redirect(url_for('inventory'))

@app.route('/low_stock')
@login_required
def low_stock():
    """View medicines with low stock"""
    try:
        table = dynamodb.Table(MEDICINE_TABLE)
        response = table.scan()
        all_medicines = response['Items']
        
        # Filter low stock items
        low_stock_medicines = [
            decimal_to_float(m) for m in all_medicines 
            if m['current_quantity'] <= m['threshold_quantity']
        ]
        
        low_stock_medicines.sort(
            key=lambda x: (x['current_quantity'] / x['threshold_quantity'])
        )
        
        return render_template('low_stock.html', medicines=low_stock_medicines)
    except Exception as e:
        flash(f'Error loading low stock items: {str(e)}', 'danger')
        return render_template('low_stock.html', medicines=[])

@app.route('/alert_logs')
@login_required
def alert_logs():
    """View alert history"""
    try:
        table = dynamodb.Table(ALERT_LOGS_TABLE)
        response = table.scan()
        alerts = decimal_to_float(response['Items'])
        
        # Sort by timestamp (most recent first)
        alerts.sort(key=lambda x: x['timestamp'], reverse=True)
        
        return render_template('alert_logs.html', alerts=alerts)
    except Exception as e:
        flash(f'Error loading alerts: {str(e)}', 'danger')
        return render_template('alert_logs.html', alerts=[])

@app.route('/api/medicines', methods=['GET'])
@login_required
def api_get_medicines():
    """API endpoint to get all medicines"""
    try:
        table = dynamodb.Table(MEDICINE_TABLE)
        response = table.scan()
        medicines = decimal_to_float(response['Items'])
        return jsonify({'success': True, 'data': medicines})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/medicine/<medicine_id>', methods=['GET'])
@login_required
def api_get_medicine(medicine_id):
    """API endpoint to get specific medicine"""
    try:
        table = dynamodb.Table(MEDICINE_TABLE)
        response = table.get_item(Key={'medicine_id': medicine_id})
        if 'Item' in response:
            medicine = decimal_to_float(response['Item'])
            return jsonify({'success': True, 'data': medicine})
        else:
            return jsonify({'success': False, 'error': 'Medicine not found'}), 404
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/delete_medicine/<medicine_id>', methods=['POST'])
@login_required
def delete_medicine(medicine_id):
    """Delete medicine from inventory"""
    try:
        table = dynamodb.Table(MEDICINE_TABLE)
        response = table.get_item(Key={'medicine_id': medicine_id})
        
        if 'Item' in response:
            medicine_name = response['Item']['medicine_name']
            table.delete_item(Key={'medicine_id': medicine_id})
            flash(f'Medicine {medicine_name} deleted successfully!', 'success')
        else:
            flash('Medicine not found!', 'danger')
            
    except Exception as e:
        flash(f'Error deleting medicine: {str(e)}', 'danger')
    
    return redirect(url_for('inventory'))

@app.route('/expiring_soon')
@login_required
def expiring_soon():
    """View medicines expiring within 90 days"""
    try:
        table = dynamodb.Table(MEDICINE_TABLE)
        response = table.scan()
        all_medicines = response['Items']
        
        # Filter medicines expiring within 90 days
        cutoff_date = datetime.now() + timedelta(days=90)
        expiring_medicines = [
            decimal_to_float(m) for m in all_medicines
            if datetime.fromisoformat(m['expiry_date']) <= cutoff_date
        ]
        
        # Sort by expiry date
        expiring_medicines.sort(key=lambda x: x['expiry_date'])
        
        return render_template('expiring_soon.html', medicines=expiring_medicines)
    except Exception as e:
        flash(f'Error loading expiring medicines: {str(e)}', 'danger')
        return render_template('expiring_soon.html', medicines=[])

if __name__ == '__main__':
    # Initialize tables on startup
    init_tables()
    
    # Run Flask app
    app.run(host='0.0.0.0', port=5000, debug=True)
