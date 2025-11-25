# from flask import Flask, request, render_template, redirect, url_for, session,flash
# import smtplib
# from email.mime.text import MIMEText
# import sqlite3
# from werkzeug.security import generate_password_hash, check_password_hash

# app = Flask(__name__)
# app.secret_key = 'your_strong_secret_key_here'  # Change this to a random string

# # Database setup
# def get_db():
#     conn = sqlite3.connect('users.db')
#     conn.row_factory = sqlite3.Row  # Allows accessing columns by name
#     return conn

# def init_db():
#     with get_db() as conn:
#         c = conn.cursor()
#         c.execute('''CREATE TABLE IF NOT EXISTS users (
#                     id INTEGER PRIMARY KEY AUTOINCREMENT,
#                     email TEXT UNIQUE,
#                     location TEXT
#                 )''')
#         c.execute('''CREATE TABLE IF NOT EXISTS admins (
#                     id INTEGER PRIMARY KEY AUTOINCREMENT,
#                     username TEXT UNIQUE,
#                     password TEXT
#                 )''')
#         try:
#             c.execute("INSERT INTO admins (username, password) VALUES (?, ?)", 
#                      ('admin', generate_password_hash('admin123')))
#         except sqlite3.IntegrityError:
#             pass
#         conn.commit()

# init_db()

# # Email configuration (using your credentials)
# EMAIL_CONFIG = {
#     'sender_email': "nayamatemeet@gmail.com",
#     'sender_password': "tjoy glyv olws wdxv",
#     'smtp_server': "smtp.gmail.com",
#     'smtp_port': 465,
#     'use_ssl': True
# }


# def send_alert_email(to_email, location, alert_message):
#     """Send emergency alert email to a user"""
#     subject = f"🚨 Emergency Alert for {location} 🚨"
#     body = f"""
#     Emergency Alert Notification
    
#     Location: {location}
#     Message: {alert_message}
    
#     Please take necessary precautions and follow local authorities' instructions.
    
#     Stay safe,
#     Disaster Management Team
#     """
#     msg = MIMEText(body)
#     msg['Subject'] = subject
#     msg['From'] = EMAIL_CONFIG['sender_email']
#     msg['To'] = to_email
    
#     try:
#         # Try STARTTLS first
#         with smtplib.SMTP(EMAIL_CONFIG['smtp_server'], 587) as server:
#             server.starttls()
#             server.login(EMAIL_CONFIG['sender_email'], EMAIL_CONFIG['sender_password'])
#             server.send_message(msg)
#             print(f"Email sent to {to_email} using STARTTLS.")
#         return True
#     except Exception as e:
#         print(f"STARTTLS failed: {e}")
    
#     try:
#         # Fallback to SSL
#         with smtplib.SMTP_SSL(EMAIL_CONFIG['smtp_server'], EMAIL_CONFIG['smtp_port']) as server:
#             server.login(EMAIL_CONFIG['sender_email'], EMAIL_CONFIG['sender_password'])
#             server.send_message(msg)
#             print(f"Email sent to {to_email} using SMTP_SSL.")
#         return True
#     except Exception as e:
#         print(f"SMTP_SSL also failed: {e}")
#         import traceback
#         traceback.print_exc()
#         return False

# @app.route('/admin/dashboard', methods=['GET', 'POST'])
# def admin_dashboard():
#     if not session.get('admin_logged_in'):
#         return redirect(url_for('admin_login'))
    
#     with get_db() as conn:
#         users = conn.execute(
#             "SELECT id, email, location FROM users ORDER BY email"
#         ).fetchall()
    
#     if request.method == 'POST':
#         location = request.form.get('location')
#         message = request.form.get('message')
        
#         if not location or not message:
#             return render_template('admin_dashboard.html', 
#                                 users=users,
#                                 error="Both location and message are required!")
        
#         try:
#             with get_db() as conn:
#                 target_users = conn.execute(
#                     "SELECT email FROM users WHERE location = ?", 
#                     (location,)
#                 ).fetchall()
                
#                 if not target_users:
#                     return render_template('admin_dashboard.html', 
#                                         users=users,
#                                         error=f"No users found in location: {location}")
                
#                 success_count = 0
#                 failed_emails = []
                
#                 for user in target_users:
#                     if send_alert_email(user['email'], location, message):
#                         success_count += 1
#                     else:
#                         failed_emails.append(user['email'])
                
#                 result = {
#                     'success': f"Alert sent to {success_count}/{len(target_users)} users in {location}",
#                     'failed': failed_emails
#                 }
                
#                 return render_template('admin_dashboard.html', 
#                                     users=users,
#                                     result=result['success'],
#                                     last_location=location,
#                                     last_message=message)
        
#         except Exception as e:
#             print(f"Error in admin_dashboard: {str(e)}")  # Debug print
#             return render_template('admin_dashboard.html', 
#                                 users=users,
#                                 error=f"An error occurred: {str(e)}")

#     return render_template('admin_dashboard.html', users=users)


# @app.route('/')
# def home():
#     return render_template('index.html')

# @app.route('/register', methods=['GET', 'POST'])
# def register():
#     if request.method == 'POST':
#         email = request.form.get('email')
#         location = request.form.get('location')
        
#         if not email or not location:
#             flash("Both email and location are required!", "error")
#             return redirect(url_for('register'))
        
#         try:
#             with get_db() as conn:
#                 conn.execute("INSERT INTO users (email, location) VALUES (?, ?)", (email, location))
#                 conn.commit()
#             flash("Registration successful! You'll now receive alerts.", "success")
#             return redirect(url_for('register'))
#         except sqlite3.IntegrityError:
#             flash("This email is already registered!", "error")
#             return redirect(url_for('register'))
    
#     return render_template('register.html')

# @app.route('/admin/login', methods=['GET', 'POST'])
# def admin_login():
#     if request.method == 'POST':
#         username = request.form.get('username')
#         password = request.form.get('password')
        
#         with get_db() as conn:
#             admin = conn.execute(
#                 "SELECT password FROM admins WHERE username = ?", 
#                 (username,)
#             ).fetchone()
        
#         if admin and check_password_hash(admin['password'], password):
#             session['admin_logged_in'] = True
#             return redirect(url_for('admin_dashboard'))
#         else:
#             return render_template('admin_login.html', error="Invalid credentials!")
    
#     return render_template('admin_login.html')



# @app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
# def delete_user(user_id):
#     if not session.get('admin_logged_in'):
#         return redirect(url_for('admin_login'))
    
#     with get_db() as conn:
#         conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
#         conn.commit()
    
#     return redirect(url_for('admin_dashboard'))

# @app.route('/admin/logout')
# def admin_logout():
#     session.pop('admin_logged_in', None)
#     return redirect(url_for('home'))





# # @app.route('/')
# # def home():
# #     return render_template('index.html')

# @app.route('/about')
# def about():
#     return render_template('aboutus.html')

# @app.route('/contacts')
# def contacts():
#     return render_template('contacts.html')

# @app.route('/donation')
# def donation():
#     return render_template('donation.html')

# @app.route('/emergency')
# def emergency():
#     return render_template('emergency.html')

# @app.route('/firstaid')
# def firstaid():
#     return render_template('firstaid.html')

# @app.route('/missing')
# def missing():
#     return render_template('missing.html')

# @app.route('/protection')
# def protection():
#     return render_template('protecthome.html')  
# @app.route('/routes')
# def routes():
#     return render_template('routes.html')

# @app.route('/user')
# def user():
#     return render_template('user.html')

# if __name__ == '__main__':
#     app.run(debug=True)










from flask import Flask, request, render_template, redirect, url_for, session, flash, jsonify
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import json
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_strong_secret_key_here'  # Change this to a random string

# Database setup
def get_db():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row  # Allows accessing columns by name
    return conn

def init_db():
    with get_db() as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE,
                    location TEXT
                )''')
        c.execute('''CREATE TABLE IF NOT EXISTS admins (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE,
                    password TEXT
                )''')
        c.execute('''CREATE TABLE IF NOT EXISTS sos_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    latitude REAL,
                    longitude REAL,
                    address TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    status TEXT DEFAULT 'active'
                )''')
        try:
            c.execute("INSERT INTO admins (username, password) VALUES (?, ?)", 
                     ('admin', generate_password_hash('admin123')))
        except sqlite3.IntegrityError:
            pass
        conn.commit()

init_db()

# Email configuration (using your credentials)
EMAIL_CONFIG = {
    'sender_email': "nayamatemeet@gmail.com",
    'sender_password': "tjoy glyv olws wdxv",
    'smtp_server': "smtp.gmail.com",
    'smtp_port': 465,
    'use_ssl': True
}

# Admin email for SOS alerts
ADMIN_EMAIL = "nayamatemeet@gmail.com"  # Change this to your admin email

def send_alert_email(to_email, location, alert_message):
    """Send emergency alert email to a user"""
    subject = f"🚨 Emergency Alert for {location} 🚨"
    body = f"""
    Emergency Alert Notification
    
    Location: {location}
    Message: {alert_message}
    
    Please take necessary precautions and follow local authorities' instructions.
    
    Stay safe,
    Disaster Management Team
    """
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = EMAIL_CONFIG['sender_email']
    msg['To'] = to_email
    
    try:
        # Try STARTTLS first
        with smtplib.SMTP(EMAIL_CONFIG['smtp_server'], 587) as server:
            server.starttls()
            server.login(EMAIL_CONFIG['sender_email'], EMAIL_CONFIG['sender_password'])
            server.send_message(msg)
            print(f"Email sent to {to_email} using STARTTLS.")
        return True
    except Exception as e:
        print(f"STARTTLS failed: {e}")
    
    try:
        # Fallback to SSL
        with smtplib.SMTP_SSL(EMAIL_CONFIG['smtp_server'], EMAIL_CONFIG['smtp_port']) as server:
            server.login(EMAIL_CONFIG['sender_email'], EMAIL_CONFIG['sender_password'])
            server.send_message(msg)
            print(f"Email sent to {to_email} using SMTP_SSL.")
        return True
    except Exception as e:
        print(f"SMTP_SSL also failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def send_sos_email(latitude, longitude, address):
    """Send SOS emergency email to admin"""
    try:
        # Create message
        msg = MIMEMultipart()
        msg['From'] = EMAIL_CONFIG['sender_email']
        msg['To'] = ADMIN_EMAIL
        msg['Subject'] = "🚨 SOS EMERGENCY ALERT - IMMEDIATE ACTION REQUIRED 🚨"
        
        # Create email body
        google_maps_link = f"https://maps.google.com/?q={latitude},{longitude}"
        
        body = f"""
🚨 SOS EMERGENCY ALERT 🚨

A user has triggered an SOS signal and needs immediate assistance!

LOCATION DETAILS:
• Coordinates: {latitude}, {longitude}
• Address: {address}
• Google Maps: {google_maps_link}
• Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

URGENT ACTION REQUIRED:
Please dispatch emergency services to this location immediately.

This is an automated emergency alert from the Disaster Relief System.

---
Emergency Response Protocol:
1. Verify location accuracy
2. Contact local emergency services
3. Dispatch nearest response team
4. Maintain communication with the user if possible
        """
        
        msg.attach(MIMEText(body, 'plain'))
        
        # Try STARTTLS first
        try:
            with smtplib.SMTP(EMAIL_CONFIG['smtp_server'], 587) as server:
                server.starttls()
                server.login(EMAIL_CONFIG['sender_email'], EMAIL_CONFIG['sender_password'])
                server.send_message(msg)
                print("SOS email sent to admin using STARTTLS")
                return True
        except Exception as e:
            print(f"STARTTLS failed: {e}")
        
        # Fallback to SSL
        try:
            with smtplib.SMTP_SSL(EMAIL_CONFIG['smtp_server'], EMAIL_CONFIG['smtp_port']) as server:
                server.login(EMAIL_CONFIG['sender_email'], EMAIL_CONFIG['sender_password'])
                server.send_message(msg)
                print("SOS email sent to admin using SMTP_SSL")
                return True
        except Exception as e:
            print(f"SMTP_SSL also failed: {e}")
            return False
            
    except Exception as e:
        print(f"Error sending SOS email: {e}")
        return False

@app.route('/api/send-sos', methods=['POST'])
def send_sos():
    """API endpoint to receive SOS alerts from frontend"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        latitude = data.get('latitude')
        longitude = data.get('longitude')
        address = data.get('address', 'Address not available')
        
        if not latitude or not longitude:
            return jsonify({'success': False, 'error': 'Latitude and longitude are required'}), 400
        
        # Send SOS email to admin
        email_sent = send_sos_email(latitude, longitude, address)
        
        # Store SOS alert in database
        with get_db() as conn:
            conn.execute(
                "INSERT INTO sos_alerts (latitude, longitude, address) VALUES (?, ?, ?)",
                (latitude, longitude, address)
            )
            conn.commit()
        
        if email_sent:
            return jsonify({
                'success': True,
                'message': 'SOS alert sent successfully! Help is on the way.',
                'coordinates': f"{latitude}, {longitude}",
                'address': address
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to send SOS email, but alert has been logged'
            }), 500
            
    except Exception as e:
        print(f"Error in send_sos: {e}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/admin/sos-alerts')
def admin_sos_alerts():
    """Admin page to view SOS alerts"""
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    
    with get_db() as conn:
        alerts = conn.execute(
            "SELECT * FROM sos_alerts ORDER BY timestamp DESC LIMIT 50"
        ).fetchall()
    
    return render_template('admin_sos_alerts.html', alerts=alerts)

@app.route('/admin/dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    
    with get_db() as conn:
        users = conn.execute(
            "SELECT id, email, location FROM users ORDER BY email"
        ).fetchall()
    
    if request.method == 'POST':
        location = request.form.get('location')
        message = request.form.get('message')
        
        if not location or not message:
            return render_template('admin_dashboard.html', 
                                users=users,
                                error="Both location and message are required!")
        
        try:
            with get_db() as conn:
                target_users = conn.execute(
                    "SELECT email FROM users WHERE location = ?", 
                    (location,)
                ).fetchall()
                
                if not target_users:
                    return render_template('admin_dashboard.html', 
                                        users=users,
                                        error=f"No users found in location: {location}")
                
                success_count = 0
                failed_emails = []
                
                for user in target_users:
                    if send_alert_email(user['email'], location, message):
                        success_count += 1
                    else:
                        failed_emails.append(user['email'])
                
                result = {
                    'success': f"Alert sent to {success_count}/{len(target_users)} users in {location}",
                    'failed': failed_emails
                }
                
                return render_template('admin_dashboard.html', 
                                    users=users,
                                    result=result['success'],
                                    last_location=location,
                                    last_message=message)
        
        except Exception as e:
            print(f"Error in admin_dashboard: {str(e)}")  # Debug print
            return render_template('admin_dashboard.html', 
                                users=users,
                                error=f"An error occurred: {str(e)}")

    return render_template('admin_dashboard.html', users=users)

@app.route('/')
def home():
    return render_template('index.html')
def get_initials(email):
    try:
        name = email.split("@")[0]
        parts = name.replace('.', ' ').split()
        initials = "".join([p[0].upper() for p in parts])
        return initials[:2]  # max 2 letters
    except:
        return "U"
@app.context_processor
def inject_user():
    email = session.get('user_email')
    initials = get_initials(email) if email else None
    return dict(user_email=email, user_initials=initials)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        location = request.form.get('location')
        
        if not email or not location:
            flash("Both email and location are required!", "error")
            return redirect(url_for('register'))
        
        try:
            with get_db() as conn:
                conn.execute("INSERT INTO users (email, location) VALUES (?, ?)", (email, location))
                conn.commit()
                
            session['user_email'] = email  
            flash("Registration successful! You'll now receive alerts.", "success")
            return redirect(url_for('home'))
        except sqlite3.IntegrityError:
            flash("This email is already registered!", "error")
            return redirect(url_for('register'))
    
    return render_template('register.html')
@app.route('/logout')
def logout():
    session.pop('user_email', None)
    return redirect(url_for('home'))

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        with get_db() as conn:
            admin = conn.execute(
                "SELECT password FROM admins WHERE username = ?", 
                (username,)
            ).fetchone()
        
        if admin and check_password_hash(admin['password'], password):
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            return render_template('admin_login.html', error="Invalid credentials!")
    
    return render_template('admin_login.html')

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    
    with get_db() as conn:
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('home'))

@app.route('/about')
def about():
    return render_template('aboutus.html')

@app.route('/contacts')
def contacts():
    return render_template('contacts.html')

@app.route('/donation')
def donation():
    return render_template('donation.html')

@app.route('/emergency')
def emergency():
    return render_template('emergency.html')

@app.route('/firstaid')
def firstaid():
    return render_template('firstaid.html')

@app.route('/missing')
def missing():
    return render_template('missing.html')

@app.route('/protection')
def protection():
    return render_template('protecthome.html')  

@app.route('/routes')
def routes():
    return render_template('routes.html')

@app.route('/user')
def user():
    return render_template('user.html')

if __name__ == '__main__':
    app.run(debug=True)