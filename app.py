from flask import Flask, request, render_template, redirect, url_for, session, flash, jsonify
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import json
from datetime import datetime
# from transformers import pipeline  # Commented out to avoid DLL issues
from datetime import datetime
from typing import Dict, Any
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
import os
from dotenv import load_dotenv
import requests
from models import (
    SOSRequest, SOSResponse, ChatRequest, ChatResponse, RumorCheckRequest, RumorCheckResponse,
    UserRegistration, UserLogin, AdminLogin, AdminAlert, MissingPersonReport, SightingReport,
    VolunteerRegistration, VolunteerRoleApplication, MissingPersonSearch, StatusUpdate,
    StandardResponse, ValidationErrorResponse, validate_request_data
)
from pydantic import ValidationError

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = 'your_strong_secret_key_here'  # Change this to a random string
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
db = SQLAlchemy(app)

# Initialize Groq API
groq_api_key = os.getenv('GROQ_API_KEY')
print(f"Groq API Key Status: {'LOADED' if groq_api_key and groq_api_key != 'your_groq_api_key_here' else 'NOT LOADED'}")
if not groq_api_key or groq_api_key == 'your_groq_api_key_here':
    print("Warning: GROQ_API_KEY not configured properly")

def call_groq_api(message):
    """Enhanced Groq API call with multiple model fallbacks"""
    if not groq_api_key or groq_api_key == 'your_groq_api_key_here' or len(groq_api_key) < 10:
        print("Groq API key not configured properly")
        return None
    
    print(f"Calling Groq API with message: {message[:50]}...")
    
    # Available models from your list (in order of preference)
    models = [
        "llama-3.1-8b-instant",
        "llama-3.3-70b-versatile", 
        "meta-llama/llama-4-maverick-17b-128e-instruct",
        "qwen/qwen3-32b"
    ]
    
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {groq_api_key}",
        "Content-Type": "application/json"
    }
    
    # Enhanced system prompt for comprehensive disaster management
    system_prompt = """You are DisasterBot, an expert AI assistant specialized in disaster management and emergency preparedness. 

Your expertise includes:
- Scientific explanations of natural disasters (how they form, causes, mechanisms)
- Emergency response procedures for all natural disasters (earthquakes, floods, hurricanes, wildfires, tornadoes, tsunamis, cyclones, etc.)
- Disaster measurement scales (Richter scale, Saffir-Simpson scale, Enhanced Fujita scale, etc.)
- First aid and medical emergency guidance
- Evacuation planning and safety protocols
- Emergency kit preparation and supplies
- Communication during emergencies
- Post-disaster recovery and safety
- Missing person protocols
- Volunteer coordination during disasters
- Rumor verification and misinformation detection
- Historical disaster events and case studies
- Climate change and disaster patterns
- Building codes and disaster-resistant construction

Answer ALL types of disaster-related questions including:
- "What is..." questions (definitions, explanations)
- "How is... formed" questions (scientific processes)
- "Why does... happen" questions (causes and mechanisms)
- "When did... occur" questions (historical events)
- "Where do... happen" questions (geographical patterns)
- Safety and preparedness questions
- Emergency response procedures

Always provide:
- Accurate, comprehensive information
- Clear explanations appropriate for the question type
- Scientific details when asked about formation/causes
- Safety information when asked about preparedness
- Step-by-step instructions when appropriate
- Relevant examples and case studies
- Calm, informative tone

Respond to EVERY disaster management question with detailed, accurate information. Never redirect to safety measures unless specifically asked about safety."""

    for model in models:
        data = {
            "model": model,
            "messages": [
                {
                    "role": "system",
                    "content": system_prompt
                },
                {
                    "role": "user",
                    "content": message
                }
            ],
            "temperature": 0.7,
            "max_tokens": 1000,
            "top_p": 0.9
        }
        
        try:
            print(f"Trying model: {model}")
            response = requests.post(url, headers=headers, json=data, timeout=20)
            
            if response.status_code == 200:
                result = response.json()
                ai_response = result["choices"][0]["message"]["content"]
                print(f"SUCCESS! Got response from {model}")
                return ai_response
            else:
                print(f"Model {model} failed with status: {response.status_code}")
                print(f"Response: {response.text}")
                continue
                
        except Exception as e:
            print(f"Error with model {model}: {e}")
            continue
    
    print("All models failed, returning None")
    return None


# -------------------------------------------------
# SQLAlchemy models for missing persons feature
# -------------------------------------------------

class MissingPerson(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(120), nullable=False)
    age = db.Column(db.Integer)
    gender = db.Column(db.String(20))
    last_location = db.Column(db.String(255), nullable=False)
    last_seen_date = db.Column(db.Date)
    description = db.Column(db.Text, nullable=False)
    notes = db.Column(db.Text)
    photo_path = db.Column(db.String(255))
    reporter_name = db.Column(db.String(120), nullable=False)
    reporter_contact = db.Column(db.String(120), nullable=False)
    reporter_relation = db.Column(db.String(120), nullable=False)
    status = db.Column(db.String(20), default="pending")  # pending, verified, found, deceased
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Sighting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    missing_person_id = db.Column(db.Integer, db.ForeignKey('missing_person.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    location = db.Column(db.String(255), nullable=False)
    details = db.Column(db.Text, nullable=False)
    contact_info = db.Column(db.String(120), nullable=False)
    media_path = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    missing_person = db.relationship('MissingPerson', backref='sightings')


class Volunteer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(50), nullable=False)
    location = db.Column(db.String(255), nullable=False)
    skills = db.Column(db.Text)
    availability = db.Column(db.String(50), nullable=False)
    interests = db.Column(db.String(255))
    role_applied = db.Column(db.String(120))
    experience = db.Column(db.Text)
    notes = db.Column(db.Text)
    status = db.Column(db.String(20), default="pending")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


with app.app_context():
    db.create_all()

# -------------------------------------------------
# Rumor classifier (Using heuristic approach)
# -------------------------------------------------
# Transformers disabled to avoid DLL issues - using enhanced heuristic approach
rumor_classifier = None
print("[RumorClassifier] Using enhanced heuristic approach (transformers disabled)")

POSITIVE_LABELS = {'real', 'true', 'reliable', 'label_1'}
NEGATIVE_LABELS = {'fake', 'false', 'hoax', 'misleading', 'rumor', 'label_0'}


def analyze_rumor(message: str) -> Dict[str, Any]:
    """Enhanced rumor analysis using heuristic approach"""
    # Always use heuristic classification since transformers is disabled
    return heuristic_classification(message)


def heuristic_classification(message: str) -> Dict[str, Any]:
    """Enhanced heuristic rumor classification for disaster management"""
    lowered = message.lower()
    
    # Enhanced fake news signals
    fake_signals = [
        "forward this to", "share this immediately", "free money", "relief camp closing",
        "pay to get aid", "army confirms via whatsapp", "unverified", "breaking news",
        "urgent forward", "share before deleted", "government hiding", "conspiracy",
        "fake relief", "scam alert", "hoax warning", "rumor mill", "whatsapp forward",
        "viral message", "must share", "before it's removed", "they don't want you to know"
    ]
    
    # Enhanced credible source signals
    real_signals = [
        "government", "official", "ndma", "imd", "who", "reliefweb", "press release",
        "echo daily flash", "un ocha", "ministry", "emergency services", "red cross",
        "disaster management", "official statement", "verified source", "authorities confirm",
        "emergency alert", "official warning", "government advisory", "fema", "cdc",
        "national weather service", "official announcement", "press conference"
    ]
    
    # Check for URLs from credible sources
    credible_domains = [
        "gov.in", "who.int", "redcross.org", "reliefweb.int", "ndma.gov.in",
        "imd.gov.in", "unocha.org", "fema.gov", "cdc.gov", "weather.gov",
        "ready.gov", "redcross.org", "un.org", "unicef.org"
    ]
    
    fake_hits = sum(1 for token in fake_signals if token in lowered)
    real_hits = sum(1 for token in real_signals if token in lowered)
    credible_url = any(domain in lowered for domain in credible_domains)
    length = len(message.split())
    
    # Enhanced scoring algorithm
    if credible_url:
        classification = "Real"
        confidence = 85 + real_hits * 3
        advice = "Contains credible source URL. Still verify with multiple official sources before acting."
    elif fake_hits >= 3 and real_hits == 0:
        classification = "Fake"
        confidence = 75 + fake_hits * 4
        advice = "Strong misinformation indicators detected. Do not share - report as fake news."
    elif real_hits >= 3 and fake_hits <= 1 and length > 30:
        classification = "Real"
        confidence = 70 + real_hits * 5
        advice = "Multiple credible authority indicators. Verify with official channels before acting."
    elif fake_hits > real_hits and fake_hits >= 2:
        classification = "Fake"
        confidence = 60 + (fake_hits - real_hits) * 8
        advice = "Likely misinformation. Cross-check with official disaster management sources."
    elif real_hits > fake_hits and real_hits >= 2:
        classification = "Real"
        confidence = 55 + (real_hits - fake_hits) * 6
        advice = "Appears credible but verify with official disaster management authorities."
    else:
        classification = "Suspicious"
        confidence = 45 + (real_hits - fake_hits) * 3
        advice = "Mixed or unclear signals. Verify with multiple official sources before sharing."

    confidence = max(15, min(confidence, 95))

    return {
        "classification": classification,
        "confidence": round(confidence, 1),
        "raw_label": "ENHANCED_HEURISTIC_ENGINE",
        "advice": advice,
        "reasons": [
            f"Enhanced heuristic analysis completed.",
            f"Credible authority indicators: {real_hits}",
            f"Misinformation indicators: {fake_hits}",
            f"Credible URL detected: {'Yes' if credible_url else 'No'}",
            f"Message length: {length} words"
        ]
    }
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
        # new govs table (government officers that can add/edit reports)
        c.execute('''CREATE TABLE IF NOT EXISTS govs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE,
                    password TEXT
                )''')
        # new disaster reports table
        c.execute('''CREATE TABLE IF NOT EXISTS disaster_reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT,
                    severity TEXT,
                    affected_areas TEXT,
                    timeframe TEXT,
                    advisory TEXT,
                    reported_by TEXT,
                    created_at TEXT
                )''')
        try:
            c.execute("INSERT INTO admins (username, password) VALUES (?, ?)", 
                     ('admin', generate_password_hash('admin123')))
        except sqlite3.IntegrityError:
            pass
        # ensure one sample gov user (change creds in production)
        try:
            c.execute("INSERT INTO govs (username, password) VALUES (?, ?)",
                      ('govuser', generate_password_hash('govpass123')))
        except sqlite3.IntegrityError:
            pass
        conn.commit()

init_db()

# Email configuration 
EMAIL_CONFIG = {
    'sender_email': "nayamatemeet@gmail.com",
    'sender_password': "tjoy glyv olws wdxv",
    'smtp_server': "smtp.gmail.com",
    'smtp_port': 465,
    'use_ssl': True
}

# Admin email for SOS alerts
ADMIN_EMAIL = "nayamatemeet@gmail.com"  

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
        data = request.get_json() or {}
        
        # Validate request data
        is_valid, validated_data, errors = validate_request_data(SOSRequest, data)
        if not is_valid:
            return jsonify(ValidationErrorResponse(
                error="Invalid SOS request data",
                details=errors
            ).dict()), 400
        
        latitude = validated_data['latitude']
        longitude = validated_data['longitude']
        address = validated_data.get('address', 'Address not available')
        
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
            response = SOSResponse(
                success=True,
                message='SOS alert sent successfully! Help is on the way.',
                coordinates=f"{latitude}, {longitude}",
                address=address
            )
            return jsonify(response.dict())
        else:
            response = SOSResponse(
                success=False,
                message='Failed to send SOS email, but alert has been logged',
                error='Email delivery failed'
            )
            return jsonify(response.dict()), 500
            
    except Exception as e:
        print(f"Error in send_sos: {e}")
        response = SOSResponse(
            success=False,
            message='Internal server error',
            error=str(e)
        )
        return jsonify(response.dict()), 500

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


@app.route('/admin/missing')
def admin_missing():
    """Admin view: list and manage all missing person reports."""
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    persons = MissingPerson.query.order_by(MissingPerson.created_at.desc()).all()
    status_choices = ["pending", "verified", "found", "deceased"]
    return render_template(
        'admin_missing.html',
        persons=persons,
        status_choices=status_choices,
    )


@app.route('/admin/missing/<int:person_id>')
def admin_missing_detail(person_id):
    """Admin view: details for a single missing person and their sightings."""
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    person = MissingPerson.query.get_or_404(person_id)
    sightings = (
        Sighting.query.filter_by(missing_person_id=person_id)
        .order_by(Sighting.date.desc())
        .all()
    )
    status_choices = ["pending", "verified", "found", "deceased"]
    return render_template(
        'admin_missing_detail.html',
        person=person,
        sightings=sightings,
        status_choices=status_choices,
    )


@app.route('/admin/missing/<int:person_id>/status', methods=['POST'])
def admin_update_missing_status(person_id):
    """Admin action: update status (e.g., found, deceased) of a missing person."""
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    status = request.form.get('status')
    person = MissingPerson.query.get_or_404(person_id)
    try:
        person.status = status
        db.session.commit()
        flash(f"Status for {person.full_name} updated to {status}.", "success")
    except Exception as e:
        db.session.rollback()
        print(f"[admin_update_missing_status] Error: {e}")
        flash("Could not update status. Please try again.", "error")

    return redirect(request.referrer or url_for('admin_missing'))


@app.route('/admin/missing/<int:person_id>/delete', methods=['POST'])
def admin_delete_missing(person_id):
    """Admin action: permanently delete a missing person record."""
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    person = MissingPerson.query.get_or_404(person_id)
    try:
        db.session.delete(person)
        db.session.commit()
        flash(f"Record for {person.full_name} has been deleted.", "success")
    except Exception as e:

        db.session.rollback()
        print(f"[admin_delete_missing] Error: {e}")
        flash("Could not delete record. Please try again.", "error")

    return redirect(url_for('admin_missing'))


@app.route('/admin/volunteers')
def admin_volunteers():
    """Admin view: list and manage volunteer applications."""
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    volunteers = Volunteer.query.order_by(Volunteer.created_at.desc()).all()
    status_choices = ["pending", "approved", "rejected"]
    return render_template(
        'admin_volunteers.html',
        volunteers=volunteers,
        status_choices=status_choices,
    )


@app.route('/admin/volunteers/<int:vol_id>/status', methods=['POST'])
def admin_update_volunteer_status(vol_id):
    """Admin action: approve/reject a volunteer."""
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    status = request.form.get('status')
    vol = Volunteer.query.get_or_404(vol_id)
    try:
        vol.status = status
        db.session.commit()
        flash(f"Volunteer {vol.full_name} marked as {status}.", "success")
    except Exception as e:
        db.session.rollback()
        print(f"[admin_update_volunteer_status] Error: {e}")
        flash("Could not update volunteer status. Please try again.", "error")

    return redirect(url_for('admin_volunteers'))


@app.route('/admin/volunteers/<int:vol_id>/delete', methods=['POST'])
def admin_delete_volunteer(vol_id):
    """Admin action: delete a volunteer record."""
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    vol = Volunteer.query.get_or_404(vol_id)
    try:
        db.session.delete(vol)
        db.session.commit()
        flash(f"Volunteer {vol.full_name} deleted.", "success")
    except Exception as e:
        db.session.rollback()
        print(f"[admin_delete_volunteer] Error: {e}")
        flash("Could not delete volunteer. Please try again.", "error")

    return redirect(url_for('admin_volunteers'))
@app.route('/api/chat', methods=['POST'])
def chat_with_bot():
    """Enhanced API endpoint for AI chatbot with comprehensive disaster management responses"""
    try:
        data = request.get_json() or {}
        
        # Validate request data
        is_valid, validated_data, errors = validate_request_data(ChatRequest, data)
        if not is_valid:
            return jsonify(ValidationErrorResponse(
                error="Invalid chat request",
                details=errors
            ).dict()), 400
        
        user_message = validated_data['message']
        print(f"User message: {user_message}")
        
        # ALWAYS try Groq API first for ALL disaster management questions
        ai_response = call_groq_api(user_message)
        
        if ai_response and len(ai_response.strip()) > 10:
            print("SUCCESS: Groq API response received")
            return jsonify(ChatResponse(response=ai_response).dict())
        
        print("Groq API failed or returned empty response, using fallback responses")
        
        # Comprehensive fallback responses for all disaster management topics
        comprehensive_responses = {
            # Formation and scientific questions
            'formed': """🌍 HOW NATURAL DISASTERS ARE FORMED:

**EARTHQUAKES:**
- Caused by movement of tectonic plates
- Stress builds up along fault lines
- Sudden release of energy creates seismic waves
- Most occur at plate boundaries

**CYCLONES/HURRICANES:**
- Form over warm ocean waters (26°C+)
- Low pressure system develops
- Coriolis effect causes rotation
- Eye wall forms with strongest winds

**FLOODS:**
- Heavy rainfall exceeds ground absorption
- River overflow from excessive water
- Storm surge from coastal storms
- Dam failures or ice jams

**TORNADOES:**
- Form from severe thunderstorms
- Wind shear creates rotating air column
- Supercell thunderstorms most dangerous
- Temperature and humidity differences crucial

**TSUNAMIS:**
- Underwater earthquakes displace water
- Volcanic eruptions can trigger them
- Landslides into water bodies
- Waves travel at 500+ mph across oceans""",
            
            'cyclone': """🌀 CYCLONE INFORMATION:

**WHAT IS A CYCLONE?**
A cyclone is a large-scale rotating storm system with low atmospheric pressure at its center.

**FORMATION:**
- Forms over warm ocean waters (26°C or higher)
- Low pressure area develops
- Air rises and rotates due to Coriolis effect
- Eye wall forms with strongest winds around calm eye

**TYPES:**
- **Tropical Cyclone:** Forms in tropics (hurricanes, typhoons)
- **Extratropical Cyclone:** Forms in mid-latitudes
- **Polar Cyclone:** Forms near poles

**CLASSIFICATION (Saffir-Simpson Scale):**
- Category 1: 74-95 mph winds
- Category 2: 96-110 mph winds
- Category 3: 111-129 mph winds (major hurricane)
- Category 4: 130-156 mph winds (major hurricane)
- Category 5: 157+ mph winds (catastrophic)

**SAFETY MEASURES:**
- Monitor weather alerts
- Evacuate if ordered
- Secure outdoor items
- Stock emergency supplies
- Stay indoors during storm""",
            'hello': "Hello! I'm DisasterBot, your comprehensive AI assistant for disaster management and emergency preparedness. I can answer questions about how disasters form, what they are, safety measures, emergency procedures, historical events, measurement scales, and much more. Ask me anything about disaster management!",
            
            'earthquake': """🚨 EARTHQUAKE SAFETY PROTOCOL:

**DURING THE EARTHQUAKE:**
1. DROP to hands and knees immediately
2. COVER your head and neck under a desk/table
3. HOLD ON to your shelter and protect yourself
4. Stay away from windows, mirrors, and heavy objects
5. If outdoors, move away from buildings and power lines
6. If in bed, stay there and cover with pillow

**AFTER THE EARTHQUAKE:**
1. Check for injuries and provide first aid
2. Check for gas leaks and turn off gas if detected
3. Be prepared for aftershocks
4. Use stairs, never elevators
5. Stay away from damaged buildings
6. Listen to emergency broadcasts

**RICHTER SCALE EXPLAINED:**
- Measures earthquake magnitude (energy released)
- Scale: 1-10+ (logarithmic scale)
- 3.0-3.9: Often felt, rarely causes damage
- 4.0-4.9: Noticeable shaking, minor damage
- 5.0-5.9: Can cause damage to buildings
- 6.0-6.9: Strong earthquake, considerable damage
- 7.0-7.9: Major earthquake, serious damage
- 8.0+: Great earthquake, massive destruction

**EMERGENCY KIT ESSENTIALS:**
- Water (1 gallon per person per day for 3+ days)
- Non-perishable food
- Flashlight and batteries
- First aid kit
- Emergency radio
- Important documents""",
            
            'flood': """🌊 FLOOD SAFETY GUIDELINES:

**IMMEDIATE ACTIONS:**
1. Move to higher ground immediately
2. NEVER walk through flood water - 6 inches can knock you down
3. Turn around, don't drown - find alternate routes
4. Turn off utilities if instructed by authorities
5. Stay away from downed power lines

**SAFETY RULES:**
- Don't drive through flooded roads
- Avoid walking in moving water
- Stay away from storm drains
- Listen to emergency broadcasts
- Have evacuation plan ready

**AFTER FLOODING:**
- Don't return until authorities say it's safe
- Wear protective clothing when cleaning
- Throw away contaminated food
- Document damage for insurance""",
            
            'fire': """🔥 FIRE EMERGENCY PROCEDURES:

**EVACUATION STEPS:**
1. Evacuate immediately if ordered by authorities
2. Close all windows and doors behind you
3. Use wet cloth over nose/mouth if smoke present
4. Stay low to avoid smoke inhalation
5. Have multiple escape routes planned
6. Don't use elevators during fire emergencies
7. Meet at designated family meeting point
8. Call emergency services once you're safe

**WILDFIRE PREPARATION:**
- Create defensible space around property
- Have go-bag ready with essentials
- Know evacuation routes
- Monitor air quality
- Sign up for emergency alerts

**HOME FIRE SAFETY:**
- Install smoke detectors
- Have fire extinguishers
- Practice escape plans
- Keep exits clear""",
            
            'hurricane': """🌀 HURRICANE PREPAREDNESS:

**BEFORE THE STORM:**
1. Monitor weather alerts and evacuation orders
2. Secure outdoor items that could become projectiles
3. Board up windows with plywood
4. Stock up on water (1 gallon per person per day for 7+ days)
5. Have battery-powered radio and flashlights
6. Fill bathtubs with water for sanitation
7. Charge all electronic devices
8. Have cash on hand

**DURING THE HURRICANE:**
- Stay indoors away from windows
- Don't go outside during eye of storm
- Listen to emergency broadcasts
- Stay in interior room on lowest floor

**AFTER THE HURRICANE:**
- Wait for all-clear from authorities
- Watch for flooding and downed power lines
- Document damage for insurance""",
            
            'tornado': """🌪️ TORNADO SAFETY:

**WARNING SIGNS:**
- Large, dark, rotating clouds
- Loud roar like freight train
- Large hail
- Wall cloud or funnel cloud

**IMMEDIATE ACTIONS:**
1. Seek shelter in lowest floor interior room
2. Stay away from windows
3. Get under sturdy furniture
4. Cover yourself with blankets/mattress
5. If outdoors, lie flat in low area and cover head
6. Never try to outrun tornado in vehicle

**SAFE PLACES:**
- Basement or storm cellar
- Interior bathroom or closet
- Center hallway on lowest floor

**AVOID:**
- Mobile homes
- Large roof areas (gyms, auditoriums)
- Upper floors""",
            
            'emergency': """🚨 EMERGENCY CONTACTS & PROCEDURES:

**EMERGENCY NUMBERS:**
- USA: 911 (Police, Fire, Medical)
- India: 100 (Police), 101 (Fire), 102 (Ambulance)
- Europe: 112 (Universal Emergency)
- UK: 999 (Emergency Services)

**WHEN CALLING EMERGENCY SERVICES:**
1. Stay calm and speak clearly
2. Give exact location/address
3. Describe the emergency
4. Follow dispatcher instructions
5. Don't hang up until told to do so

**USE SOS BUTTON:** On this website for location-based alerts

**EMERGENCY PREPAREDNESS:**
- Know your local emergency evacuation routes
- Have emergency contacts readily available
- Keep important documents accessible
- Maintain emergency communication plan""",
            
            'kit': """📦 COMPREHENSIVE EMERGENCY KIT:

**WATER & FOOD:**
- 1 gallon water per person per day (3+ day supply)
- Non-perishable food for 3+ days
- Manual can opener
- Paper plates, cups, utensils

**TOOLS & SUPPLIES:**
- Flashlight and extra batteries
- Battery/hand-crank radio
- Multi-tool or Swiss Army knife
- Duct tape and plastic sheeting
- Matches in waterproof container

**FIRST AID & MEDICATIONS:**
- Complete first aid kit
- Prescription medications (7+ day supply)
- Over-the-counter medications
- Medical supplies for special needs

**DOCUMENTS & COMMUNICATION:**
- Copies of important documents (waterproof container)
- Emergency contact information
- Cash in small bills
- Cell phone chargers/power banks

**CLOTHING & HYGIENE:**
- Extra clothing and sturdy shoes
- Blankets or sleeping bags
- Personal hygiene items
- Sanitation supplies""",
            
            'missing': """👥 MISSING PERSON PROTOCOLS:

**IMMEDIATE ACTIONS:**
1. Contact local police immediately (don't wait 24 hours)
2. File report with detailed information
3. Provide recent photos and description
4. Share last known location and circumstances

**SEARCH EFFORTS:**
- Contact hospitals and local shelters
- Use social media responsibly to spread awareness
- Coordinate with local search and rescue teams
- Check with friends, family, and coworkers

**INFORMATION TO PROVIDE:**
- Full name, age, physical description
- Last seen location and time
- Clothing worn
- Medical conditions or medications
- Vehicle information if applicable

**USE OUR PLATFORM:**
- Report missing persons on our Missing Persons page
- Upload photos and detailed descriptions
- Receive updates on search efforts

**KEEP DETAILED RECORDS:**
- Document all search efforts
- Save all communications
- Work with authorities""",
            
            'evacuation': """🚪 EVACUATION PLANNING:

**EVACUATION ROUTES:**
1. Know primary and alternate evacuation routes
2. Practice routes regularly with family
3. Identify shelter locations along routes
4. Keep vehicle fueled and maintained

**FAMILY COMMUNICATION PLAN:**
- Designate meeting points (local and out-of-area)
- Choose out-of-state contact person
- Ensure everyone knows the plan
- Practice the plan regularly

**GRAB-AND-GO BAG:**
- Important documents (copies)
- Medications and medical supplies
- Change of clothes
- Emergency cash
- Phone chargers
- Comfort items for children

**PET EVACUATION:**
- Know pet-friendly shelters
- Have pet carriers ready
- Keep pet supplies packed
- Ensure pets have ID tags

**SPECIAL CONSIDERATIONS:**
- Plan for elderly or disabled family members
- Know workplace evacuation procedures
- Coordinate with neighbors
- Stay informed through emergency alerts""",
            
            'first aid': """🏥 FIRST AID ESSENTIALS:

**BASIC LIFE SUPPORT:**
1. Check for responsiveness and breathing
2. Call for emergency medical help (911)
3. Perform CPR if trained and necessary
4. Use AED if available and trained

**BLEEDING CONTROL:**
- Apply direct pressure with clean cloth
- Elevate injured area above heart if possible
- Don't remove embedded objects
- Apply pressure to pressure points if needed

**SHOCK TREATMENT:**
- Keep person lying down
- Elevate legs if no spinal injury
- Keep person warm
- Monitor breathing and pulse

**BURNS:**
- Cool with water (not ice)
- Remove from heat source
- Don't break blisters
- Cover with sterile gauze

**CHOKING:**
- Perform Heimlich maneuver
- For infants: back blows and chest thrusts
- Continue until object dislodged or person unconscious

**IMPORTANT:** Get proper first aid and CPR training from certified instructors""",
            
            'shelter': """🏠 EMERGENCY SHELTER INFORMATION:

**FINDING SHELTERS:**
- Identify local emergency shelters in advance
- Know pet-friendly shelter locations
- Understand shelter capacity and rules
- Have backup shelter options

**WHAT TO BRING:**
- Identification documents
- Essential medications
- Comfort items for children
- Sleeping materials if allowed
- Personal hygiene items

**SHELTER ETIQUETTE:**
- Follow all shelter rules and guidelines
- Respect other evacuees' space
- Help with shelter operations if able
- Keep noise levels down

**REGISTRATION:**
- Register with Red Cross family reunification
- Notify family/friends of your location
- Keep emergency contacts updated

**SPECIAL NEEDS:**
- Medical equipment and supplies
- Dietary restrictions information
- Accessibility requirements
- Service animal documentation""",
            
            'communication': """📱 EMERGENCY COMMUNICATION:

**MULTIPLE ALERT SOURCES:**
- Weather radio (NOAA Weather Radio)
- Emergency alert systems on phone
- Local news and social media
- Community warning systems

**COMMUNICATION PLAN:**
- Designate out-of-area contact person
- Share plan with all family members
- Include work and school contacts
- Update plan regularly

**DURING EMERGENCIES:**
- Use text messages when phone lines busy
- Keep messages brief
- Conserve phone battery
- Use social media check-in features

**BACKUP COMMUNICATION:**
- Two-way radios for family
- Ham radio for community communication
- Satellite communicators for remote areas
- Written messages and meeting points

**STAYING INFORMED:**
- Sign up for local emergency alerts
- Follow official emergency management accounts
- Verify information from multiple sources
- Don't spread unconfirmed information"""
        }
        
        user_lower = user_message.lower()
        
        # Check for formation/scientific questions first
        formation_keywords = ['formed', 'form', 'formation', 'cause', 'caused', 'how is', 'how are', 'how do', 'how does', 'why do', 'why does', 'what causes']
        if any(keyword in user_lower for keyword in formation_keywords):
            if 'cyclone' in user_lower or 'hurricane' in user_lower:
                return jsonify(ChatResponse(response=comprehensive_responses['cyclone']).dict())
            elif any(term in user_lower for term in ['earthquake', 'seismic', 'tremor']):
                return jsonify(ChatResponse(response="""🌍 HOW EARTHQUAKES ARE FORMED:

**TECTONIC PLATE MOVEMENT:**
Earthquakes occur due to the movement of tectonic plates that make up Earth's crust.

**THE PROCESS:**
1. **Stress Buildup:** Tectonic plates constantly move, creating stress along fault lines
2. **Friction:** Plates get stuck due to friction, but stress continues to build
3. **Breaking Point:** When stress exceeds rock strength, sudden movement occurs
4. **Energy Release:** Stored energy releases as seismic waves
5. **Wave Propagation:** Seismic waves travel through Earth, causing ground shaking

**TYPES OF PLATE BOUNDARIES:**
- **Transform:** Plates slide past each other (San Andreas Fault)
- **Convergent:** Plates collide (subduction zones)
- **Divergent:** Plates move apart (mid-ocean ridges)

**DEPTH FACTORS:**
- **Shallow earthquakes:** 0-70 km deep, most destructive
- **Intermediate:** 70-300 km deep
- **Deep:** 300-700 km deep, less surface damage

**RICHTER SCALE:** Measures magnitude (energy released)
- Each whole number = 10x more ground motion
- Each whole number = 32x more energy release""").dict())
            else:
                return jsonify(ChatResponse(response=comprehensive_responses['formed']).dict())
        
        # Check for specific disaster keywords and provide comprehensive response
        for key, value in comprehensive_responses.items():
            if key in user_lower:
                return jsonify(ChatResponse(response=value).dict())
        
        # Check for additional disaster-related keywords
        additional_keywords = {
            'richter': """📊 RICHTER SCALE EXPLAINED:

**WHAT IS THE RICHTER SCALE?**
The Richter Scale measures the magnitude of earthquakes based on the energy released. It was developed by Charles F. Richter in 1935.

**SCALE BREAKDOWN:**
- **1.0-2.9:** Micro earthquakes - Not felt by people
- **3.0-3.9:** Minor - Often felt, rarely causes damage
- **4.0-4.9:** Light - Noticeable shaking, dishes rattle, minor damage
- **5.0-5.9:** Moderate - Can cause damage to poorly built structures
- **6.0-6.9:** Strong - Considerable damage to buildings, infrastructure
- **7.0-7.9:** Major - Serious damage over large areas
- **8.0-8.9:** Great - Massive destruction, ground waves visible
- **9.0+:** Rare great earthquakes - Devastating over vast areas

**IMPORTANT FACTS:**
- Logarithmic scale: Each whole number = 10x more energy
- Magnitude 7.0 releases 1,000x more energy than 5.0
- Most destructive earthquakes are 6.0+ magnitude
- Location and depth also affect damage levels

**RECENT MAJOR EARTHQUAKES:**
- 2011 Japan: 9.1 magnitude (tsunami)
- 2004 Indian Ocean: 9.1-9.3 magnitude
- 1906 San Francisco: 7.9 magnitude

**SAFETY TIP:** Magnitude alone doesn't determine damage - depth, location, and building standards matter too!""",
            
            'magnitude': """The earthquake magnitude measures the energy released during an earthquake. The Richter Scale is the most common measurement, ranging from 1-10+. Higher numbers mean more powerful earthquakes. A magnitude 7.0 earthquake releases about 1,000 times more energy than a 5.0 earthquake.""",
            'tsunami': """🌊 TSUNAMI SAFETY:

**WARNING SIGNS:**
- Strong earthquake lasting 20+ seconds
- Ocean water receding unusually far
- Loud ocean roar
- Official tsunami warning

**IMMEDIATE ACTIONS:**
1. Move to high ground immediately (100+ feet elevation)
2. Move inland at least 2 miles if possible
3. Don't wait for official warning
4. Help others who need assistance
5. Stay away from coast until all-clear given

**SAFETY RULES:**
- Don't go to beach to watch tsunami
- Don't return to evacuation zone until authorities say safe
- Be aware of multiple waves
- Stay tuned to emergency broadcasts

**PREPARATION:**
- Know evacuation routes and high ground locations
- Practice evacuation with family
- Have emergency kit ready
- Sign up for tsunami alerts""",
            
            'landslide': """⛰️ LANDSLIDE SAFETY:

**WARNING SIGNS:**
- Changes in landscape (new cracks, bulges)
- Water breaking through ground surface
- Unusual sounds (trees cracking, boulders knocking)
- Tilting trees, poles, walls
- Sudden decrease in creek water levels

**IMMEDIATE ACTIONS:**
1. Evacuate immediately if ground movement detected
2. Move away from path of landslide
3. Don't return until area declared safe
4. Listen for unusual sounds indicating movement

**SAFETY MEASURES:**
- Avoid building on steep slopes
- Plant ground cover on slopes
- Install proper drainage
- Don't ignore small slides

**AFTER LANDSLIDE:**
- Stay away from slide area
- Watch for flooding
- Report broken utility lines
- Replant damaged ground cover""",
            
            'blizzard': """❄️ BLIZZARD PREPAREDNESS:

**BEFORE THE STORM:**
- Stock up on food, water, medications
- Have heating alternatives ready
- Charge electronic devices
- Bring pets indoors
- Clear gutters and drains

**DURING BLIZZARD:**
- Stay indoors
- Conserve heat by closing off unused rooms
- Avoid overexertion when shoveling
- Check on neighbors safely
- Keep fresh air intake clear if using generator

**WINTER DRIVING:**
- Avoid travel during storm
- Keep winter emergency kit in car
- Tell someone your travel plans
- Stay with vehicle if stranded

**POWER OUTAGES:**
- Use flashlights, not candles
- Keep refrigerator/freezer closed
- Use generator outdoors only
- Dress in layers to stay warm""",
            
            'heat wave': """🌡️ HEAT WAVE SAFETY:

**STAYING COOL:**
- Stay in air-conditioned areas
- Drink plenty of water
- Avoid alcohol and caffeine
- Wear lightweight, light-colored clothing
- Take cool showers or baths

**OUTDOOR SAFETY:**
- Avoid outdoor activities during peak hours (10am-6pm)
- Seek shade when outside
- Wear sunscreen and hat
- Take frequent breaks in cool areas

**HEALTH MONITORING:**
- Watch for heat exhaustion symptoms
- Check on elderly neighbors and relatives
- Never leave children or pets in vehicles
- Know signs of heat stroke

**HEAT EMERGENCY SIGNS:**
- High body temperature
- Confusion or altered mental state
- Hot, dry skin or profuse sweating
- Rapid pulse
- Nausea or vomiting

**CALL 911 IMMEDIATELY** if someone shows heat stroke symptoms""",
            
            'power outage': """⚡ POWER OUTAGE RESPONSE:

**IMMEDIATE ACTIONS:**
1. Check if outage is widespread or just your home
2. Report outage to utility company
3. Turn off/unplug electrical appliances
4. Keep refrigerator and freezer doors closed

**LIGHTING & SAFETY:**
- Use flashlights, not candles
- Have battery-powered radio
- Keep extra batteries available
- Use battery-powered or hand-crank radio

**FOOD SAFETY:**
- Refrigerated food safe for 4 hours without power
- Frozen food safe for 24-48 hours in full freezer
- Use coolers with ice for perishables
- Don't eat food that smells bad or feels warm

**GENERATOR SAFETY:**
- Use generators outdoors only
- Keep away from windows and doors
- Don't connect to home wiring
- Have carbon monoxide detector

**MEDICAL DEVICES:**
- Have backup power for essential medical equipment
- Contact medical provider about power-dependent devices
- Keep extra batteries for devices"""
        }
        
        # Check additional keywords
        for keyword, response in additional_keywords.items():
            if keyword in user_lower:
                return jsonify(ChatResponse(response=response).dict())
        
        # Check for earthquake-related terms
        earthquake_terms = ['seismic', 'tremor', 'aftershock', 'epicenter', 'fault line']
        if any(term in user_lower for term in earthquake_terms):
            return jsonify(ChatResponse(response=comprehensive_responses['earthquake']).dict())
        
        # Default comprehensive response for any disaster-related query
        default_response = """🚨 DISASTER MANAGEMENT ASSISTANT

I'm DisasterBot, your comprehensive disaster management assistant. I can provide detailed guidance on:

🌪️ **NATURAL DISASTERS:**
- Earthquakes, Floods, Hurricanes, Tornadoes
- Tsunamis, Wildfires, Landslides, Blizzards
- Heat Waves, Power Outages

🏥 **EMERGENCY RESPONSE:**
- First Aid & Medical Emergencies
- Emergency Communication
- Evacuation Planning & Routes

📦 **PREPAREDNESS:**
- Emergency Kit Preparation
- Family Emergency Plans
- Shelter Information

👥 **COMMUNITY SUPPORT:**
- Missing Person Protocols
- Volunteer Coordination
- Rumor Verification

**Ask me about any specific disaster or emergency topic, and I'll provide detailed, actionable guidance to keep you and your community safe!**

What specific disaster management topic would you like to know about?"""
        
        return jsonify(ChatResponse(response=default_response).dict())
        
    except Exception as e:
        print(f"Chat error: {e}")
        return jsonify(ChatResponse(
            response='I\'m here to help with disaster management and emergency preparedness. Please try asking your question again, and I\'ll provide comprehensive guidance to keep you safe.'
        ).dict()), 200

@app.route('/api/rumor-check', methods=['POST'])
def rumor_check():
    """API endpoint to classify disaster-related rumors."""
    try:
        data = request.get_json() or {}
        
        # Validate request data
        is_valid, validated_data, errors = validate_request_data(RumorCheckRequest, data)
        if not is_valid:
            return jsonify(ValidationErrorResponse(
                error="Invalid rumor check request",
                details=errors
            ).dict()), 400
        
        message = validated_data['message']
        context = validated_data.get('context', '')
        source = validated_data.get('source', '')

        combined_text = message
        if context:
            combined_text = f"{message}\nContext: {context}"
        if source:
            combined_text = f"{combined_text}\nSource: {source}"

        result = analyze_rumor(combined_text)
        status_code = 200 if result.get("classification") != "Unavailable" else 503

        response = RumorCheckResponse(
            classification=result["classification"],
            confidence=result["confidence"],
            advice=result["advice"],
            raw_label=result["raw_label"],
            reasons=result["reasons"],
            evaluated_at=datetime.utcnow().isoformat() + "Z"
        )
        
        return jsonify(response.dict()), status_code
        
    except Exception as e:
        print(f"Rumor check error: {e}")
        response = RumorCheckResponse(
            classification="Error",
            confidence=0.0,
            advice="Unable to process request at this time",
            raw_label="ERROR",
            reasons=["System error occurred"],
            evaluated_at=datetime.utcnow().isoformat() + "Z",
            error=str(e)
        )
        return jsonify(response.dict()), 500
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
        data = {
            'email': request.form.get('email'),
            'location': request.form.get('location')
        }
        
        # Validate request data
        is_valid, validated_data, errors = validate_request_data(UserRegistration, data)
        if not is_valid:
            error_msg = "Registration failed: " + "; ".join(errors.values())
            flash(error_msg, "error")
            return redirect(url_for('register'))
        
        try:
            with get_db() as conn:
                conn.execute("INSERT INTO users (email, location) VALUES (?, ?)", 
                           (validated_data['email'], validated_data['location']))
                conn.commit()
                
            session['user_email'] = validated_data['email']
            flash("Registration successful! You'll now receive alerts.", "success")
            return redirect(url_for('home'))
        except sqlite3.IntegrityError:
            flash("This email is already registered!", "error")
            return redirect(url_for('register'))
        except Exception as e:
            print(f"Registration error: {e}")
            flash("Registration failed. Please try again.", "error")
            return redirect(url_for('register'))
    
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login existing user by email only."""
    if request.method == 'POST':
        email = request.form.get('email')
        if not email:
            flash("Email is required to login.", "error")
            return redirect(url_for('login'))

        with get_db() as conn:
            user = conn.execute(
                "SELECT id FROM users WHERE email = ?", (email,)
            ).fetchone()

        if user:
            session['user_email'] = email
            flash("Logged in successfully.", "success")
            return redirect(url_for('home'))
        else:
            flash("This email is not registered. Please register first.", "error")
            return redirect(url_for('register'))

    return render_template('login.html')
@app.route('/logout')
def logout():
    session.pop('user_email', None)
    return redirect(url_for('home'))

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    admin_error = None
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
            admin_error = "Invalid credentials!"
    
    return render_template('login.html', admin_error=admin_error)

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

@app.route('/missing', methods=['GET'])
def missing():
    """Public page: search and list missing persons."""
    name = request.args.get('name', '').strip()
    location = request.args.get('location', '').strip()
    age_range = request.args.get('age_range', '').strip()

    query = MissingPerson.query.filter(
        MissingPerson.status.in_(["pending", "verified"])
    )

    if name:
        query = query.filter(MissingPerson.full_name.ilike(f"%{name}%"))
    if location:
        query = query.filter(MissingPerson.last_location.ilike(f"%{location}%"))

    if age_range:
        if age_range == "0-12":
            query = query.filter(MissingPerson.age >= 0, MissingPerson.age <= 12)
        elif age_range == "13-17":
            query = query.filter(MissingPerson.age >= 13, MissingPerson.age <= 17)
        elif age_range == "18-59":
            query = query.filter(MissingPerson.age >= 18, MissingPerson.age <= 59)
        elif age_range == "60+":
            query = query.filter(MissingPerson.age >= 60)

    persons = query.order_by(MissingPerson.created_at.desc()).all()

    return render_template(
        'missing.html',
        persons=persons,
        name=name,
        location=location,
        age_range=age_range,
    )


@app.route('/missing/report', methods=['POST'])
def report_missing():
    """Handle submission of a new missing person report."""
    form = request.form
    photo = request.files.get('missing-photo')

    # Prepare data for validation
    data = {
        'full_name': form.get('missing-name'),
        'age': int(form.get('missing-age')) if form.get('missing-age') else None,
        'gender': form.get('missing-gender'),
        'last_location': form.get('missing-location'),
        'last_seen_date': form.get('missing-date'),
        'description': form.get('missing-description'),
        'notes': form.get('missing-notes'),
        'reporter_name': form.get('reporter-name'),
        'reporter_contact': form.get('reporter-contact'),
        'reporter_relation': form.get('reporter-relation')
    }
    
    # Validate request data
    is_valid, validated_data, errors = validate_request_data(MissingPersonReport, data)
    if not is_valid:
        error_msg = "Report submission failed: " + "; ".join(errors.values())
        flash(error_msg, "error")
        return redirect(url_for('missing'))

    photo_path = None
    if photo and photo.filename:
        filename = secure_filename(photo.filename)
        upload_dir = app.config['UPLOAD_FOLDER']
        os.makedirs(upload_dir, exist_ok=True)
        save_path = os.path.join(upload_dir, filename)
        photo.save(save_path)
        photo_path = os.path.join('uploads', filename)

    try:
        person = MissingPerson(
            full_name=validated_data['full_name'],
            age=validated_data.get('age'),
            gender=validated_data.get('gender'),
            last_location=validated_data['last_location'],
            last_seen_date=validated_data.get('last_seen_date'),
            description=validated_data['description'],
            notes=validated_data.get('notes'),
            photo_path=photo_path,
            reporter_name=validated_data['reporter_name'],
            reporter_contact=validated_data['reporter_contact'],
            reporter_relation=validated_data['reporter_relation'],
            status='pending',
        )
        db.session.add(person)
        db.session.commit()
        flash('Missing person report submitted successfully. Admin will review it.', 'success')
    except Exception as e:
        db.session.rollback()
        print(f"[report_missing] Error: {e}")
        flash('There was an error submitting the report. Please try again.', 'error')

    return redirect(url_for('missing'))


@app.route('/sighting/report', methods=['POST'])
def report_sighting():
    """Handle submission of a sighting report for a missing person."""
    form = request.form
    media = request.files.get('sighting-photo')

    media_path = None
    if media and media.filename:
        filename = secure_filename(media.filename)
        upload_dir = app.config['UPLOAD_FOLDER']
        os.makedirs(upload_dir, exist_ok=True)
        save_path = os.path.join(upload_dir, filename)
        media.save(save_path)
        media_path = os.path.join('uploads', filename)

    try:
        date_str = form.get('sighting-date')
        sighting_date = datetime.strptime(date_str, '%Y-%m-%d') if date_str else None

        sighting = Sighting(
            missing_person_id=int(form.get('missing_person_id')),
            date=sighting_date,
            location=form.get('sighting-location'),
            details=form.get('sighting-details'),
            contact_info=form.get('sighting-contact'),
            media_path=media_path,
        )
        db.session.add(sighting)
        db.session.commit()
        flash(
            'Thank you for reporting this sighting. This information could be crucial.',
            'success',
        )
    except Exception as e:
        db.session.rollback()
        print(f"[report_sighting] Error: {e}")
        flash('There was an error submitting the sighting. Please try again.', 'error')

    return redirect(url_for('missing'))

@app.route('/protection')
def protection():
    return render_template('protecthome.html')  

@app.route('/routes')
def routes():
    return render_template('routes.html')

@app.route('/volunteer/register', methods=['POST'])
def register_volunteer():
    """Handle general volunteer registration."""
    if not session.get('user_email'):
        flash('Please register or log in before applying as a volunteer.', 'error')
        return redirect(url_for('register'))

    form = request.form
    try:
        interests_list = form.getlist('vol-interests')
        interests = ",".join(interests_list) if interests_list else None

        volunteer = Volunteer(
            full_name=form.get('vol-name'),
            email=form.get('vol-email'),
            phone=form.get('vol-phone'),
            location=form.get('vol-location'),
            skills=form.get('vol-skills'),
            availability=form.get('vol-availability'),
            interests=interests,
        )
        db.session.add(volunteer)
        db.session.commit()
        flash('Thank you for your volunteer application!', 'success')
    except Exception as e:
        db.session.rollback()
        print(f"[register_volunteer] Error: {e}")
        flash('There was an error submitting your application. Please try again.', 'error')

    return redirect(url_for('missing'))


@app.route('/volunteer/apply-role', methods=['POST'])
def apply_role():
    """Handle volunteer applications for specific roles from the modal."""
    if not session.get('user_email'):
        flash('Please register or log in before applying as a volunteer.', 'error')
        return redirect(url_for('register'))

    form = request.form
    try:
        # location/skills are optional for role-based applications, but the model
        # requires a non-null location, so store a placeholder description.
        volunteer = Volunteer(
            full_name=form.get('vol-specific-name'),
            email=form.get('vol-specific-email'),
            phone=form.get('vol-specific-phone'),
            location=form.get('vol-location') or 'Not specified',
            skills=None,
            availability='immediate' if form.get('immediate') == 'yes' else 'flexible',
            interests=None,
            role_applied=form.get('role_name'),
            experience=form.get('vol-specific-experience'),
            notes=form.get('vol-specific-notes'),
        )
        db.session.add(volunteer)
        db.session.commit()
        flash(
            f"Application submitted for {form.get('role_name')}. We'll contact you soon.",
            'success',
        )
    except Exception as e:
        db.session.rollback()
        print(f"[apply_role] Error: {e}")
        flash('There was an error submitting your application. Please try again.', 'error')

    return redirect(url_for('missing'))

# ---------------------------
# Admin: Reports CRUD
# ---------------------------
@app.route('/admin/reports')
def admin_reports():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    with get_db() as conn:
        reports = conn.execute(
            "SELECT * FROM disaster_reports ORDER BY created_at DESC"
        ).fetchall()

    return render_template('admin_reports.html', reports=reports)


@app.route('/admin/view_report/<int:report_id>')
def admin_view_report(report_id):
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    with get_db() as conn:
        report = conn.execute("SELECT * FROM disaster_reports WHERE id=?", (report_id,)).fetchone()

    return render_template('view_report.html', report=report)

@app.route('/admin/edit_report/<int:report_id>', methods=['GET', 'POST'])
def admin_edit_report(report_id):
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    with get_db() as conn:
        report = conn.execute(
            "SELECT * FROM disaster_reports WHERE id = ?", (report_id,)
        ).fetchone()

        if not report:
            flash("Report not found.", "error")
            return redirect(url_for('admin_reports'))

        if request.method == 'POST':
            title = request.form.get('title')
            severity = request.form.get('severity')
            affected = request.form.get('affected_areas')
            timeframe = request.form.get('timeframe')
            advisory = request.form.get('advisory')

            conn.execute("""
                UPDATE disaster_reports
                SET title=?, severity=?, affected_areas=?, timeframe=?, advisory=?
                WHERE id=?
            """, (title, severity, affected, timeframe, advisory, report_id))

            conn.commit()
            flash("Report updated!", "success")
            return redirect(url_for('admin_reports'))

    return render_template('admin_edit_report.html', report=report)


@app.route('/admin/delete_report/<int:report_id>', methods=['POST'])
def admin_delete_report(report_id):
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    with get_db() as conn:
        conn.execute("DELETE FROM disaster_reports WHERE id=?", (report_id,))
        conn.commit()

    flash("Report deleted.", "success")
    return redirect(url_for('admin_reports'))


# ---------------------------
# Gov login + report flow
# ---------------------------
@app.route('/gov/login', methods=['GET', 'POST'])
def gov_login():
    # This is separate from admin. Gov users can add/edit reports (but cannot delete)
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        with get_db() as conn:
            gov = conn.execute("SELECT * FROM govs WHERE username = ?", (username,)).fetchone()
        if gov and check_password_hash(gov['password'], password):
            session['gov_logged_in'] = True
            session['gov_username'] = username
            # If there is a 'next' param, redirect there
            next_url = request.args.get('next') or url_for('gov_report_form')
            return redirect(next_url)
        else:
            return render_template('gov_login.html', error="Invalid government credentials!")
    # GET
    return render_template('gov_login.html')

@app.route('/gov/logout')
def gov_logout():
    session.pop('gov_logged_in', None)
    session.pop('gov_username', None)
    return redirect(url_for('home'))

@app.route('/gov/reports')
def gov_reports():
    if not session.get('gov_logged_in'):
        return redirect(url_for('gov_login'))

    username = session['gov_username']

    with get_db() as conn:
        reports = conn.execute(
            "SELECT * FROM disaster_reports WHERE reported_by = ? ORDER BY created_at DESC",
            (username,)
        ).fetchall()

    return render_template('gov_reports.html', reports=reports)

@app.route('/gov/delete_report/<int:report_id>', methods=['POST'])
def gov_delete_report(report_id):
    if not session.get('gov_logged_in'):
        return redirect(url_for('gov_login'))

    username = session['gov_username']

    with get_db() as conn:
        # Ensure gov only deletes their own report
        report = conn.execute(
            "SELECT reported_by FROM disaster_reports WHERE id = ?", (report_id,)
        ).fetchone()

        if report and report['reported_by'] == username:
            conn.execute("DELETE FROM disaster_reports WHERE id=?", (report_id,))
            conn.commit()
            flash("Report deleted successfully.", "success")
        else:
            flash("You can delete only your own reports.", "error")

    return redirect(url_for('gov_reports'))

@app.route('/gov/edit_report/<int:report_id>', methods=['GET', 'POST'])
def gov_edit_report(report_id):
    if not session.get('gov_logged_in'):
        return redirect(url_for('gov_login'))

    username = session['gov_username']

    with get_db() as conn:
        # Fetch the report
        report = conn.execute(
            "SELECT * FROM disaster_reports WHERE id = ?", (report_id,)
        ).fetchone()

        # Check permission
        if not report or report['reported_by'] != username:
            flash("You are not allowed to edit this report.", "error")
            return redirect(url_for('gov_reports'))

        # On POST: update
        if request.method == 'POST':
            title = request.form.get('title')
            severity = request.form.get('severity')
            affected = request.form.get('affected_areas')
            timeframe = request.form.get('timeframe')
            advisory = request.form.get('advisory')

            conn.execute("""
                UPDATE disaster_reports
                SET title = ?, severity = ?, affected_areas = ?, timeframe = ?, advisory = ?
                WHERE id = ?
            """, (title, severity, affected, timeframe, advisory, report_id))
            conn.commit()

            flash("Report updated successfully!", "success")
            return redirect(url_for('gov_reports'))

    return render_template('gov_edit_report.html', report=report)


@app.route('/gov/report', methods=['GET', 'POST'])
def gov_report_form():
    # Only gov users can access report form
    if not session.get('gov_logged_in'):
        # redirect to gov login with next param so after login they return here
        return redirect(url_for('gov_login', next=url_for('gov_report_form')))
    if request.method == 'POST':
        title = request.form.get('title')
        severity = request.form.get('severity') or 'LOW'
        affected_areas = request.form.get('affected_areas')
        timeframe = request.form.get('timeframe')
        advisory = request.form.get('advisory')
        reported_by = session.get('gov_username', 'gov')
        created_at = datetime.utcnow().isoformat()

        if not title or not affected_areas or not advisory:
            flash("Please fill required fields (title, affected areas, advisory).", "error")
            return render_template('report_disaster.html')

        with get_db() as conn:
            conn.execute("""INSERT INTO disaster_reports
                            (title, severity, affected_areas, timeframe, advisory, reported_by, created_at)
                            VALUES (?, ?, ?, ?, ?, ?, ?)""",
                         (title, severity, affected_areas, timeframe, advisory, reported_by, created_at))
            conn.commit()

            # Optionally: notify users in affected location
            # We'll find users whose location matches any substring in affected_areas (simple approach)
            notified = 0
            try:
                location_query = affected_areas.split(',')[0].strip()  # crude: take first area
                target_users = conn.execute("SELECT email FROM users WHERE location LIKE ?", (f"%{location_query}%",)).fetchall()
                for u in target_users:
                    if send_alert_email(u['email'], location_query, advisory):
                        notified += 1
            except Exception as e:
                print("Notification error:", e)

        flash("Report added successfully. Users notified: {}".format(notified), "success")
        return redirect(url_for('home'))

    # GET -> show form
    return render_template('report_disaster.html')

# Update user route to show disaster reports
@app.route('/user')
def user():
    with get_db() as conn:
        alerts = conn.execute("SELECT * FROM disaster_reports ORDER BY created_at DESC").fetchall()
    return render_template('user.html', alerts=alerts)

# Add edit report route for regular users
@app.route('/edit_report/<int:report_id>', methods=['GET', 'POST'])
def edit_report(report_id):
    # This route is for regular users to edit their disaster reports
    with get_db() as conn:
        report = conn.execute(
            "SELECT * FROM disaster_reports WHERE id = ?", (report_id,)
        ).fetchone()

        if not report:
            flash("Report not found.", "error")
            return redirect(url_for('user'))

        if request.method == 'POST':
            reporter_name = request.form.get('reporter_name')
            reporter_email = request.form.get('reporter_email')
            disaster_type = request.form.get('disaster_type')
            location = request.form.get('location')
            severity = request.form.get('severity')
            description = request.form.get('description')

            # For this simplified version, we'll update the basic fields
            conn.execute("""
                UPDATE disaster_reports
                SET title = ?, severity = ?, affected_areas = ?, advisory = ?
                WHERE id = ?
            """, (f"{disaster_type} in {location}", severity, location, description, report_id))

            conn.commit()
            flash("Report updated successfully!", "success")
            return redirect(url_for('user'))

    return render_template('edit_report.html', report=report)

if __name__ == '__main__':
    app.run(debug=True)