from flask import Flask, request, jsonify, redirect, url_for, session
from flask_cors import CORS
import os
from pymongo import MongoClient
from dotenv import load_dotenv
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random
import string
import certifi
from datetime import datetime, timedelta
import bcrypt
import uuid

app = Flask(__name__)
CORS(app, resources={
    r"/*": {
        "origins": ["https://securityviz.site", "http://localhost:8080"],
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type", "X-Session-ID", "Accept", "Origin"],
        "supports_credentials": True
    }
})
app.secret_key = os.urandom(24)  # Generate a random secret key for session management

# Load environment variables
load_dotenv()
MONGO_URI = os.getenv("MONGO_URI")
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

# Connect to MongoDB
try:
    client = MongoClient(MONGO_URI, tlsCAFile=certifi.where())
    db = client["auth_db"]
    users_collection = db["users"]
    sessions_collection = db["sessions"]
    scores_collection = db["quiz_scores"]  # New collection for quiz scores
    print("[SUCCESS] Connected to MongoDB!")
except Exception as e:
    print(f"[ERROR] MongoDB Connection Error: {str(e)}")
    exit()

def generate_otp():
    """Generate a 6-digit OTP"""
    return ''.join(random.choices(string.digits, k=6))

def send_otp_email(email, otp):
    """Send OTP via email"""
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_USER
        msg['To'] = email
        msg['Subject'] = "Your OTP for Email Verification"

        body = f"""
        Hello,

        Your OTP for email verification is: {otp}

        This OTP will expire in 10 minutes.

        Best regards,
        Your App Team
        """

        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()

        return True
    except Exception as e:
        print(f"[ERROR] Failed to send email: {str(e)}")
        return False

@app.route("/register", methods=["POST"])
def register():
    try:
        data = request.json
        username = data.get("username")
        email = data.get("email")
        password = data.get("password")

        if not all([username, email, password]):
            return jsonify({"error": "Username, email and password are required"}), 400

        # Check if email or username already exists
        if users_collection.find_one({"email": email}):
            return jsonify({"error": "Email already registered"}), 400
        if users_collection.find_one({"username": username}):
            return jsonify({"error": "Username already taken"}), 400

        # Generate OTP
        otp = generate_otp()
        otp_expiry = datetime.utcnow() + timedelta(minutes=10)

        # Hash password
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

        # Store user data with unverified status
        user_data = {
            "username": username,
            "email": email,
            "password": hashed_password,
            "otp": otp,
            "otp_expiry": otp_expiry,
            "verified": False,
            "created_at": datetime.utcnow()
        }

        users_collection.insert_one(user_data)

        # Send OTP email
        if send_otp_email(email, otp):
            return jsonify({"message": "Registration successful. Please check your email for OTP."}), 201
        else:
            return jsonify({"error": "Failed to send OTP email"}), 500

    except Exception as e:
        print(f"[ERROR] Registration failed: {str(e)}")
        return jsonify({"error": "Registration failed"}), 500

@app.route("/verify-email", methods=["POST"])
def verify_email():
    try:
        data = request.json
        email = data.get("email")
        otp = data.get("otp")

        if not email or not otp:
            return jsonify({"error": "Email and OTP are required"}), 400

        user = users_collection.find_one({"email": email})
        if not user:
            return jsonify({"error": "User not found"}), 404

        if user.get("verified"):
            return jsonify({"error": "Email already verified"}), 400

        if user.get("otp") != otp:
            return jsonify({"error": "Invalid OTP"}), 400

        if datetime.utcnow() > user.get("otp_expiry"):
            return jsonify({"error": "OTP has expired"}), 400

        # Update user as verified
        users_collection.update_one(
            {"email": email},
            {"$set": {"verified": True}}
        )

        return jsonify({"message": "Email verified successfully"}), 200

    except Exception as e:
        print(f"[ERROR] Email verification failed: {str(e)}")
        return jsonify({"error": "Verification failed"}), 500

@app.route("/login", methods=["POST"])
def login():
    try:
        data = request.json
        email = data.get("email")
        password = data.get("password")

        if not email or not password:
            return jsonify({"error": "Email and password are required"}), 400

        user = users_collection.find_one({"email": email})
        if not user:
            return jsonify({"error": "User not found"}), 404

        if not user.get("verified"):
            return jsonify({"error": "Please verify your email first"}), 401

        # Verify password
        if not bcrypt.checkpw(password.encode('utf-8'), user.get("password")):
            return jsonify({"error": "Invalid password"}), 401

        # Create session
        session_id = str(uuid.uuid4())
        session_data = {
            "session_id": session_id,
            "user_id": str(user["_id"]),
            "username": user["username"],
            "created_at": datetime.utcnow(),
            "expires_at": datetime.utcnow() + timedelta(days=7)
        }
        sessions_collection.insert_one(session_data)

        response = jsonify({
            "message": "Login successful",
            "username": user.get("username"),
            "session_id": session_id
        })
        
        # Set CORS headers with dynamic origin support
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        origin = request.headers.get('Origin', '')
        if origin in ['https://securityviz.site', 'http://localhost:8080']:
            response.headers.add('Access-Control-Allow-Origin', origin)
        
        return response, 200

    except Exception as e:
        print(f"[ERROR] Login failed: {str(e)}")
        return jsonify({"error": "Login failed"}), 500

@app.route("/check-session", methods=["GET", "OPTIONS"])
def check_session():
    # Handle preflight OPTIONS request
    if request.method == "OPTIONS":
        response = jsonify({})
        origin = request.headers.get('Origin', '')
        if origin in ['https://securityviz.site', 'http://localhost:8080']:
            response.headers.add('Access-Control-Allow-Origin', origin)
            response.headers.add('Access-Control-Allow-Headers', 'Content-Type, X-Session-ID, Accept, Origin')
            response.headers.add('Access-Control-Allow-Methods', 'GET, OPTIONS')
            response.headers.add('Access-Control-Allow-Credentials', 'true')
        return response, 200
        
    try:
        session_id = request.headers.get("X-Session-ID")
        if not session_id:
            response = jsonify({"authenticated": False})
            origin = request.headers.get('Origin', '')
            if origin in ['https://securityviz.site', 'http://localhost:8080']:
                response.headers.add('Access-Control-Allow-Origin', origin)
                response.headers.add('Access-Control-Allow-Credentials', 'true')
            return response, 401

        session_data = sessions_collection.find_one({
            "session_id": session_id,
            "expires_at": {"$gt": datetime.utcnow()}
        })

        if not session_data:
            response = jsonify({"authenticated": False})
            origin = request.headers.get('Origin', '')
            if origin in ['https://securityviz.site', 'http://localhost:8080']:
                response.headers.add('Access-Control-Allow-Origin', origin)
                response.headers.add('Access-Control-Allow-Credentials', 'true')
            return response, 401

        response = jsonify({
            "authenticated": True,
            "username": session_data.get("username")
        })
        origin = request.headers.get('Origin', '')
        if origin in ['https://securityviz.site', 'http://localhost:8080']:
            response.headers.add('Access-Control-Allow-Origin', origin)
            response.headers.add('Access-Control-Allow-Credentials', 'true')
        return response, 200

    except Exception as e:
        print(f"[ERROR] Session check failed: {str(e)}")
        response = jsonify({"error": "Session check failed"})
        origin = request.headers.get('Origin', '')
        if origin in ['https://securityviz.site', 'http://localhost:8080']:
            response.headers.add('Access-Control-Allow-Origin', origin)
            response.headers.add('Access-Control-Allow-Credentials', 'true')
        return response, 500

@app.route("/logout", methods=["POST"])
def logout():
    try:
        session_id = request.headers.get("X-Session-ID")
        if session_id:
            sessions_collection.delete_one({"session_id": session_id})
        return jsonify({"message": "Logged out successfully"}), 200
    except Exception as e:
        print(f"[ERROR] Logout failed: {str(e)}")
        return jsonify({"error": "Logout failed"}), 500

@app.route("/resend-otp", methods=["POST"])
def resend_otp():
    try:
        data = request.json
        email = data.get("email")

        if not email:
            return jsonify({"error": "Email is required"}), 400

        user = users_collection.find_one({"email": email})
        if not user:
            return jsonify({"error": "User not found"}), 404

        if user.get("verified"):
            return jsonify({"error": "Email already verified"}), 400

        # Generate new OTP
        otp = generate_otp()
        otp_expiry = datetime.utcnow() + timedelta(minutes=10)

        # Update OTP in database
        users_collection.update_one(
            {"email": email},
            {"$set": {
                "otp": otp,
                "otp_expiry": otp_expiry
            }}
        )

        # Send new OTP
        if send_otp_email(email, otp):
            return jsonify({"message": "New OTP sent successfully"}), 200
        else:
            return jsonify({"error": "Failed to send OTP email"}), 500

    except Exception as e:
        print(f"[ERROR] Failed to resend OTP: {str(e)}")
        return jsonify({"error": "Failed to resend OTP"}), 500

@app.route("/save-quiz-score", methods=["POST"])
def save_quiz_score():
    try:
        session_id = request.headers.get("X-Session-ID")
        if not session_id:
            return jsonify({"error": "Authentication required"}), 401

        session_data = sessions_collection.find_one({
            "session_id": session_id,
            "expires_at": {"$gt": datetime.utcnow()}
        })

        if not session_data:
            return jsonify({"error": "Invalid or expired session"}), 401

        data = request.json
        algorithm = data.get("algorithm")
        score = data.get("score")
        total_questions = data.get("totalQuestions")

        if not all([algorithm, score is not None, total_questions is not None]):
            return jsonify({"error": "Algorithm, score, and totalQuestions are required"}), 400

        # Get current user
        user_id = session_data.get("user_id")
        username = session_data.get("username")

        # Check if user already has a score for this algorithm
        existing_score = scores_collection.find_one({
            "user_id": user_id,
            "algorithm": algorithm
        })

        # Convert to int to ensure proper comparison
        score = int(score)
        total_questions = int(total_questions)

        # Calculate percentage
        percentage = (score / total_questions) * 100

        if existing_score:
            # Update only if the new score is higher
            if percentage > existing_score.get("percentage", 0):
                scores_collection.update_one(
                    {"_id": existing_score["_id"]},
                    {"$set": {
                        "score": score,
                        "total_questions": total_questions,
                        "percentage": percentage,
                        "updated_at": datetime.utcnow()
                    }}
                )
                return jsonify({"message": "Score updated successfully", "new_high_score": True}), 200
            else:
                return jsonify({"message": "Existing score is higher", "new_high_score": False}), 200
        else:
            # Create new score record
            score_data = {
                "user_id": user_id,
                "username": username,
                "algorithm": algorithm,
                "score": score,
                "total_questions": total_questions,
                "percentage": percentage,
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow()
            }
            scores_collection.insert_one(score_data)
            return jsonify({"message": "Score saved successfully", "new_high_score": True}), 201

    except Exception as e:
        print(f"[ERROR] Saving quiz score failed: {str(e)}")
        return jsonify({"error": "Failed to save score"}), 500

@app.route("/get-leaderboard", methods=["GET"])
def get_leaderboard():
    try:
        algorithm = request.args.get("algorithm")
        if not algorithm:
            return jsonify({"error": "Algorithm parameter is required"}), 400

        # Get top 10 scores for the algorithm
        leaderboard = list(scores_collection.find(
            {"algorithm": algorithm},
            {"_id": 0, "user_id": 0}  # Exclude sensitive fields
        ).sort("percentage", -1).limit(10))

        return jsonify({"leaderboard": leaderboard}), 200

    except Exception as e:
        print(f"[ERROR] Fetching leaderboard failed: {str(e)}")
        return jsonify({"error": "Failed to fetch leaderboard"}), 500

@app.route("/get-user-score", methods=["GET"])
def get_user_score():
    try:
        session_id = request.headers.get("X-Session-ID")
        if not session_id:
            return jsonify({"error": "Authentication required"}), 401

        session_data = sessions_collection.find_one({
            "session_id": session_id,
            "expires_at": {"$gt": datetime.utcnow()}
        })

        if not session_data:
            return jsonify({"error": "Invalid or expired session"}), 401

        algorithm = request.args.get("algorithm")
        if not algorithm:
            return jsonify({"error": "Algorithm parameter is required"}), 400

        user_id = session_data.get("user_id")
        
        # Get user's score for the algorithm
        user_score = scores_collection.find_one(
            {"user_id": user_id, "algorithm": algorithm},
            {"_id": 0, "user_id": 0}  # Exclude sensitive fields
        )

        return jsonify({"user_score": user_score}), 200

    except Exception as e:
        print(f"[ERROR] Fetching user score failed: {str(e)}")
        return jsonify({"error": "Failed to fetch user score"}), 500

if __name__ == "__main__":
    app.run(debug=True)
