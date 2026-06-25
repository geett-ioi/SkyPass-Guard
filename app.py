"""
app.py — SkyPass Guard Backend (FIXED)

This is the main Flask application file for the SkyPass Guard project.
It handles:
- Password strength checking with real-time analysis
- Secure password generation
- Encryption/decryption of test passwords
- Saving password check history to SQLite
- Exporting history to CSV
- Dashboard API endpoints
"""

from flask import Flask, render_template, request, jsonify
from models import init_db, save_password_check, get_all_checks, export_to_csv
import secrets
import re
import math
from datetime import datetime
import base64
import os
from cryptography.fernet import Fernet

# Initialize Flask app
app = Flask(__name__)

# ============================================================
# ENCRYPTION SETUP
# ============================================================
# Generate or load encryption key for password encryption/decryption
# This key is used with Fernet symmetric encryption
# WARNING: In production, store this key securely (environment variable or secrets manager)

ENCRYPTION_KEY_FILE = 'encryption.key'

def get_or_create_key():
    """
    Get existing encryption key or create a new one.
    If the key file exists, load it. Otherwise, generate a new key and save it.
    """
    if os.path.exists(ENCRYPTION_KEY_FILE):
        # Load existing key from file
        with open(ENCRYPTION_KEY_FILE, 'rb') as f:
            key = f.read()
    else:
        # Generate new encryption key
        key = Fernet.generate_key()
        # Save key to file for future use
        with open(ENCRYPTION_KEY_FILE, 'wb') as f:
            f.write(key)
    
    return key

# Create encryption key and cipher suite
key = get_or_create_key()
cipher_suite = Fernet(key)


def encrypt_password(password):
    """
    Encrypt a password using Fernet symmetric encryption.
    
    Args:
        password (str): The plain text password to encrypt
        
    Returns:
        str: Base64-encoded encrypted password (safe to store)
    
    Note:
        - Fernet provides authenticated encryption
        - The encrypted password can be decrypted later with the same key
        - Store the encrypted version, not the plain password
    """
    # Encrypt the password
    encrypted = cipher_suite.encrypt(password.encode('utf-8'))
    # Convert to base64 string for storage
    return base64.b64encode(encrypted).decode('utf-8')


def decrypt_password(encrypted_password_b64):
    """
    Decrypt an encrypted password back to plain text.
    
    Args:
        encrypted_password_b64 (str): Base64-encoded encrypted password
        
    Returns:
        str: Decrypted plain text password
        
    Note:
        - This should only be used for testing/demo purposes
        - Never expose decrypted passwords to users in production
        - The encryption key must match the one used for encryption
    """
    # Convert base64 string back to bytes
    encrypted = base64.b64decode(encrypted_password_b64)
    # Decrypt and return plain text
    decrypted = cipher_suite.decrypt(encrypted)
    return decrypted.decode('utf-8')


# ============================================================
# PASSWORD STRENGTH ANALYSIS
# ============================================================

def calculate_entropy(password):
    """
    Calculate password entropy using Shannon's formula.
    
    Entropy = L * log2(R)
    where:
    - L = length of password
    - R = size of character pool used
    
    Higher entropy = more secure against brute force attacks
    
    Args:
        password (str): The password to analyze
        
    Returns:
        float: Entropy score in bits
    """
    if not password:
        return 0
    
    # Determine character pool size
    pool_size = 0
    
    # Check for lowercase letters (pool += 26)
    if any(c.islower() for c in password):
        pool_size += 26
    
    # Check for uppercase letters (pool += 26)
    if any(c.isupper() for c in password):
        pool_size += 26
    
    # Check for digits (pool += 10)
    if any(c.isdigit() for c in password):
        pool_size += 10
    
    # Check for special characters (pool += ~32)
    if any(not c.isalnum() for c in password):
        pool_size += 32
    
    # Calculate entropy
    if pool_size == 0:
        return 0
    
    entropy = len(password) * math.log2(pool_size)
    return entropy


def estimate_crack_time(entropy):
    """
    Estimate how long it would take to crack the password.
    
    Uses entropy to estimate crack time assuming 10 billion guesses per second.
    This is a rough estimate based on modern GPU cracking capabilities.
    
    Args:
        entropy (float): Password entropy in bits
        
    Returns:
        str: Human-readable time estimate
    """
    if entropy <= 0:
        return "Instantly"
    
    # Assume 10 billion guesses per second (modern GPU cracking)
    guesses_per_second = 10_000_000_000
    
    # Calculate number of possible combinations
    combinations = 2 ** entropy
    
    # Calculate time in seconds
    seconds = combinations / guesses_per_second
    
    # Convert to human-readable format
    if seconds < 1:
        return "Instantly"
    elif seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        return f"{seconds/60:.1f} minutes"
    elif seconds < 86400:
        return f"{seconds/3600:.1f} hours"
    elif seconds < 31536000:
        return f"{seconds/86400:.1f} days"
    elif seconds < 315360000:
        return f"{seconds/31536000:.1f} years"
    else:
        return f"{seconds/31536000:.1f}+ years"


def analyze_password_strength(password):
    """
    Analyze password strength and provide detailed feedback.
    
    This function performs comprehensive password analysis including:
    - Length validation
    - Character diversity check
    - Pattern detection (repeated chars, keyboard patterns, common words)
    - Entropy calculation
    - Crack time estimation
    
    Args:
        password (str): The password to analyze
        
    Returns:
        dict: Analysis results with score, label, issues, and suggestions
    """
    
    # Initialize result object
    result = {
        'score': 0,
        'label': '',
        'issues': [],
        'suggestions': [],
        'entropy': 0,
        'crack_time': ''
    }
    
    # Handle empty password
    if not password:
        result['label'] = 'Enter Password'
        return result
    
    # ========================================================
    # 1. LENGTH ANALYSIS
    # ========================================================
    
    length = len(password)
    
    # Check if too short (less than 8 characters)
    if length < 8:
        result['issues'].append('Password is too short')
        result['suggestions'].append('Add at least 8 characters')
        result['score'] -= 20
    elif length < 12:
        result['issues'].append('Password is a bit short')
        result['suggestions'].append('Consider using 12+ characters for better security')
        result['score'] -= 5
    elif length >= 16:
        # Bonus for long passwords
        result['score'] += 10
    
    # ========================================================
    # 2. CHARACTER DIVERSITY ANALYSIS
    # ========================================================
    
    # Count different character types
    has_lowercase = any(c.islower() for c in password)
    has_uppercase = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    
    char_types = sum([has_lowercase, has_uppercase, has_digit, has_special])
    
    # Missing character types penalty
    if char_types < 2:
        result['issues'].append('Missing character variety')
        result['suggestions'].append('Add uppercase, lowercase, numbers, and symbols')
        result['score'] -= 25
    elif char_types < 3:
        result['issues'].append('Limited character variety')
        result['suggestions'].append('Mix different character types')
        result['score'] -= 10
    elif char_types == 4:
        # Bonus for all character types
        result['score'] += 15
    
    # ========================================================
    # 3. PATTERN DETECTION
    # ========================================================
    
    # Check for repeated characters (e.g., "aaaaaa")
    repeated_pattern = re.search(r'(\w)\1{2,}', password)
    if repeated_pattern:
        result['issues'].append('Contains repeated characters')
        result['suggestions'].append('Avoid repeating the same character')
        result['score'] -= 15
    
    # Check for keyboard patterns (e.g., "qwerty", "1234")
    keyboard_patterns = ['qwerty', 'qwert', '1234', '12345', 'abcd', 'abcde']
    password_lower = password.lower()
    for pattern in keyboard_patterns:
        if pattern in password_lower:
            result['issues'].append('Contains keyboard pattern')
            result['suggestions'].append('Avoid common patterns like qwerty or 1234')
            result['score'] -= 15
            break
    
    # Check for sequential numbers (e.g., "123456")
    if re.search(r'\d{4,}', password):
        result['issues'].append('Contains sequential numbers')
        result['suggestions'].append('Avoid sequential numbers')
        result['score'] -= 10
    
    # Check for sequential letters (e.g., "abcdef")
    if re.search(r'[a-zA-Z]{4,}', password):
        result['issues'].append('Contains sequential letters')
        result['suggestions'].append('Avoid sequential letters')
        result['score'] -= 10
    
    # ========================================================
    # 4. COMMON PASSWORD CHECK
    # ========================================================
    
    # Very common weak passwords (expanded list)
    common_passwords = [
        'password', 'password123', '123456', '123456789', 'qwerty',
        'abc123', 'admin', 'letmein', 'welcome', 'monkey',
        'dragon', 'master', 'login', 'passw0rd', 'root'
    ]
    
    if password_lower in common_passwords:
        result['issues'].append('Common password detected')
        result['suggestions'].append('Use a unique password, not a common one')
        result['score'] -= 40
    
    # ========================================================
    # 5. ENTROPY ANALYSIS
    # ========================================================
    
    # Calculate entropy
    entropy = calculate_entropy(password)
    result['entropy'] = entropy
    result['crack_time'] = estimate_crack_time(entropy)
    
    # ========================================================
    # 6. FINAL SCORE CALCULATION
    # ========================================================
    
    # Base score from length (0-40 points)
    base_score = min(length * 3, 40)
    
    # Add character diversity bonus (0-20 points)
    diversity_bonus = char_types * 5
    
    # Total score
    result['score'] = base_score + diversity_bonus + result['score']
    
    # Ensure score is between 0 and 100
    result['score'] = max(0, min(100, result['score']))
    
    # ========================================================
    # 7. STRENGTH LABEL
    # ========================================================
    
    if result['score'] < 30:
        result['label'] = 'Very Weak'
        result['color'] = '#ef4444'  # Red
    elif result['score'] < 50:
        result['label'] = 'Weak'
        result['color'] = '#f59e0b'  # Orange
    elif result['score'] < 70:
        result['label'] = 'Medium'
        result['color'] = '#3b82f6'  # Blue
    elif result['score'] < 90:
        result['label'] = 'Strong'
        result['color'] = '#10b981'  # Green
    else:
        result['label'] = 'Very Strong'
        result['color'] = '#059669'  # Dark Green
    
    # Return analysis result
    return result


# ============================================================
# PASSWORD GENERATION
# ============================================================

def generate_secure_password(length=16, use_symbols=True):
    """
    Generate a secure random password.
    
    Uses Python's secrets module for cryptographic random generation.
    Combines lowercase, uppercase, digits, and optionally symbols.
    
    Args:
        length (int): Desired password length (default: 16)
        use_symbols (bool): Whether to include symbols (default: True)
        
    Returns:
        str: Securely generated password
    """
    # Define character sets
    lowercase = 'abcdefghijklmnopqrstuvwxyz'
    uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    digits = '0123456789'
    symbols = '!@#$%^&*_-+=?'
    
    # Build character pool
    char_pool = lowercase + uppercase + digits
    
    if use_symbols:
        char_pool += symbols
    
    # Generate password using cryptographically secure random
    password = ''.join(secrets.choice(char_pool) for _ in range(length))
    
    return password


# ============================================================
# FLASK ROUTES
# ============================================================

@app.route('/')
def home():
    """
    Render the main dashboard page with 4 navigation sections.
    
    This is the home route that displays the SkyPass Guard dashboard
    with a top nav bar and 4 animated sections:
    1. Password Checker
    2. Password Generator
    3. Encrypt/Decrypt
    4. History & Export
    
    Returns:
        str: Rendered HTML page
    """
    return render_template('index.html')


@app.route('/api/check-password', methods=['POST'])
def check_password():
    """
    API endpoint to check password strength.
    
    Receives a password from the frontend, analyzes it, and returns
    detailed strength analysis including score, issues, and suggestions.
    
    Also saves the check to SQLite database for history.
    
    Request Body:
        {
            "password": "user_password_here"
        }
    
    Returns:
        JSON: Analysis result with score, label, issues, suggestions, entropy, crack_time
    """
    
    # Get password from request
    data = request.get_json()
    password = data.get('password', '')
    
    # Analyze password
    result = analyze_password_strength(password)
    
    # Save to database (encrypt password for storage)
    if password:
        encrypted_password = encrypt_password(password)
        save_password_check(
            password_hash=encrypted_password,  # Store encrypted version
            score=result['score'],
            label=result['label'],
            issues=result['issues'],
            suggestions=result['suggestions']
        )
    
    # Return analysis result
    return jsonify(result)


@app.route('/api/generate-password', methods=['POST'])
def generate_password():
    """
    API endpoint to generate a secure password.
    
    Receives generation parameters from frontend and returns
    a cryptographically secure random password.
    
    Request Body:
        {
            "length": 16,
            "use_symbols": true
        }
    
    Returns:
        JSON: Generated password
    """
    
    # Get parameters from request
    try:
        data = request.get_json()
    except Exception:
        # If JSON is invalid, return error
        return jsonify({'error': 'Invalid JSON'}), 400
    
    length = data.get('length', 16)
    use_symbols = data.get('use_symbols', True)
    
    # Validate length
    try:
        length = int(length)
        length = max(4, min(length, 50))  # clamp between 4 and 50
    except:
        length = 16
    
    # Generate password
    password = generate_secure_password(length, use_symbols)
    
    # Return generated password
    return jsonify({'password': password})


@app.route('/api/history', methods=['GET'])
def get_history():
    """
    API endpoint to get password check history.
    
    Retrieves all saved password checks from SQLite database.
    Returns encrypted passwords (not decrypted) for security.
    
    Returns:
        JSON: List of password checks with timestamp, score, label, issues
    """
    
    # Get all checks from database
    checks = get_all_checks()
    
    # Return history
    return jsonify(checks)


@app.route('/api/export-csv', methods=['GET'])
def export_csv():
    """
    API endpoint to export password history to CSV.
    
    Retrieves all password checks and exports them to CSV format.
    The CSV file is created and can be downloaded by the user.
    
    Returns:
        JSON: CSV filename and success message
    """
    
    # Generate CSV file
    csv_filename = export_to_csv()
    
    # Return filename and message
    return jsonify({'filename': csv_filename, 'message': 'CSV exported successfully'})


# ============================================================
# ENCRYPTION / DECRYPTION ROUTES
# ============================================================

@app.route('/api/encrypt-password', methods=['POST'])
def encrypt_password_route():
    """
    API endpoint to encrypt a password.
    
    Receives a password from the frontend and returns
    the encrypted (base64-encoded) password.
    
    Request Body:
        {
            "password": "user_password"
        }
    
    Returns:
        JSON: encrypted password
    """
    
    # Get password from request
    try:
        data = request.get_json()
    except Exception:
        return jsonify({'error': 'Invalid JSON'}), 400
    
    password = data.get('password', '')
    
    if not password:
        return jsonify({'error': 'Password is required'}), 400
    
    # Encrypt password
    encrypted = encrypt_password(password)
    
    # Return encrypted password
    return jsonify({'encrypted': encrypted})


@app.route('/api/decrypt-password', methods=['POST'])
def decrypt_password_route():
    """
    API endpoint to decrypt an encrypted password.
    
    Receives an encrypted password from the frontend and returns
    the decrypted plain text password.
    
    Request Body:
        {
            "encrypted_password": "base64_encrypted_string"
        }
    
    Returns:
        JSON: decrypted password
    """
    
    # Get encrypted password from request
    try:
        data = request.get_json()
    except Exception:
        return jsonify({'error': 'Invalid JSON'}), 400
    
    encrypted_password = data.get('encrypted_password', '')
    
    if not encrypted_password:
        return jsonify({'error': 'Encrypted password is required'}), 400
    
    # Decrypt password
    try:
        decrypted = decrypt_password(encrypted_password)
    except Exception as e:
        return jsonify({'error': f'Decryption failed: {str(e)}'}), 400
    
    # Return decrypted password
    return jsonify({'decrypted': decrypted})


# ============================================================
# MAIN ENTRY POINT
# ============================================================

if __name__ == '__main__':
    """
    Main entry point for the Flask application.
    
    Initializes the database and starts the Flask server.
    Runs on localhost:5000 by default.
    """
    
    # Initialize SQLite database
    init_db()
    
    # Run Flask app
    print("[*] SkyPass Guard is running!")
    print("[*] Open http://localhost:5000 in your browser")
    app.run(debug=True, port=5000)