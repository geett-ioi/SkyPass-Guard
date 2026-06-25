# SkyPass Guard — Secure Password Analyzer & Generator

I built **SkyPass Guard** 
It's a web dashboard that checks password strength, generates secure passwords, and lets you encrypt/decrypt test passwords for learning.

I wanted to make something that actually helps people understand **why** passwords are weak and **how** to make them stronger — not just a simple "weak/strong" meter.

## What makes this project cool? 

- **Real-time strength checking** — See your score update as you type
- **Animated circular score ring** — Fun visual feedback that changes color with strength
- **Detailed issues & suggestions** — Know exactly what's wrong and how to fix it
- **Entropy & crack-time estimates** — See how long it would take to brute force your password
- **Secure password generator** — Create cryptographically strong passwords with custom length
- **Encrypt/decrypt demo** — Learn how symmetric encryption works (Fernet)
- **Password check history** — Save all your checks to SQLite for learning
- **Export to CSV** — Download your history for reports
- **Clean sky-blue design** — Makes it look like a real product, not just a school demo

## Tech Stack 

- **Frontend:** HTML, CSS, JavaScript
- **Backend:** Python Flask
- **Database:** SQLite
- **Encryption:** Fernet (from `cryptography` library)
- **Security:** Password hashing, entropy calculation, pattern detection

## How to Use It 

### 1. Install Dependencies

First, make sure you have Python 3.8 or higher installed.

Then install the required packages:

```bash
pip install -r requirements.txt
```

### 2. Run the App

Start the Flask server:

```bash
python app.py
```

The app will start on `http://localhost:5000`.

### 3. Open in Browser

Open your browser and go to: http://localhost:5000 
