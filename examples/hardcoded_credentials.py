# CWE-798: Hard-coded Credentials Vulnerability
import mysql.connector
import requests

# VULNERABLE: Hard-coded database password
def connect_to_database():
    conn = mysql.connector.connect(
        host="localhost",
        user="admin",
        password="MySecretPassword123!",  # NEVER DO THIS!
        database="myapp"
    )
    return conn

# VULNERABLE: Hard-coded API key
def call_api():
    api_key = "sk_live_51Hxxxxxxxxxxxxxxxxx"  # EXPOSED!
    
    headers = {
        "Authorization": f"Bearer {api_key}"
    }
    
    response = requests.get("https://api.service.com/data", headers=headers)
    return response.json()

# VULNERABLE: Embedded AWS credentials
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# VULNERABLE: Secret key in code
SECRET_KEY = "my-super-secret-encryption-key-2024"

# SAFE VERSION: Use environment variables
import os

def connect_to_database_safe():
    conn = mysql.connector.connect(
        host=os.getenv("DB_HOST", "localhost"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),  # From .env file
        database=os.getenv("DB_NAME")
    )
    return conn

def call_api_safe():
    api_key = os.getenv("API_KEY")  # From environment
    
    if not api_key:
        raise ValueError("API_KEY not configured")
    
    headers = {
        "Authorization": f"Bearer {api_key}"
    }
    
    response = requests.get("https://api.service.com/data", headers=headers)
    return response.json()

# Example .env file (never commit this to Git!):
"""
DB_HOST=localhost
DB_USER=admin
DB_PASSWORD=MySecretPassword123!
DB_NAME=myapp
API_KEY=sk_live_51Hxxxxxxxxxxxxxxxxx
AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""

# Add to .gitignore:
"""
.env
*.env
secrets/
"""
