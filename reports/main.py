from functools import wraps
import random
import string
import datetime
import os
import time
import requests
from flask import Flask, jsonify
from flask_jwt_extended import (jwt_required, get_jwt, JWTManager)
from flask_cors import CORS


app = Flask(__name__)
app.config.update({
    "JWT_TOKEN_LOCATION": "headers",
    "JWT_HEADER_NAME": "Authorization",
    "JWT_HEADER_TYPE": "Bearer",
    "JWT_ALGORITHM": "RS256"
})


def get_jwt_public_key():
    max_retries = 10
    retry_delay = 3

    for attempt in range(max_retries):
        try:
            response = requests.get(
                f'{os.environ.get("FLASK_APP_KEYCLOAK_URL")}/realms/{os.environ.get("FLASK_APP_KEYCLOAK_REALM")}'
            )
            return response.json()['public_key']
        except requests.exceptions.ConnectionError:
            print(f"Error getting JWT public key (attempt {attempt + 1}/{max_retries})")
            time.sleep(retry_delay)

    raise Exception("Failed to retrieve JWT public key")

app.config['JWT_PUBLIC_KEY'] = f'-----BEGIN PUBLIC KEY-----{get_jwt_public_key()}-----END PUBLIC KEY-----'


jwt = JWTManager(app)
CORS(
    app,
    origins=os.environ.get("FRONT_URL", 'http://localhost:3000'),
    methods=["GET", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
    supports_credentials=True
)

def role_required(role_name):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            claims = get_jwt()
            if role_name not in claims.get('realm_access', {}).get('roles', []):
                return jsonify(msg='Access denied'), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def generate_random_report():
    return {
        "report_id": ''.join(random.choices(string.ascii_uppercase + string.digits, k=8)),
        "timestamp": datetime.datetime.now().isoformat(),
        "battery_level": random.randint(20, 100),
        "temperature": round(random.uniform(35.0, 37.5), 1),
        "usage_hours": random.randint(0, 24),
        "error_code": random.choice([0, 1, 2, 3]),
        "status": random.choice(["NORMAL", "WARNING", "CRITICAL"]),
        "last_service": (datetime.datetime.now() - datetime.timedelta(days=random.randint(0, 365))).isoformat(),
        "steps_today": random.randint(0, 10000),
        "activity_level": random.choice(["LOW", "MEDIUM", "HIGH"])
    }

@app.route('/reports', methods=['GET'])
@jwt_required()
@role_required('prothetic_user')
def get_report():
    report = generate_random_report()
    return jsonify(report)

if __name__ == '__main__':
    app.run(
        host="0.0.0.0",
        debug=True,
        port=int(os.environ.get('FLASK_APP_PORT', "5000"))
    )
