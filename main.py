from flask import Flask, request, redirect, session
import requests
import pprint
import urllib.parse
import datetime
import os
from dotenv import load_dotenv
import secrets
import json

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY') or secrets.token_urlsafe(32)

INSTANCE = os.getenv('INSTANCE')
CLIENT_ID = os.getenv('CLIENT_ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')
PUBLIC_URL = os.getenv('PUBLIC_URL')
REDIRECT_URI = f"{PUBLIC_URL}/callback"
TOKEN_URL = os.getenv('TOKEN_URL')
REQUESTED_SCOPES = os.getenv('REQUESTED_SCOPES')
STATE = os.getenv('STATE')

def check_env_vars():
    required_vars = [INSTANCE, CLIENT_ID, CLIENT_SECRET, PUBLIC_URL, TOKEN_URL, REQUESTED_SCOPES, STATE]
    if not all(required_vars):
        raise EnvironmentError("One or more required environment variables are missing.")

check_env_vars()

def store_tokens(access_token, refresh_token, expires_at):
    session['ACCESS_TOKEN'] = access_token
    session['REFRESH_TOKEN'] = refresh_token
    session['EXPIRES_AT'] = expires_at.isoformat()

def get_access_token():
    access_token = session.get('ACCESS_TOKEN')
    expires_at = datetime.datetime.fromisoformat(session.get('EXPIRES_AT'))

    if not access_token or datetime.datetime.now() >= expires_at:
        refresh_token = session.get('REFRESH_TOKEN')
        try:
            token_response = requests.post(
                f'https://{INSTANCE}.{TOKEN_URL}',
                data={
                    'grant_type': 'refresh_token',
                    'refresh_token': refresh_token,
                    'client_id': CLIENT_ID,
                    'client_secret': CLIENT_SECRET
                },
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )
            token_response.raise_for_status()
        except requests.RequestException as e:
            return f"Error refreshing token: {e}"

        token_json = token_response.json()
        access_token = token_json.get('access_token')
        refresh_token = token_json.get('refresh_token')
        expires_in = token_json.get('expires_in')
        expires_at = datetime.datetime.now() + datetime.timedelta(seconds=expires_in)

        store_tokens(access_token, refresh_token, expires_at)
    
    return access_token

@app.route('/')
def home():
    return f'''
        <html>
            <body>
                <h1>Ninja Webhook</h1>
                <ul>
                    <li><a href="{PUBLIC_URL}/authorize">Authorize</a></li>
                    <li><a href="{PUBLIC_URL}/setup_webhook">Setup Webhook</a></li>
                    <li><a href="{PUBLIC_URL}/view_webhook">View latest Webhook</a></li>
                    <li><a href="{PUBLIC_URL}/remove_webhook">Remove Webhook</a></li>
                </ul>
            </body>
        </html>
    '''

@app.route('/authorize')
def authorize():
    authorization_url = f'https://{INSTANCE}.ninjarmm.com/ws/oauth/authorize?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&response_type=code&scope={urllib.parse.quote(REQUESTED_SCOPES)}&state={STATE}'
    return redirect(authorization_url)

@app.route('/callback')
def callback():
    code = request.args.get('code')
    if code:
        try:
            token_response = requests.post(
                f'https://{INSTANCE}.{TOKEN_URL}',
                data={
                    'grant_type': 'authorization_code',
                    'code': code,
                    'redirect_uri': REDIRECT_URI,
                    'client_id': CLIENT_ID,
                    'client_secret': CLIENT_SECRET
                },
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )
            token_response.raise_for_status()
        except requests.RequestException as e:
            return f"Error during token exchange: {e}"

        token_json = token_response.json()
        access_token = token_json.get('access_token')
        refresh_token = token_json.get('refresh_token')
        expires_in = token_json.get('expires_in')
        expires_at = datetime.datetime.now() + datetime.timedelta(seconds=expires_in)

        store_tokens(access_token, refresh_token, expires_at)
        return f"Access:\n{token_json}"
    else:
        return "Error: Authorization code not found"

@app.route('/setup_webhook')
def setup_webhook():
    url = f"https://{INSTANCE}.ninjarmm.com/v2/webhook"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {get_access_token()}"
    }
    payload = {
        "url": f"{PUBLIC_URL}/webhook_listener",
        "activities": {activity: ["*"] for activity in [
            "ACTIONSET", "ACTION", "CONDITION", "CONDITION_ACTIONSET",
            "CONDITION_ACTION", "ANTIVIRUS", "PATCH_MANAGEMENT", "TEAMVIEWER",
            "MONITOR", "SYSTEM", "COMMENT", "SHADOWPROTECT", "IMAGEMANAGER",
            "HELP_REQUEST", "SOFTWARE_PATCH_MANAGEMENT", "SPLASHTOP", "CLOUDBERRY",
            "CLOUDBERRY_BACKUP", "SCHEDULED_TASK", "RDP", "SCRIPTING", "SECURITY",
            "REMOTE_TOOLS", "VIRTUALIZATION", "PSA", "MDM", "NINJA_REMOTE",
            "NINJA_QUICK_CONNECT", "NINJA_NETWORK_DISCOVERY", "NINJA_BACKUP"
        ]},
        "expand": [
            "device", "organization", "location", "policy",
            "rolePolicy", "role"
        ]
    }

    try:
        response = requests.put(url, json=payload, headers=headers)
        response.raise_for_status()
    except requests.RequestException as e:
        return f"Error setting up webhook: {e}", response.status_code

    if response.status_code == 204:
        return "Webhook Established!", 204
    elif response.status_code == 403:
        return "Error: Only system administrators can configure webhooks.\nDouble check your webhook destination and user permissions.", 403
    else:
        return f"Error: {response.text}", response.status_code

@app.route('/remove_webhook')
def remove_webhook():
    url = f"https://{INSTANCE}.ninjarmm.com/v2/webhook"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {get_access_token()}"
    }

    try:
        response = requests.delete(url, headers=headers)
        response.raise_for_status()
    except requests.RequestException as e:
        return f"Error removing webhook: {e}", response.status_code

    if response.status_code == 204:
        return "Webhook Removed!", 204
    elif response.status_code == 403:
        return "Different PSA is already configured", 403
    elif response.status_code == 500:
        return "Failed to disable PSA", 500
    else:
        return f"Error: {response.text}", response.status_code

@app.route('/webhook_listener', methods=['POST'])
def webhook_listener():
    latest_webhook_data = request.json
    pprint.pprint(latest_webhook_data)
    return "Webhook received!"

@app.route('/view_webhook', methods=['GET'])
def view_webhook():
    formatted_json = json.dumps(session.get('latest_webhook_data', {}), indent=4)
    return f'''
        <html>
            <head>
                <title>View Webhook Data</title>
            </head>
            <body>
                <h1>Latest Webhook Data</h1>
                <pre>{formatted_json}</pre>
            </body>
        </html>
    '''

@app.route('/ticket_received', methods=['POST'])
def ticket_received():
    if request.method == 'POST':
        pprint.pprint(request.json)
        return "Webhook received!"

if __name__ == '__main__':
    debug = os.getenv('DEBUG', 'False') == 'True'
    app.run(debug=debug, host='0.0.0.0', port=8000)
