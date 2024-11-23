from flask import Flask, render_template, request, redirect, url_for, session
from authlib.integrations.flask_client import OAuth
import requests
import time, random, string, os

app = Flask(__name__)
app.secret_key = os.urandom(24)

users = {'testuser': 'testpassword'} #test db

oauth = OAuth(app)

UNT_TENANT_ID = 'tenant id here'
UNT_CLIENT_ID = 'client id here'
UNT_CLIENT_SECRET = 'Client secret here' #stored privately
UNT_REDIRECT_URI = 'http://localhost:5000/login/unt-email/callback'

# OAuth URLs
AUTHORIZATION_URL = f'https://login.microsoftonline.com/{UNT_TENANT_ID}/oauth2/v2.0/authorize'
TOKEN_URL = f'https://login.microsoftonline.com/{UNT_TENANT_ID}/oauth2/v2.0/token'
USER_INFO_URL = 'https://graph.microsoft.com/v1.0/me'

SCOPE = 'User.Read'

unt = oauth.register(
    name='unt',
    client_id=UNT_CLIENT_ID,
    client_secret=UNT_CLIENT_SECRET,
    authorize_url=AUTHORIZATION_URL,
    access_token_url=TOKEN_URL,
    client_kwargs={'scope': SCOPE}
)

# LinkedIn credentials yet to be added
LINKEDIN_CLIENT_ID = 'your_linkedin_client_id'
LINKEDIN_CLIENT_SECRET = 'your_linkedin_client_secret'
LINKEDIN_REDIRECT_URI = 'http://localhost:5000/login/linkedin/callback'
LINKEDIN_SCOPE = 'r_liteprofile r_emailaddress'

linkedin = oauth.register(
    name='linkedin',
    client_id=LINKEDIN_CLIENT_ID,
    client_secret=LINKEDIN_CLIENT_SECRET,
    authorize_url='https://www.linkedin.com/oauth/v2/authorization',
    access_token_url='https://www.linkedin.com/oauth/v2/accessToken',
    client_kwargs={'scope': LINKEDIN_SCOPE}
)

@app.route('/')
def home():
    return render_template('index.html') 

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    if username in users and users[username] == password:
        return "Logged in successfully!"  #dashboard integration later
    else:
        return "Invalid credentials, please try again."
    
@app.route('/login/linkedin')
def login_linkedin():
    linkedin_auth_url = (
        f"https://www.linkedin.com/oauth/v2/authorization?response_type=code&client_id={LINKEDIN_CLIENT_ID}"
        f"&redirect_uri={LINKEDIN_REDIRECT_URI}&scope={LINKEDIN_SCOPE}"
    )
    return redirect(linkedin_auth_url)


@app.route('/callback') #for linkedin
def callback():
    code = request.args.get('code')

    token_data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': LINKEDIN_REDIRECT_URI,
        'client_id': LINKEDIN_CLIENT_ID,
        'client_secret': LINKEDIN_CLIENT_SECRET
    }
    response = requests.post(TOKEN_URL, data=token_data)
    response_json = response.json()

    access_token = response_json.get('access_token')
    if access_token:
        user_profile = fetch_linkedin_profile(access_token)
        return f'User Profile: {user_profile}'
    else:
        return 'Error: Unable to get access token'


def fetch_linkedin_profile(access_token):
    profile_url = 'https://api.linkedin.com/v2/me'
    headers = {'Authorization': f'Bearer {access_token}'}
    profile_response = requests.get(profile_url, headers=headers)
    return profile_response.json()


@app.route('/login/unt-email')
def login_unt_email():
    state = ''.join(random.choices(string.ascii_letters + string.digits, k=32)) #to prevent state attacks
    
    session['oauth_state'] = state
    
    # to the UNT authorization URL with the state
    redirect_uri = url_for('unt_email_callback', _external=True)
    authorization_url = unt.authorize_redirect(redirect_uri, state=state)
    
    return authorization_url

@app.route('/login/unt-email/callback')
def unt_email_callback():
    state = request.args.get('state')
    if state != session.get('oauth_state'):
        return "Error: CSRF attack detected! State parameter mismatch."

    try:
        token = unt.authorize_access_token()
        
        # Store token in the session (optional)
        session['access_token'] = token['access_token']
        session['refresh_token'] = token.get('refresh_token')
        session['token_expiry'] = time.time() + token['expires_in']
        
        # Fetch user information from Microsoft Graph API
        user_info = unt.get('https://graph.microsoft.com/v1.0/me').json()
        email = user_info.get('mail') or user_info.get('userPrincipalName')
        
        if email:
            session['user_email'] = email
            if email not in whitelist_emails:
                return render_template('unauthorized.html', email=email)
            
            return f"Logged in as {email}"
        else:
            return "Error: Unable to retrieve email from the user profile."

    except Exception as e:
        # Handle exceptions if any
        return f"Error occurred: {e}"

# Dummy alumni profiles for demonstration 
alumni_profiles = [
    {
        'name': 'Jane Doe',
        'photo': 'static/jane_doe.jpg',  # Replace with a valid image path in the static folder
        'feed': ['Graduated 2020', 'Software Engineer at Google', 'Active in AI research'],
        'activities': ['Attended UNT Hackathon', 'Guest Speaker at UNT CS Conference']
    },
    {
        'name': 'John Smith',
        'photo': 'static/john_smith.jpg',  # Replace with a valid image path in the static folder
        'feed': ['Graduated 2019', 'Data Scientist at Amazon', 'Author of Data Science book'],
        'activities': ['Volunteered at UNT Career Fair', 'Hosted Coding Workshop']
    }
]


@app.route('/request-access', methods=['POST'])
def request_access():
    email = request.form.get('email')
    print(f"Access request received for email: {email}") 
    return f"Access request submitted for {email}. An admin will review your request."

whitelist_emails = [
    "KirmiVyas@my.unt.edu"
]


if __name__ == '__main__':
    app.run(host="localhost", port=5000,debug=True)

