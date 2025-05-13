from flask import Flask, redirect, request, session, render_template_string
import jwt
import requests

app = Flask(__name__)
app.secret_key = 'secret-key'


client_id = "40a1968c3f5301c67b05"
client_secret = "63b400121b889efcd3c3edcd7c9dce0730737cb7"
redirect_uri = "https://localhost:5000/callback"
casdoor_url = "https://localhost:8443"
casdoor_token_url = f"{casdoor_url}/api/login/oauth/access_token"
jwt_public_key_url = f"{casdoor_url}/.well-known/jwks"


HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Casdoor App</title>
</head>
<body>
    <h1>Casdoor App</h1>
    <a href="/login"><button>Реєстрація через Casdoor</button></a>
    <a href="/user"><button>Інформація про користувача</button></a>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML)

@app.route('/login')
def login():
    auth_url = f"{casdoor_url}/login/oauth/authorize?client_id={client_id}&response_type=code&redirect_uri={redirect_uri}&scope=read&state=casdoor"
    return redirect(auth_url)

@app.route('/callback')
def callback():
    code = request.args.get('code')
    token_data = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
    }
    response = requests.post(casdoor_token_url, data=token_data, verify=False)
    access_token = response.json().get('access_token')
    session['access_token'] = access_token
    return redirect('/user')

@app.route('/user')
def user_info():
    token = session.get('access_token')
    if not token:
        return "Не авторизовано"

    try:
        
        resp = requests.get(jwt_public_key_url, verify=False)
        jwk_set = resp.json()['keys'][0]
        public_key = jwt.algorithms.RSAAlgorithm.from_jwk(jwk_set)

        payload = jwt.decode(token, public_key, algorithms=["RS256"], audience=client_id)

        return f"""
        <b>Інформація про користувача:</b><br>
        Ім’я: {payload.get("name")}<br>
        Email: {payload.get("email")}<br>
        Організація: {payload.get("owner")}<br>
        """
    except Exception as e:
        return f"Помилка при декодуванні JWT: {str(e)}"

if __name__ == '__main__':
    app.run(port=5000, ssl_context=('C:/Users/User_01/casdoor-flask-app/cert.pem', 'C:/Users/User_01/casdoor-flask-app/key.pem'), debug=True)
