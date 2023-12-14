import json
from os import environ as env
from urllib.parse import quote_plus, urlencode
from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv
from flask import Flask, redirect, render_template, session, url_for, request, g
import pypyodbc as odbc
import sqlite3
import bcrypt


# Function to get the SQLite connection
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect('database.sqlite')
    return db

def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()
        
ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

app = Flask(__name__)
app.secret_key = env.get("APP_SECRET_KEY")

oauth = OAuth(app)

connectionString="Driver={ODBC Driver 18 for SQL Server};Server=tcp:"+env.get("SERVER")+",1433;Database="+env.get("DATABASE")+";Uid="+env.get("USERS")+";Pwd="+env.get("PASSWORD")+";Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;"
conn1 = odbc.connect(connectionString)
#conn1 = sqlite3.connect('database.db')
conn=sqlite3.connect('database.sqlite', check_same_thread=False)
createTable1 = """
-- Creating the first table
CREATE TABLE IF NOT EXISTS Users (
    userId VARCHAR(50) PRIMARY KEY,
    password VARCHAR(100),
    salt VARCHAR(50)
);
"""
createTable2="""
-- Creating the second table
CREATE TABLE IF NOT EXISTS UserServices (
    userId VARCHAR(50),
    service VARCHAR(50),
    password VARCHAR(100),
    PRIMARY KEY (userId, service),
    FOREIGN KEY (userId) REFERENCES Users(userId)
);
"""
conn.execute(createTable1)
conn.execute(createTable2)

oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid profile email",
    },
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration'
)

@app.route("/")
def home():
    conn = get_db()
    if (session.get('user') is None):
        return render_template("home.html", session=None, pretty=None, services=None)
    cursor = conn.cursor()
    userInfo = json.loads(json.dumps(session.get('user')['userinfo']))
    username = userInfo.get("email")

    cursor.execute("SELECT service FROM UserServices WHERE userId = ?", (username,))
    services = cursor.fetchall()
    cursor.close()
    
    service_list = [service[0] for service in services]  # Extracting service names
    return render_template("home.html", session=session.get('user'), pretty=json.dumps(session.get('user'), indent=4), services=service_list)

@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )

@app.route("/callback", methods=["GET", "POST"])
def callback():
    conn = get_db()
    token = oauth.auth0.authorize_access_token()
    session["user"] = token

    userInfo = json.loads(json.dumps(session["user"]['userinfo']))

    username = userInfo.get("email")

    
    # Check if the user exists in the database
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM Users WHERE userId = ?", (username,))
    user = cursor.fetchone()

    cursor1 = conn1.cursor()

    if user is None:
        # If user doesn't exist, prompt to set a password
        cursor.execute("INSERT INTO Users (userId) VALUES (?)", (username,))
        cursor1.execute("INSERT INTO Users (userId) VALUES (?)", (username,))
        conn.commit()
        conn1.commit()
        cursor.close()
        cursor1.close()
        return redirect(url_for("set_password"))

    cursor.execute("SELECT password FROM Users WHERE userId = ?", (username,))
    password = cursor.fetchone()
    cursor.close()
    cursor1.close()
    # Check if the user has a password set
    if password[0] is None:
        # Redirect to set password route
        return redirect(url_for("set_password"))
    
    return redirect("/")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://" + env.get("AUTH0_DOMAIN")
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("home", _external=True),
                "client_id": env.get("AUTH0_CLIENT_ID"),
            },
            quote_via=quote_plus,
        )
    )

@app.route("/set_password", methods=["GET", "POST"])
def set_password():
    userInfo = json.loads(json.dumps(session["user"]['userinfo']))
    username = userInfo.get("email")  # Assuming username is retrieved from Auth0
    # Update the password in the database
    cursor = conn.cursor()
    cursor1 = conn1.cursor()

    if request.method == "POST":
        # Get the password from the form submission
        new_password = request.form.get("password")
        salt = bcrypt.gensalt()
        passwd = new_password.encode('utf-8')
        pass_len = len(passwd)
        hashed = bcrypt.hashpw(passwd[0:pass_len//2], salt)
        hashed1 = bcrypt.hashpw(passwd[pass_len//2:pass_len], salt)

        # Get the user's information from the session
        cursor.execute("UPDATE Users SET password = ?, salt = ? WHERE userId = ?", (hashed, salt, username))
        conn.commit()
        cursor.close()

        cursor1.execute("UPDATE Users SET password = ?, salt = ? WHERE userId = ?", (hashed1, salt, username))
        conn1.commit()
        cursor1.close()

        # Redirect to the home page or any desired route
        return redirect("/")

    # Render the template to set a new password
    cursor.execute("SELECT password FROM Users WHERE userId = ?", (username,))
    password = cursor.fetchone()
    cursor.close()
    if password[0] is None:
        return render_template("set_password.html")
    else:
        return redirect("/")


@app.route("/store_password", methods=["GET","POST"])
def store_password():
    if request.method == "POST":
        service_name = request.form.get("service_name")
        service_password = request.form.get("service_password")
        
        userInfo = json.loads(json.dumps(session["user"]['userinfo']))
        username = userInfo.get("email")
        
        cursor = conn.cursor()
        cursor.execute("INSERT INTO UserServices (userId, service, password) VALUES (?, ?, ?)", (username, service_name, service_password[0:len(service_password)//2]))
        conn.commit()
        cursor.close()

        cursor1 = conn1.cursor()
        cursor1.execute("INSERT INTO UserServices (userId, service, password) VALUES (?, ?, ?)", (username, service_name, service_password[len(service_password)//2:len(service_password)]))
        conn1.commit()
        cursor1.close()
        
        return redirect("/")
    # Handle other HTTP methods or render a form for password storage
    return render_template("store_password.html")

# New route for retrieving stored passwords for a service
@app.route("/get_password/<service_name>")
def get_password(service_name):
    userInfo = json.loads(json.dumps(session["user"]['userinfo']))
    username = userInfo.get("email")
    
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM UserServices WHERE userId = ? AND service = ?", (username, service_name))
    password = cursor.fetchone()
    cursor.close()

    cursor1 = conn1.cursor()
    cursor1.execute("SELECT password FROM UserServices WHERE userId = ? AND service = ?", (username, service_name))
    password1 = cursor1.fetchone()
    cursor1.close()
    
    if password:
        return f"The password for {service_name} is: {password[0]+password1[0]}"
    else:
        return f"No password found for {service_name}"

@app.route("/delete_password/<service_name>")
def delete_password(service_name):
    userInfo = json.loads(json.dumps(session["user"]['userinfo']))
    username = userInfo.get("email")
    
    cursor = conn.cursor()
    cursor.execute("DELETE FROM UserServices WHERE userId = ? AND service = ?", (username, service_name))
    conn.commit()
    cursor.close()

    cursor1 = conn1.cursor()
    cursor1.execute("DELETE FROM UserServices WHERE userId = ? AND service = ?", (username, service_name))
    conn1.commit()
    cursor1.close()
    
    return redirect("/")

@app.route("/verify_password/<service_name>", methods=["GET", "POST"])
def verify_password(service_name):
    userInfo = json.loads(json.dumps(session["user"]['userinfo']))
    username = userInfo.get("email")
    
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM UserServices WHERE userId = ? AND service = ?", (username, service_name))
    password = cursor.fetchone()
    cursor.execute("SELECT password, salt FROM Users WHERE userId = ?", (username,))
    userPassword = cursor.fetchone()
    cursor.close()

    cursor1 = conn1.cursor()
    cursor1.execute("SELECT password FROM UserServices WHERE userId = ? AND service = ?", (username, service_name))
    password1 = cursor1.fetchone()
    cursor1.execute("SELECT password, salt FROM Users WHERE userId = ?", (username,))
    userPassword1 = cursor1.fetchone()
    cursor1.close()
    
    if request.method == "POST":
        entered_password = request.form.get("service_password")

        hashed = bcrypt.hashpw(entered_password.encode('utf-8')[0:len(entered_password)//2], userPassword[1])
        hashed1 = bcrypt.hashpw(entered_password.encode('utf-8')[len(entered_password)//2:len(entered_password)], userPassword1[1].encode('utf-8'))
        if hashed==userPassword[0] and hashed1==userPassword1[0].encode('utf-8'):
            return f"The password for {service_name} is: {password[0]+password1[0]}"
        else:
            return "Incorrect password"
    return render_template("verify_password.html", service_name=service_name)

# @app.route("/update_password/<service_name>", methods=["GET", "POST"])
# def update_password(service_name):
#     userInfo = json.loads(json.dumps(session["user"]['userinfo']))
#     username = userInfo.get("email")
    
#     cursor = conn.cursor()
#     cursor.execute("SELECT password FROM UserServices WHERE userId = ? AND service = ?", (username, service_name))
#     password = cursor.fetchone()
#     cursor.close()

#     cursor1 = conn1.cursor()
#     cursor1.execute("SELECT password FROM UserServices WHERE userId = ? AND service = ?", (username, service_name))
#     password1 = cursor1.fetchone()
#     cursor1.close()
    
#     if request.method == "POST":
#         new_password = request.form.get("service_password")
#         cursor = conn.cursor()
#         cursor.execute("UPDATE UserServices SET password = ? WHERE userId = ? AND service = ?", (new_password[0:len(new_password)//2], username, service_name))
#         conn.commit()
#         cursor.close()

#         cursor1 = conn1.cursor()
#         cursor1.execute("UPDATE UserServices SET password = ? WHERE userId = ? AND service = ?", (new_password[len(new_password)//2:len(new_password)], username, service_name))
#         conn1.commit()
#         cursor1.close()
        
#         return redirect("/")
#     return render_template("update_password.html", service_name=service_name, password=password[0]+password1[0])

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=env.get("PORT", 3000), debug=True, ssl_context=("cert.pem", "key.pem"))
