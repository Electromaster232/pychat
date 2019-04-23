from flask import Blueprint, request, make_response

account_api = Blueprint('account_api', __name__)


# Login
@account_api.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == "GET":
        return render_template("login.html")
    if request.method == "POST":
        username = request.form['username']
        users = query("SELECT * FROM users WHERE nickname = %s", [username])
        if not users:
            return "Invalid username."
        if users:
            if check_encrypted_password(request.form['password'], users[0][1]):
                token = users[0][2]
                resp = make_response(redirect("/chat/general"))
                resp.set_cookie('pychatToken', token)
                return resp
            else:
                return "Your password was incorrect."


# Login Mobile
@account_api.route("/loginmobile", methods=['GET', 'POST'])
def loginmobile():
    if request.method == "POST":
        return "Invalid Request."
    if request.method == "GET":
        if request.args['token']:
             users = query("SELECT * FROM users WHERE token = %s", [request.args['token']])
             if users:
                token = users[0][2]
                resp = make_response(redirect("/m/chat/general"))
                resp.set_cookie('pychatToken', token)
                return resp
        username = request.args['username']
        users = query("SELECT * FROM users WHERE nickname = %s", [username])
        if not users:
            return "Invalid username."
        if users:
            if check_encrypted_password(request.args['password'], users[0][1]):
                token = users[0][2]
                resp = make_response(redirect("/m/chat/general"))
                resp.set_cookie('pychatToken', token)
                return resp
            else:
                return "Incorrect Password"

# Login
@account_api.route("/getcookie", methods=['GET', 'POST'])
def getcookie():
    if request.method == "GET":
        return "Invalid Request."
    if request.method == "POST":
        username = request.form['username']
        users = query("SELECT * FROM users WHERE nickname = %s", [username])
        if not users:
            return "Invalid username."
        if users:
            if check_encrypted_password(request.form['password'], users[0][1]):
                token = users[0][2]
                return token
            else:
                return "Incorrect Password"

