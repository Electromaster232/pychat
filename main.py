from flask import Flask, request, redirect, render_template, make_response, session
from flask_socketio import SocketIO
import MySQLdb
import requests
import markdown
import random
import datetime
import time
from passlib.context import CryptContext
import secrets
import re
from config import Config
import pymdownx.emoji


app = Flask(__name__)
app.config['SECRET_KEY'] = 'odL1}0a=}E:ybjfY.%rH"Ys5?6;J<^'
socketio = SocketIO(app)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/about")
def about():
    return render_template("about.html")


# Minified channel switcher
@app.route("/chanswitch", methods=['GET', 'POST'])
def chanswitch():
    if request.method == "GET":
        return "Invalid Request."
    if request.method == "POST":
        channel = request.form['channel'].lower()
        if "g-" in request.form['channel']:
            return redirect("/group/" + channel.strip('g-'))
        else:
            return redirect("/chat/" + channel)



# Send messages from previous chat sessions
@socketio.on("getprevmsg")
def send_prev_msg(json, methods=['GET', 'POST']):
    if json['group'] == "yes":
          msgs = query("SELECT * FROM privatemessages WHERE channel = %s ORDER BY id DESC LIMIT 15;", [json['channel']])
    else:
          msgs = query("SELECT * FROM messages WHERE channel = %s ORDER BY id DESC LIMIT 15;", [json['channel']])
    key = json['key']
    for r in msgs[::-1]:
        json2 = {}
        json2['message'] = markdown.markdown(r[0], extensions=['pymdownx.tilde', 'pymdownx.emoji'], extension_configs = {"pymdownx.emoji": {"emoji_generator":pymdownx.emoji.to_alt}})
        usr = query("SELECT * FROM users WHERE nickname = %s", [r[1]])
        if usr[0][6] == "yes":
            json2['user_name'] = "<i class='fa fa-gavel'></i> " + r[1]
        else:
            json2['user_name'] = r[1]
        json2['channel'] = json['channel']
        json2['key'] = key
        time = r[3]
        json2['timestamp'] = time.strftime('%d/%m/%Y %H:%M:%S')
        socketio.emit("recvprevmsg", json2)


# Return chat window

@app.route("/m/chat/<string:channel>", methods=['GET', 'POST'])
def chatembedmobile(channel):
    if "g-" in channel:
        return redirect("/chat/"+channel.replace("g-", ""))
    token = request.cookies.get("pychatToken")
    users = query("SELECT * FROM users WHERE token = %s", [token])
    if not users:
        return redirect("/login")
    if request.method == "GET":
        key = random.getrandbits(10)
        return render_template("pychatmobile.html", channel=channel, username=users[0][0], key=key, group="no")


@app.route("/chat/<string:channel>", methods=['GET', 'POST'])
def chatembed(channel):
    if "g-" in channel:
        return redirect("/chat/"+channel.replace("g-", ""))
    token = request.cookies.get("pychatToken")
    users = query("SELECT * FROM users WHERE token = %s", [token])
    if not users:
        return redirect("/login")
    if request.method == "GET":
        key = random.getrandbits(10)
        return render_template("chat.html", channel=channel, username=users[0][0], key=key, ip=request.environ['REMOTE_ADDR'], group="no")

@app.route("/group/<string:channel>", methods=['GET', 'POST'])
def groupchat(channel):
    token = request.cookies.get("pychatToken")
    users = query("SELECT * FROM users WHERE token = %s", [token])
    if not users:
        return redirect("/login")
    try:
         if users[0][0] in query("SELECT * FROM privatechannels WHERE channame = %s", [channel])[0][2]:
             key = random.getrandbits(10)
             return render_template("chat.html", channel="g-"+channel, username=users[0][0], key=key,
                               ip=request.environ['REMOTE_ADDR'], group="yes")
    except IndexError:
        return "Sorry idiot but you're not allowed to access this chat room."

@app.route("/m/group/<string:channel>", methods=['GET', 'POST'])
def groupchatmobile(channel):
    token = request.cookies.get("pychatToken")
    users = query("SELECT * FROM users WHERE token = %s", [token])
    if not users:
        return redirect("/login")
    try:
         if users[0][0] in query("SELECT * FROM privatechannels WHERE channame = %s", [channel])[0][2]:
             key = random.getrandbits(10)
             return render_template("pychatmobile.html", channel="g-"+channel, username=users[0][0], key=key,
                               ip=request.environ['REMOTE_ADDR'], group="yes")
    except IndexError:
        return "Sorry idiot but you're not allowed to access this chat room."


# Login
@app.route("/login", methods=['GET', 'POST'])
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


# Login
@app.route("/loginmobile", methods=['GET', 'POST'])
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
@app.route("/getcookie", methods=['GET', 'POST'])
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



# Handle chat

@socketio.on("chatsend")
def handle_chat(json, methods=['GET', 'POST']):
    now = datetime.datetime.now()
    f = '%d/%m/%Y %H:%M:%S'
    content = json['message']
    channel = json['channel']
    if not channel == joined[json['user_name']]:
         return
    token = request.cookies.get("pychatToken")
    users = query("SELECT * FROM users WHERE token = %s", [token])
    if channel == "rules" or channel == "announcements":
         return
    if users[0][5] == "yes":
        return
    json['user_name'] = users[0][0]
    if "g-" in channel:
         if users[0][0] not in str(query("SELECT * FROM privatechannels WHERE channame = %s", [channel.strip("g-")])):
              return
    author = json['user_name']
    if users[0][6] == "yes":
        json['user_name'] = "<i class='fa fa-gavel'></i> " + author
    json['timestamp'] = now.strftime(f)
    content = content.replace('<','&lt;').replace('>','&gt;')
    content = content.strip("#")
    content = content.strip("`")
    channels = query("SELECT * FROM privatechannels WHERE channame = %s", [channel.strip("g-")])
    if content.isspace() or content == "":
        return
    if json['group'] == "yes":
         if channels[0][4] == "yes":
             pass
         else:
            query("INSERT INTO privatemessages (content, author, channel) VALUES (%s,%s,%s);", (content, author, channel))
    else:
         query("INSERT INTO messages (content, author, channel) VALUES (%s,%s,%s);", (content, author, channel))
    content = content.replace("/shrug", " ¯\\\_(ツ)_/¯")
    json['message'] = markdown.markdown(content, extensions=['pymdownx.tilde', 'pymdownx.emoji'], extension_configs = {"pymdownx.emoji": {"emoji_generator":pymdownx.emoji.to_alt}})
    for k, r in sockettokens.items():
        if r == channel:
             socketio.emit('chatrecieve', json, room=k)
        else:
             pass
    execbot(content, channel)


# Signup
@app.route("/signup", methods=['GET', 'POST'])
def signup():
    if request.method == "GET":
        return render_template("signup.html")
    if request.method == "POST":
        if not request.form['password'] and request.form['email'] and request.form['username']:
            return "Sorry, but you're missing something. Go back and try again"
        username = request.form['username'].replace("<", "")
        username = username.replace(">", "")
        username = username.lower()
        iftehuser = query("SELECT * FROM users WHERE nickname = %s", [username])
        if username in iftehuser:
            return "Sorry, someone already has that username. Go back and pick another"
        encryptedpassword = encrypt_password(request.form['password'])
        token = secrets.token_hex(20)
        email = request.form['email']
        query("INSERT INTO users (nickname, password, token, email, muted) VALUES (%s,%s,%s,%s,\"no\")", (username, encryptedpassword, token, email))
        resp = make_response(redirect("/chat/general"))
        resp.set_cookie('pychatToken', token)
        return resp

# Logout
@app.route("/logout")
def logout():
    resp = make_response(redirect("/"))
    resp.set_cookie('pychatToken', expires=0)
    return resp

### BEGIN BOT

def execbot(content, channel):
    print("starting execbot")
    if "/ping" in content:
        json2 = {}
        json2['user_name'] = "b1nzy"
        json2['message'] = "Pong!"
        json2['channel'] = channel
        socketio.emit("chatrecieve", json2)
    elif "/history" in content:
        content = content.replace("/history ", "")
        content = int(content)
        list = query("SELECT * FROM messages WHERE channel = %s ORDER BY id DESC LIMIT %s", (channel, content))
        list2 = ""
        for r in list:
            list2 = list2 + "\n{}: {}".format(r[1], r[0])
        with open('error.txt', 'w') as file:
            file.write(list2)
        files = {'file': open("error.txt", "rb")}
        response = requests.post("https://dj-electro.me/upload/ba2cfcff45ad1f470af2ab3ab96d3248037e6c41",
                                 files=files)
        json2 = {}
        json2['user_name'] = "b1nzy"
        json2['message'] = response.url
        json2['channel'] = channel
        socketio.emit("chatrecieve", json2)
    else:
        return

# Join messages
@socketio.on("joinree")
def joinree(json):
    channel = json['channel']
    if "/group/" in request.referrer:
        re1 = channel.strip("g-")
        re1 = "/group/" + re1
        if not re1 in request.referrer:
            return
    if "/chat/" in request.referrer:
        re1 = "/chat/" + channel
        if not re1 in request.referrer:
            return
    user = request.cookies.get("pychatToken")
    users = query("SELECT * FROM users WHERE token = %s", [user])
    json2 = {}
    json2['author'] = users[0][0]
    if users[0][6] == "yes":
        json2['staff'] = "yes"
    json2['channel'] = channel
    json2['key'] = json['key']
    socketio.emit("userconn", json2)
    try:
         joined[users[0][0]] = channel
         print(request.sid)
         sockettokens[request.sid] = channel
    except KeyError:
         pass
    for r, v in joined.items():
        user2 = query("SELECT * FROM users WHERE nickname = %s", [r])
        json3 = {}
        print("Sent user" + r)
        json3['key'] = json['key']
        if user2[0][6] == "yes":
              json3['staff'] = "yes"
        json3['author'] = r
        json3['channel'] = v
        socketio.emit("userconn", json3)


# D e s t r u c t i v e  m e s s a g e s
@app.route("/destructionon/<string:channel>")
def deson(channel):
    channel = query("SELECT * FROM privatechannels WHERE authkey = %s", [channel])
    channelt = channel[0][1]
    json4 = {}
    json4['channel'] = "g-" + channelt
    socketio.emit("deson", json4)

@app.route("/destructionoff/<string:channel>")
def desoff(channel):
    channel = query("SELECT * FROM privatechannels WHERE authkey = %s", [channel])
    channelt = channel[0][1]
    json4 = {}
    json4['channel'] = "g-" + channelt
    socketio.emit("desoff", json4)


# When a user leaves :(
@socketio.on("leave")
def leave(json2):
    print("Disconnecc")
    user = request.cookies.get("pychatToken")
    user = query("SELECT * FROM users WHERE token = %s", [user])
    print(user[0][0])
    try:
         del joined[user[0][0]]
    except KeyError:
         pass
    json = {}
    json['author'] = user[0][0]
    json['channel'] = json2['channel']
    socketio.emit("userdiss", json)

# Misc Functions

def query(query, values):
    conn.ping(True)
    cur = conn.cursor()
    cur.execute(query, values)
    conn.commit()
    return cur.fetchall()


def convertSQLDateTimeToTimestamp(value):
    return time.mktime(time.strptime(value, '%Y-%m-%d %H:%M:%S'))


def encrypt_password(password):
    return pwd_context.encrypt(password)


def check_encrypted_password(password, hashed):
    return pwd_context.verify(password, hashed)


if __name__ == '__main__':
    conn = MySQLdb.connect(host=Config.host,  # your host, usually localhost
                         user=Config.user,  # your username
                         passwd=Config.passwd,  # your password
                         db=Config.db)
    random.seed()
    pwd_context = CryptContext(
        schemes=["pbkdf2_sha256"],
        default="pbkdf2_sha256",
        pbkdf2_sha256__default_rounds=30000
    )
    joined = {}
    sockettokens = {}
    socketio.run(app)
