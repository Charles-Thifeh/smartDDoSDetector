from flask import Flask, render_template, request, session, jsonify, after_this_request
import urllib.request
from pusher import Pusher
from datetime import datetime
import httpagentparser
import json
import os
import sys
import hashlib
from dbsetup import create_connection, create_session, update_or_create_page, select_all_sessions, \
    select_all_user_visits, user_visits, dash
from sklearn import svm
from sklearn.model_selection import train_test_split

app = Flask(__name__)
app.secret_key = os.urandom(24)

pusher = Pusher(app_id="851355", key="610900e71a09f6db0e63", secret="294767ffcf1477dbfe6c", cluster="eu")

database = "./pythonsqlite.db"
conn = create_connection(database)
c = conn.cursor()

userOS = None
userIP = None
userBrowser = None
sessionID = None

# global UserGRR
# global UserTSoP
UserGRR = 0
UserTSoP = 0
UserSr = 0
Uservisit = user_visits(c, sessionID)
while Uservisit != []:
    User = (Uservisit[0])
    UserGRR1 = int(User["visits"])
    UserGRR = UserGRR1
    visit_ = Uservisit[0]


def main():
    global conn, c


def parseVisitor(data):
    update_or_create_page(c, data)
    pusher.trigger(u'pageview', u'new', {
        u'page': data[0],
        u'session': sessionID,
        u'ip': userIP
    })
    pusher.trigger(u'numbers', u'update', {
        u'page': data[0],
        u'session': sessionID,
        u'ip': userIP
    })


def parameter_GRR():
    Uservisit = user_visits(c, sessionID)
    while Uservisit != []:
        User = (Uservisit[0])
        UserGRR1 = int(User["visits"])
        UserGRR = UserGRR1
        return UserGRR


def parameter_TSoP():
    present = datetime.now()
    UserTSoP1 = (present - uTIndex).total_seconds()
    UserTSoP2 = int(UserTSoP1 * 60)
    UserTSoP = UserTSoP2
    return UserTSoP


def route():
    data = ['home', sessionID, str(datetime.now().replace(microsecond=0))]
    parseVisitor(data)
    return render_template('index.html'), 'OK'


def notroute():
    return render_template('about.html')


# Legitimate Request Profile
def LRP():
    if (UserGRR in range(0, 5)) & (UserTSoP in range(5, 10)):
        req = 'legit'
        return req


# Illegitimate Request Profile
def IRP():
    if (UserGRR in range(0, 10)) & (UserTSoP in range(0, 4)):
        req = 'illegit'
        return req


# SVM classifier
def SVM_CR():
    sys.path.append(os.path.abspath("../"))
    from svmutils import read_data, plot_data, plot_decision_function

    # Read data
    x, labels = read_data("points_class_0.txt", "points_class_1.txt")
    x.reshape(-1, 1)

    # Split data to train and test
    X_train, X_test, y_train, y_test = train_test_split(x, labels, test_size=0.4, random_state=0)

    # Displaying dataset
    plot_data(X_train, y_train, X_test, y_test)

    # Create the SVM classifier
    clf = svm.SVC(kernel='linear')

    # Train classifier
    clf.fit(X_train, y_train)

    # Plot decision function on training and test data
    plot_decision_function(X_train, y_train, X_test, y_test, clf)

    # predict unknown data
    # newData = [UserGRR, UserTSoP]
    rc = clf.predict([[UserGRR, UserTSoP]])
    # print(rc)

    global req
    if rc == [1]:
        req = 'legit'
        return req
    else:
        req = 'illegit'
        return req


@app.before_request
def getAnalyticsData():
    global userOS, userBrowser, userIP, sessionID
    userInfo = httpagentparser.detect(request.headers.get('User-Agent'))
    userOS = userInfo['platform']['name']
    userBrowser = userInfo['browser']['name']
    # userIP = "72.229.28.185" if request.remote_addr == '127.0.0.1' else request.remote_addr
    userIP = '127.0.0.1'
    api = "https://www.iplocate.io/api/lookup/" + userIP
    try:
        resp = urllib.request.urlopen(api)
        result = resp.read()
        result = json.loads(result.decode("utf-8"))
    except:
        print("Blocked IP GET request: ", userIP)
        return render_template('about.html')
    getSession()


def getSession():
    global sessionID
    time = datetime.now().replace(microsecond=0)
    if 'user' not in session:
        lines = (str(time) + userIP).encode('utf-8')
        session['user'] = hashlib.md5(lines).hexdigest()
        sessionID = session['user']
        pusher.trigger(u'session', u'new', {
            u'ip': userIP,
            u'os': userOS,
            u'browser': userBrowser,
            u'session': sessionID,
            u'time': str(time),
        })
        data = [userIP, userOS, userBrowser, sessionID, time]
        create_session(c, data)
    else:
        sessionID = session['user']


@app.route('/')
def detectDDoS():
    global uTIndex
    uTIndex = datetime.now()
    parameter_GRR()
    parameter_TSoP()
    # print(UserGRR, '\n', UserTSoP)
    if UserGRR == 0:
        LRP()
        IRP()
        SVM_CR()
    else:
        LRP()
        IRP()
        SVM_CR()
    # print(req)
    if req == 'legit':
        data = ['home', sessionID, str(datetime.now().replace(microsecond=0))]
        parseVisitor(data)
        return render_template('index.html')
    if req == 'illegit':
        return render_template('about.html')


@app.route('/homepage')
def index():
    return render_template('index.html')


@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')


@app.route('/user/<session_id>', methods=['GET'])
def sessionPages(session_id):
    results = select_all_user_visits(c, session_id)
    return render_template("dashboard-single.html", data=results)


@app.route('/get-all-sessions')
def get_all_sessions():
    data = []
    dbRows = select_all_sessions(c)
    for row in dbRows:
        data.append({
            'time': row['created_at'],
            'ip': row['ip'],
            'os': row['os'],
            'browser': row['browser'],
            'session': row['session']
        })
    return render_template("all.html", data=data)
    # return jsonify(data)


if __name__ == '__main__':
    main()
    app.run(debug=True)

