from flask import Flask, flash, redirect, render_template, \
     request, jsonify, url_for, session, send_from_directory, \
     make_response, Response as ress, send_file
from flask_sqlalchemy import SQLAlchemy
from cerberus import Validator
from sqlalchemy import cast, func, distinct
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.dialects.postgresql import JSON
from functools import wraps
from datetime import datetime, timedelta
import time
import json
import os
from settings import APP_STATIC_JSON, APP_ROOT
from random import shuffle
import cgi
from werkzeug.utils import secure_filename
from flask import json as fJson
import logging
from logging.handlers import RotatingFileHandler
from config import BaseConfig
from config import EmailConfig
import uuid
import base64
from flask_mail import Mail, Message
import requests
import hashlib
from flask_csv import send_csv
import pytz
import io
import csv
import inspect
import unittest
import re
import mimetypes
import zipfile
from sqlalchemy.ext.hybrid import hybrid_property
app = Flask(__name__, static_url_path='')

app.config['UPLOAD_FOLDER'] = APP_STATIC_JSON
#app.config['JSON_AS_ASCII'] = False
app.debug_log_format = "[%(asctime)s] {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s"
# logHandler = logging.FileHandler('logs/login.log')
logHandler = RotatingFileHandler('logs.log', maxBytes=10000, backupCount=1)
# logHandler.setFormatter(formatter)
logHandler.setLevel(logging.NOTSET)
app.logger.addHandler(logHandler)
app.logger.setLevel(logging.NOTSET)
#app.logger.info('Log message')
login_log = app.logger
app.debug = False
app.secret_key = "some_secret"
app.config.from_object(BaseConfig)
# app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:postgres@localhost/multiple_tests'
# app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://gct:gct123@oes.rguktn.ac.in/gct'
app.config.from_object(EmailConfig)
# app.logger.info("app key is %s"%app.config['NUZVID_MAIL_GUN_KEY'])
db = SQLAlchemy(app)

# formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
# def setup_logger(name, log_file, level=logging.DEBUG):
#     handler = logging.FileHandler(log_file)
#     handler.setFormatter(formatter)
#     logger = logging.getLogger(name)
#     logger.setLevel(level)
#     logger.addHandler(handler)
#     return logger

# login_log = setup_logger('login_logger', 'logs/login.log')

ALLOWED_EXTENSIONS = set(['json'])
QP_TEMPLATE_SCHEMA = {
    'name': {'type': 'string', 'required': True},
    'section': {
        'type': 'list', 'minlength': 1, 'required': True,
        'schema': {
            'type': 'dict',
            'schema': {
                'name': {'type': 'string', 'required': True},
                'subsection': {
                    'type': 'list', 'minlength': 1, 'required': True,
                    'schema': {
                        'type': 'dict',
                        'schema': {
                            'name': {'type': 'string', 'required': True},
                            'count': {'type': 'string', 'required': True},
                            'questions': {'type': 'list', 'maxlength': 0, 'required': True},
                            'note': {'type': 'string', 'required': True},
                            'types': {'type': 'string', 'required': True, 'allowed': ['video', 'record', 'passage', 'essay']},
                        }
                    }
                }
            }
        }
    }
}

RECORD_TYPE_SCHEMA = {
    'name': {'type': 'string', 'required': True},
    'questions': {
        'type': 'list', 'minlength': 1, 'required': True,
        'schema': {
            'type': 'dict',
            'schema': {
                'question': {'type': 'string', 'required': True},
                'options': {'type': 'list', 'maxlength': 0, 'required': True},
                'id': {'type': 'string', 'required': True},
            }
        }
    },
    'note': {'type': 'string', 'required': True},
    'types': {'type': 'string', 'required': True, 'allowed': ['record']},
}

ESSAY_TYPE_SCHEMA = {
    'name': {'type': 'string', 'required': True},
    'questions': {
        'type': 'list', 'minlength': 1, 'required': True,
        'schema': {
            'type': 'dict',
            'schema': {
                'question': {'type': 'string', 'required': True},
                'options': {'type': 'list', 'maxlength': 0, 'required': True},
                'id': {'type': 'string', 'required': True},
            }
        }
    },
    'note': {'type': 'string', 'required': True},
    'types': {'type': 'string', 'required': True, 'allowed': ['essay']},
}

PASSAGE_TYPE_SCHEMA = {
    'name': {'type': 'string', 'required': True},
    'types': {'type': 'string', 'required': True, 'allowed': ['passage']},
    'passageArray': {
        'type': 'list', 'minlength': 1, 'required': True,
        'schema': {
            'type': 'dict',
            'schema': {
                'note': {'type': 'string', 'required': True},
                'passage': {'type': 'string', 'required': True},
                'questions': {
                    'type': 'list', 'minlength': 1, 'required': True,
                    'schema': {
                        'type': 'dict',
                        'question': {'type': 'string', 'required': True},
                        'options': {'type': 'list', 'minlength': 4, 'required': True},
                        'id': {'type': 'string', 'required': True},
                        'answer': {'type': 'string', 'required': True},
                        'practicelinks': {'type': 'list', 'minlength': 0, 'required': True},
                    }
                }
            }
        }
    }
}

VIDEO_TYPE_SCHEMA = {
    'name': {'type': 'string', 'required': True},
    'types': {'type': 'string', 'required': True, 'allowed': ['passage']},
    'note': {'type': 'string', 'required': True},
    'videoArray': {
        'type': 'list', 'minlength': 1, 'required': True,
        'schema': {
            'type': 'dict',
            'schema': {
                'link': {'type': 'string', 'required': True},
                'questions': {
                    'type': 'list', 'minlength': 1, 'required': True,
                    'schema': {
                        'type': 'dict',
                        'question': {'type': 'string', 'required': True},
                        'options': {'type': 'list', 'minlength': 4, 'required': True},
                        'id': {'type': 'string', 'required': True},
                        'answer': {'type': 'string', 'required': True},
                        'practicelinks': {'type': 'list', 'minlength': 0, 'required': True},
                    }
                }
            }
        }
    }
}

validate_qp_template = Validator(QP_TEMPLATE_SCHEMA)
validate_passage_template = True
validate_video_template = True
validate_essay_template = Validator(ESSAY_TYPE_SCHEMA)
validate_record_template = Validator(RECORD_TYPE_SCHEMA)

schema_type_mapping = {
    'essay' :validate_essay_template,
    'record' :validate_record_template,
    'passage' :validate_record_template,
    'video' :validate_record_template,
}

e1_start=1;e1_end=100;e2_start=101;e2_end=200;e3_start=201;e3_end=300;
e4_start=301;e4_end=400;

#create a local timezone (Indian Standard Time)
IST = pytz.timezone('Asia/Kolkata')

global status
global errortype

@app.errorhandler
def default_error_handler(error):
    '''Default error handler'''
    return {'message': str(error)}, getattr(error, 'code', 500)

def to_pretty_json(value):
    return json.dumps(value, sort_keys=True, indent=4, separators=(',', ': '))

app.jinja_env.filters['tojson_pretty'] = to_pretty_json

#A list of uri for each role
permissions_object = {
    'student':[
        '/',
        '/student'
    ],
    'admin':[
        '/',
        '/student',
        '/admin'
    ]}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

class LoginLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    emailid = db.Column(db.String(180))
    ip = db.Column(db.String(20))
    logged_on = db.Column(db.DateTime(), default=datetime.utcnow)

    def __init__(self, emailid, ip):
        self.ip = ip
        self.emailid = emailid

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80))
    emailid = db.Column(db.String(180), unique=True)
    pin = db.Column(db.String(80))
    testctime = db.Column(db.DateTime(), default=datetime.utcnow, onupdate=datetime.utcnow)

    def __init__(self, name, pin, emailid):
        self.name = name
        self.pin = pin
        self.emailid = emailid

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    emailid = db.Column(db.String(180), unique=True)
    password = db.Column(db.String(80))
    user_type = db.Column(db.String(10), default="student")
    verified = db.Column(db.String(80), default=False)
    registered_time = db.Column(db.DateTime(), default=datetime.utcnow)
    password_last_time = db.Column(db.DateTime(), default=datetime.utcnow, onupdate=datetime.utcnow)

    def __init__(self, emailid, password, user_type, verified):
        self.emailid = emailid
        self.password = password
        self.user_type = user_type
        self.verified = verified

    def __repr__(self):
        return str(self.emailid)

class AdminDetails(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(180), unique=True)
    password = db.Column(db.String(1000))

    def __init__(self, email, password):
        self.email = email
        self.password = password

    def __repr__(self):
        return str(self.password)

class Students(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80))
    emailid = db.Column(db.String(180), unique=True)
    rollno = db.Column(db.String(80))

    def __init__(self, name, emailid, rollno):
        self.name = name
        self.emailid = emailid
        self.rollno = rollno

    def __repr__(self):
        return str(self.name)+"::"+str(self.emailid)+"::"+str(self.rollno)

class Tests(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True)
    start_date = db.Column(db.String(80))
    end_date = db.Column(db.String(80))
    test_mode = db.Column(db.String(80), default="TOEFL")
    # json = db.Column(db.String(1000))
    creator = db.Column(db.String(180))
    time = db.Column(db.DateTime(), default=pytz.utc.localize(datetime.utcnow()), onupdate=pytz.utc.localize(datetime.utcnow()))

    def __init__(self, name, creator, start_date, end_date, test_mode):
        self.name = name
        self.creator = creator
        self.start_date = start_date
        self.end_date = end_date
        self.test_mode = test_mode
        self.time = pytz.utc.localize(datetime.utcnow())
        # self.json = json
    def isHosted(self):
        today = datetime.now(IST)
        start_date = datetime.strptime(self.start_date, '%d-%m-%Y %H:%M')
        end_date = datetime.strptime(self.end_date, '%d-%m-%Y %H:%M')

        return IST.localize(start_date) < today < IST.localize(end_date)

    def __repr__(self):
        return str(self.name)+"::"+str(self.start_date)+"::"+str(self.end_date)

class StudentTests(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    emailid = db.Column(db.String(180))
    test_name = db.Column(db.String(180))
    invitation_email_sent = db.Column(db.Boolean(), default=False)

    def __init__(self, emailid, test_name):
        self.emailid = emailid
        self.test_name = test_name

    def __repr__(self):
        return self.test_name

    def getTests(self):
        return self.test_name

class UserAudio(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String(80))
    test_name = db.Column(db.String(180))
    blob1 = db.Column(db.LargeBinary)
    time = db.Column(db.DateTime(), default=datetime.utcnow, onupdate=datetime.utcnow)

    def __init__(self, user, blob1, test_name):
        self.user = user
        self.test_name = test_name
        self.blob1 = blob1

class TestAudio(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    blob1 = db.Column(db.LargeBinary)

    def __init__(self, blob1):
        self.blob1 = blob1

class DataModel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(180))
    blob = db.Column(db.LargeBinary)

    def __init__(self, url, blob):
        self.url = url
        self.blob = blob

class userDetails(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120))
    email=db.Column(db.String(120), unique=True)
    phno = db.Column(db.String(120))
    rollno = db.Column(db.String(120))
    learningcenter = db.Column(db.String(120))

    def __init__(self, name, email, phno, rollno, learningcenter):
        self.name = name
        self.email = email
        self.phno = phno
        self.rollno = rollno
        self.learningcenter = learningcenter

class TestDetails(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email=db.Column(db.String(120))
    test_name = db.Column(db.String(180))
    test= db.Column(db.Boolean())
    teststime=db.Column(db.DateTime(), default=datetime.utcnow)
    delays=db.Column(db.Float())
    testend= db.Column(db.Boolean())
    lastPing = db.Column(db.DateTime(), default=datetime.utcnow, onupdate=datetime.utcnow)
    score = db.Column(db.Integer())
    learningcenter = db.Column(db.String(120))

    def __init__(self, **kwargs):
        super(TestDetails, self).__init__(**kwargs)

class Response(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80))
    emailid = db.Column(db.String(180))
    test_name = db.Column(db.String(180))
    pin = db.Column(db.String(80))
    testctime = db.Column(db.DateTime(), default=datetime.utcnow)
    submittedans = db.Column(db.Text)
    responsetime = db.Column(db.Float)
    q_score = db.Column(db.Integer)
    q_status = db.Column(db.String(120))
    time = db.Column(db.DateTime(), default=datetime.utcnow, onupdate=datetime.utcnow )
    currentQuestion=db.Column(db.String(120))
    serialno=db.Column(db.Integer)
    q_section = db.Column(db.String(120))
    ip = db.Column(db.String(20), default="127.0.0.1")

    def __init__(self, **kwargs):
        super(Response, self).__init__(**kwargs)


class Randomize(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user1=db.Column(db.String(120))
    test_name = db.Column(db.String(180))
    serialno=db.Column(db.Integer)
    qno=db.Column(db.String(120))

    def __init__(self, user1, serialno, qno, test_name):
        self.user1 = user1
        self.serialno = serialno
        self.qno = qno
        self.test_name = test_name

class EssayTypeResponse(db.Model):
    """Sub model for storing user response for essay type questions"""
    id = db.Column(db.Integer, primary_key=True)
    useremailid = db.Column(db.String(120))
    qid = db.Column(db.String(120))
    ansText = db.Column(db.Text)
    qattemptedtime = db.Column(db.Float)
    test_name = db.Column(db.String(180))

    def __init__(self, useremailid, qid, ansText, qattemptedtime, test_name):
        self.useremailid = useremailid
        self.qid = qid
        self.ansText = ansText
        self.qattemptedtime = qattemptedtime
        self.test_name = test_name

def getQuestionPaper(qid_list,path):
    json_temp=json.loads(open(os.path.join(path,'QP_template.json')).read())
    #print qid_list
    i=0;j=0;k=0;l=0;m=0;n=0;p=0;q=0;r=0;s=0;t=0
    for qid in qid_list:
        qid=int(qid)
        if qid in list(range(e1_start,e1_end)):
              e1_readjson=json.loads(open(os.path.join(path,'E1-Reading.json'), encoding='utf-8').read())
              for key in e1_readjson["passageArray"]:
                    for qn in key["questions"]:
                          pid=qn["id"]
                          if int(pid) == qid:
                                json_temp["section"][2]["subsection"][0]["passage"]=key["passage"]
                                json_temp["section"][2]["subsection"][0]["questions"].append(qn)
                                json_temp["section"][2]["subsection"][0]["questions"][m]["serialno"] = qid_list[qid]
                                m +=1
        if qid in list(range(e2_start,e2_end)):
              e2_lsnjson=json.loads(open(os.path.join(path,'E2-Listening.json'), encoding='utf-8').read())
              for key in e2_lsnjson["videoArray"]:
                    for qn in key["questions"]:
                          pid=qn["id"]
                          if int(pid) == qid:
                                json_temp["section"][0]["subsection"][0]["link"]=key["link"]
                                json_temp["section"][0]["subsection"][0]["questions"].append(qn)
                                json_temp["section"][0]["subsection"][0]["questions"][n]["serialno"] = qid_list[qid]
                                n +=1
        if qid in list(range(e3_start,e3_end)):
              e3_spkjson=json.loads(open(os.path.join(path,'E3-Speaking.json'), encoding='utf-8').read())
              for key in e3_spkjson["questions"]:
                    if int(key["id"]) == qid:
                          json_temp["section"][1]["subsection"][0]["questions"].append(key)
                          json_temp["section"][1]["subsection"][0]["questions"][p]["serialno"] = qid_list[qid]
                          p += 1
        if qid in list(range(e4_start,e4_end)):
              e4_wrtjson=json.loads(open(os.path.join(path,'E4-Writing.json'), encoding='utf-8').read())
              for key in e4_wrtjson["questions"]:
                    if int(key["id"]) == qid:
                          json_temp["section"][3]["subsection"][0]["questions"].append(key)
                          json_temp["section"][3]["subsection"][0]["questions"][q]["serialno"] = qid_list[qid]
                          q += 1
    return json_temp

def generateQuestionPaper(path):
    json_temp=json.loads(open(os.path.join(path,'QP_template.json'), encoding='utf-8').read())
    for key in json_temp:
        if  key == "section":
            section=json_temp[key]
            for s in section:
                for key in s:
                    if key == "subsection":
                        for subs in s[key]:
                            cnt=int(subs["count"])
                            app.logger.info(cnt)
                            name=subs["name"]
                            types=subs["types"]
                            #print name
                            if name == "E2-Listening":
                                #print name
                                json_subs=json.loads(open(os.path.join(path,name+".json"), encoding='utf-8').read())
                                video_list=json_subs["videoArray"]
                                serialno=list(range(0,len(video_list)))
                                shuffle(serialno)
                                subs["link"]=video_list[serialno[0]]["link"]
                                subs["questions"]=video_list[serialno[0]]["questions"]
                                i=0
                                for qn in subs["questions"]:
                                    subs["questions"][i]["serialno"]=i+1
                                    i +=1
                            if types =="question" or types =="record":
                                #print name
                                json_subs=json.loads(open(os.path.join(path,name+".json"), encoding='utf-8').read())
                                qns_list=json_subs["questions"];
                                serialno=list(range(0,len(qns_list)))
                                shuffle(serialno)
                                for no in list(range(0,cnt)):
                                    subs["questions"].append(qns_list[serialno[no]])
                                    subs["questions"][no]["serialno"]=no+1
                            if types == "passage":
                                #print name
                                json_subs=json.loads(open(os.path.join(path,name+".json"), encoding='utf-8').read())
                                psglist=json_subs["passageArray"]
                                serialno=list(range(0,len(psglist)))
                                shuffle(serialno)
                                subs["questions"]=psglist[serialno[0]]["questions"]
                                j=0
                                for qn in subs["questions"]:
                                    subs["questions"][j]["serialno"]=j+1
                                    j +=1
                                subs["passage"]=psglist[serialno[0]]["passage"]
                            if types =="essay":
                                #print name
                                app.logger.info("essay came")
                                json_subs=json.loads(open(os.path.join(path,name+".json"), encoding='utf-8').read())
                                qns_list=json_subs["questions"];
                                serialno=list(range(0,len(qns_list)))
                                shuffle(serialno)
                                for no in list(range(0,cnt)):
                                    subs["questions"].append(qns_list[serialno[no]])
                                    subs["questions"][no]["serialno"]=no+1
                            if name == "T2-Listening":
                                #print name
                                json_subs=json.loads(open(os.path.join(path,name+".json"), encoding='utf-8').read())
                                video_list=json_subs["videoArray"]
                                serialno=list(range(0,len(video_list)))
                                shuffle(serialno)
                                subs["link"]=video_list[serialno[0]]["link"]
                                subs["questions"]=video_list[serialno[0]]["questions"]
                                k=0
                                for qn in subs["questions"]:
                                  subs["questions"][k]["serialno"]=k+1
                                  k +=1
    #ss=json.dumps(json_temp)
    return json_temp

def getAnswer(qid,path):
    qid=int(qid)

    if qid in list(range(e1_start,e1_end)):
        e1_readjson=json.loads(open(os.path.join(path, 'E1-Reading.json'), encoding='utf-8').read())
        for psg in e1_readjson["passageArray"]:
            for key in psg["questions"]:
                if int(key["id"]) == qid:
                    for op in key["options"]:
                        if op[0] == "=":
                            return op[1:len(op)]
    if qid in list(range(e2_start,e2_end)):
        e2_lsnjson=json.loads(open(os.path.join(path, 'E2-Listening.json'), encoding='utf-8').read())
        for key in e2_lsnjson["videoArray"]:
            for qn in key["questions"]:
                if int(qn["id"]) == qid:
                    for op in qn["options"]:
                        if op[0] == "=":
                            return op[1:len(op)]

def admin_login_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        user = session['user'] if 'user' in session else None
        if not user:
            #app.logger.info("User not logged in")
            return render_template('login.html')
        elif 'role' not in session['user']:
            return render_template('unauthorized.html')
        elif session['user']['role'] != 'admin':
            #app.logger.info("User not logged in as admin")
            return render_template('unauthorized.html')
        return func(*args, **kwargs)
    return decorated_function

def login_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        user = session['user'] if 'user' in session else None
        if not user:
            #app.logger.info("User not logged in")
            return render_template('login.html')
        elif 'role' not in session['user']:
            return render_template('unauthorized.html')
        return func(*args, **kwargs)
    return decorated_function

def list_files(startpath):
    for root, dirs, files in os.walk(startpath):
        level = root.replace(startpath, '').count(os.sep)
        indent = ' ' * 4 * (level)
        #app.logger.info('{}{}/'.format(indent, os.path.basename(root)))
        subindent = ' ' * 4 * (level + 1)
        for f in files:
            app.logger.info('{}{}'.format(subindent, f))

@app.before_request
def before_request():
    db.session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=15)
    db.session.modified = True
    #app.logger.info(["Session expire time extentended to ", datetime.now(IST) + app.permanent_session_lifetime])

@app.route('/error/<error>')
def error(error):
    return render_template('error.html', error=error)

@app.route('/test', methods=['GET', 'POST'])
def test():
    email="vy@fju.us"
    password="veda1997"
    password = hashlib.md5(password.encode('utf-8')).hexdigest()
    verified=True
    user_type="student"
    user = Users(email, password, user_type, verified)
    db.session.add(user)
    db.session.commit()
    # response = sendNotifyMail()
    # res = Response(serialno="123",emailid="email",name="email",currentQuestion=str("123"),submittedans="submittedans",responsetime=1.2,q_status="tre",q_score=1)
    # db.session.add(res)
    # app.logger.info(["result object", res, res.get_q_section])
    # res = db.session.query(Response).filter_by(get_q_section="Reading")
    # app.logger.info(["result object", res, res.get_q_section])
    #app.logger.info(['path', ])
    result = [request.headers.get('X-Forwarded-For', request.remote_addr),
        request.environ['REMOTE_ADDR'],
        request.environ.get('HTTP_X_REAL_IP', request.remote_addr)]
    app.logger.info(result)
    return json.dumps(result)

def store_audio(user, blob, test_name):
    try:
        useraudio = UserAudio(user=user, blob1=blob, test_name=test_name)
        db.session.add(useraudio)
        db.session.commit()
        return useraudio.blob1
    except Exception as e:
        app.logger.error(e)
        return None

@app.route('/audio_upload', methods=["POST"])
@login_required
def audio_upload():
    file = request.files['file']
    test_name = request.form['test_name']
    app.logger.info("test name in audio upload %s"%(test_name))
    user=session['user']['email']
    if file:
        useraudio = store_audio(user, file.read(), test_name)
        if useraudio:
            return app.response_class(base64.b64encode(useraudio), mimetype="audio/webm")
        else:
            return "Record Not Saved.\n\n"+str(useraudio)
    else:
        return "Audio not recieved from user."


@app.route('/get_audio/<test_name>', methods=["GET"])
@login_required
def get_audio(test_name, user=None):
    #app.logger.info("get audio called")
    user = user if user else session['user']['email']
    event = UserAudio.query.filter_by(user=user, test_name=test_name).order_by(UserAudio.time.desc()).first()
    if not event:
        return "Audio not found"
    # app.logger.info(event.blob1)
    return app.response_class(base64.b64encode(event.blob1), mimetype="audio/webm")
    # return '<audio src="data:audio/webm;base64,'+base64.b64encode(event.blob1).decode('utf-8')+'" controls></audio>'


@app.route('/', methods=['GET'])
@login_required
def index(role=None):
    # return render_template('index.html')
    if request.method == "GET":
        if not role:
            if 'role' not in session['user']:
                return "Your account still not activated, Please come here after activation of your account."
            role = session['user']['role']
        return redirect(url_for(role))
    else:
        return None


def get_role_from_session():
    if 'user' in session:
        if 'role' in session['user']:
            return session["user"]['role']
    return None

def get_email_from_session():
    if 'user' in session:
        return session["user"]['email']
    return None


def delete_entries(Object, email):
    try:
        entries = Object.query.filter_by(emailid=email).all()
    except Exception as e:
        app.logger.error(e)
        entries = Object.query.filter_by(email=email).all()
    for entry in entries:
        db.session.delete(entry)
    db.session.commit()

def allowed_to_take_test(testid=None, email=None, role=None):

    if not email or not testid or not role:
        return False

    studenttests = getAllTestRecord(email)
    if role=="admin":
        delete_entries(Response(), email)
        delete_entries(TestDetails(), email)
        return True
    if not studenttests:
        #app.logger.info(studenttests)
        return False
    app.logger.info("Student Tests %s for student %s"%(studenttests, email))
    app.logger.info("testid %s in tests %s %s %s"%(testid, studenttests, type(studenttests), type(studenttests[0])))
    app.logger.info("testid %s in tests %s"%(type(testid), testid in studenttests))
    if testid in studenttests:

        result = Tests.query.filter_by(name=testid).first()
        if result:
            return result.isHosted()
    return False

@app.route('/quiz/<test_name>')
@login_required
def quiz(test_name, email=None):
    # return render_template('index.html')
    role = get_role_from_session()
    email = email if email else get_email_from_session()
    if not role:
        return "Your account still not activated, Please come here after activation of your account."
    if allowed_to_take_test(test_name, email, role):
        # return render_template('index.html')
        if len(TestDetails.query \
                .filter(TestDetails.email==email,TestDetails.test_name==test_name) \
                .all()) != 0:
            return redirect("/checklogin/"+test_name)
        else:
            return render_template('index.html', test_name=test_name)
    app.logger.info("Allowed %s"%(allowed_to_take_test(test_name, email, role)))
    return redirect(url_for(role))

@app.route('/javascripts/<path:path>')
def send_javascripts(path):
    app.logger.info("seeking for "+path)
    return send_from_directory('static/javascripts', path)

@app.route('/src/<path:path>')
def send_src(path):
    #app.logger.info("seeking for "+path)
    return send_from_directory('static/src', path)

@app.route('/js/<path:path>')
def send_js(path):
    #app.logger.info("seeking for "+path)
    return send_from_directory('static/js', path)

@app.route('/video/<path:path>')
def send_video(path):
    return send_from_directory('static/video', path)

@app.route('/stylesheets/<path:path>')
def send_stylesheets(path):
    return send_from_directory('static/stylesheets', path)

def add_first_response(test_name, email=None):
    if not email or email == "":
        return False
    response = Response.query.filter_by(emailid=email, test_name=test_name).first()
    if response is None:
        try:
            response = Response(emailid=email, name=email, test_name=test_name)
            db.session.add(response)
            db.session.commit()

            return True
        except Exception as e:
            app.logger.error(e)
            return False
    return True

def get_user_details(email):
    user = userDetails.query.filter_by(email=email).first()
    #app.logger.info(user)
    return user

@app.route('/checklogin/<test_name>')
@login_required
def checklogin(test_name, email=None):
    email = email if email else get_email_from_session()
    if test_name:
        first_response = add_first_response(test_name,email)
        if not first_response:
            return redirect(url_for("error", error="checklogin: Something is wrong with checking your session. Please contact test admin."))

        userdetails = get_user_details(email)
        if userdetails:
            return redirect("/startquiz/"+test_name)
        else:
            return render_template('register.html')
    return redirect("/")

def add_user_profile(name=None,email=None,phno=None,rollno=None,learningcenter=None):
    if name == None or name == "" or email == None or email == "" or phno == None or phno == "" or rollno == None or rollno == "":
        return False
    userdetails = userDetails.query.filter_by(email=email).first()
    if not userdetails:
        try:
            userdetails = userDetails(name=name,email=email,phno=phno,rollno=rollno,learningcenter=learningcenter)
            db.session.add(userdetails)
            db.session.commit()
            return True
        except Exception as e:
            #app.logger.error(e)
            return False
    return False

@app.route('/savepersonaldata', methods=['POST'])
@login_required
def savepersonaldata(email=None):
    name = request.form['name']
    email = email if email else get_email_from_session()
    phno=request.form['phone']
    rollno=request.form['rollno']
    # learningcenter=request.form['learningcenter']
    learningcenter=""

    addprofile = add_user_profile(name,email,phno,rollno,learningcenter)
    if not addprofile:
        return redirect(url_for("error", error="savepersonaldata: Error updating your profile."))
    return redirect("/")

def checkrandomizetable(email,test_name):
    return Randomize.query.filter_by(user1=email,test_name=test_name).all()

def qidlisttodict(question_ids=None):
    if question_ids == None:
        return False
    qid_list={}
    for data in question_ids:
        qid_list[int(data.qno)] = data.serialno
    return qid_list

def add_to_randomize(email=None,serialno=None,qno=None,test_name=None):
    if email == None or email == "" or serialno == None or serialno == "" or qno == None or qno == "" or test_name == None:
        return False
    userdetails = userDetails.query.filter_by(email=email).first()
    try:
        r = Randomize(user1 = email, serialno = serialno, qno=qno, test_name=test_name)
        db.session.add(r)
        db.session.commit()
        return True
    except Exception as e:
        app.logger.error(e)
        return False

def setquizstatus(email=None, test_name=None):
    if email == None or test_name==None:
        return False
    td = TestDetails.query.filter_by(email=email, test_name=test_name).first()
    if td:
        if td.testend:
            return 'END'
        else:
            return 'INPROGRESS'
    else:
        return 'START'

def quizstatus(test_name, email=None):
    if email == None or not test_name:
        return False
    td = TestDetails.query.filter(TestDetails.email==email, TestDetails.test_name==test_name).first()
    # app.logger.info(td, test_name)
    if td:
        if td.testend:
            return 'END'
        else:
            return 'INPROGRESS'
    else:
        return 'START'

#pending
def buildquizobject(email,isRandomized,json_data,test_name):
    #app.logger.info(json_data)
    for key in json_data:
        if  key == "section":
            section = json_data[key]
            for s in  section:
                for key in s:
                    if key == "subsection":
                        for subs in s[key]:
                            for key in subs:
                                if key == "questions":
                                    for q in subs[key]:
                                        if not isRandomized:
                                            add_to_randomize(email,q['serialno'], q["id"],test_name)
                                        #     r = Randomize.query.filter_by(user1 = session['user']['email'], qno = q["id"]).all()
                                        q1 = Response.query.filter_by(emailid=email, currentQuestion=q["id"], test_name=test_name).order_by(Response.time.desc()).first()
                                        # app.logger.info("respponse is %s "%q1)
                                        if q1:
                                            q["responseAnswer"]=q1.submittedans
                                            q["responseTime"]=q1.responsetime
                                            q["status"]=q1.q_status
                                            q["test_name"] = q1.test_name
    json_data['quizStatus'] = quizstatus(test_name, email)
    # app.logger.info(json_data)
    return json_data

@app.route('/getquizstatus', methods=['POST'])
@login_required
def getquizstatus(email=None):
    email = email if email else get_email_from_session()
    role = get_role_from_session()
    test_name = str(request.get_data(),'utf-8')
    isAllowed = allowed_to_take_test(test_name, email, role)
    question_ids = checkrandomizetable(email,test_name)
    if not isAllowed:
        app.logger.info("is not allowed %s"%isAllowed)
        self.redirect("/")
    # check if user resumes the test and get/generate accordingly
    test = Tests.query.filter_by(name=test_name).first()
    path = ""
    if test:
        path = "static/content/%s/%s/"%(test.test_mode, str_date_filepath(test.start_date))
        app.logger.info("constructed path for getquesiton paper %s"%path)
    if question_ids:
        isRandomized = True
        qid_dict = qidlisttodict(question_ids)
        json_data=getQuestionPaper(qid_dict,path)
        #app.logger.info("User is Resuming Test")
    else:
        isRandomized = False
        json_data=generateQuestionPaper(path)
        #app.logger.info("User is Starting Test")

    # build quiz object based on get/generated question paper and set
    quiz_status_object = buildquizobject(email,isRandomized,json_data,test_name)
    return json.dumps(quiz_status_object)

def addtestdetails(email=None,test=None,delays=None,test_name=None):
    if email == None or email == "" or test == None or test == "" or test_name==None:
        return False
    try:
        testdetails = TestDetails(email=email,test=test,delays=delays,test_name=test_name)
        db.session.add(testdetails)
        db.session.commit()
        return True
    except Exception as e:
        #app.logger.error(e)
        return False

#pending
def updatetimeobj(td):
    duration = 60*60
    if not td.testend:
        currTime = datetime.now()
        deltaTime = (currTime - td.lastPing).total_seconds()
        if(deltaTime > 65.0):
            td.delays = td.delays + deltaTime - 60.0

        timeSpent = (currTime - td.teststime).total_seconds() - td.delays

        if timeSpent >= duration:
            td.testend = True
            quizStatus = u"END"
        else:
            quizStatus = u"INPROGRESS"

        obj = {u"timeSpent" : timeSpent, u"quizStatus": quizStatus, u"timeRemaining" : duration - timeSpent}
        td.lastPing = currTime
    else:
        obj = {u"quizStatus":u"END"}

    return td, obj

@app.route('/testtime', methods=['POST'])
@login_required
def testtime(email=None):
    email = email if email else get_email_from_session()
    #app.logger.info(email)
    test_name = str(request.get_data(),'utf-8')
    duration = 60 * 60

    td = TestDetails.query.filter_by(email=email, test_name=test_name).first()
    #app.logger.info(td)
    if td is None:
        addtestdetails(email,True,0.0,test_name)
        time_obj = {u"timeSpent":0, u"timeRemaining":duration, u"quizStatus": u"INPROGRESS"}
    else:
        td, time_obj = updatetimeobj(td)
        db.session.add(td)
        db.session.commit()

    return json.dumps(time_obj)

def convert_to_minutes(responsetime):
    number_of_seconds = responsetime
    minutes = time.strftime("%M:%S", time.gmtime(number_of_seconds))
    #app.logger.info(minutes)
    return minutes

#pending
def getsubmittedresponse(email,request_data):
    vals = json.loads(cgi.escape(request_data))
    vals = vals['jsonData']

    currentQuestion =int(vals['id'])
    submittedans = vals['responseAnswer']
    responsetime = vals['responseTime']
    test_name = vals["test_name"]

    return email,currentQuestion,submittedans,responsetime,test_name

def get_q_section(currentQuestion):
    if currentQuestion in range(e1_start,e1_end):
        return "Reading"
    elif currentQuestion in range(e2_start,e2_end):
        return "Listening"
    elif currentQuestion in range(e3_start,e3_end):
        return "Speaking"
    elif currentQuestion in range(e4_start,e4_end):
        return "Writing"
    else:
        return None

def storeresponse(test_name,email=None,currentQuestion=None,submittedans=None,responsetime=None,score=0):
    app.logger.info([email, test_name])
    if email == None or email == "" or test_name==None:
        return {u"status":"error" , u"q_status":None, u"validresponse":"false", u"qid":None, u"test_name":None}
    try:
        if submittedans == "skip":
            validresponse="true"
            q_status="skip"

        if currentQuestion in range(e3_start,e3_end):
            r=UserAudio.query.filter_by(user=email).first()
            if r :
                q_status="submitted"
                status="success"
                validresponse="true"
            else :
                q_status="submitted"
                status="success"
                validresponse="true"
        if currentQuestion in range(e4_start,e4_end):
            q_status="submitted"
            status="success"
            validresponse="true"
        else :
            q_status="submitted"
            status="success"
            validresponse="true"
            test = Tests.query.filter_by(name=test_name).first()
            path = "static/content/%s/%s/"%(test.test_mode, str_date_filepath(test.start_date))
            cans=getAnswer(currentQuestion,path)
            if cans == submittedans:
                score = 1

        if validresponse=="true":
            status="success"
            if q_status!="skip":
                q_status="submitted"
        else:
            status="error"
        q_section = get_q_section(currentQuestion)
        data=Response(ip=request.headers.get('X-Forwarded-For', request.remote_addr), q_section=q_section, serialno=currentQuestion,emailid=email,name=email,currentQuestion=str(currentQuestion),submittedans=submittedans,responsetime=responsetime,q_status=q_status,q_score=score, test_name=test_name)
        db.session.add(data)
        db.session.commit()
        status="success"
    except Exception as e:
        app.logger.info(e)
        status="error"

    responseobj = {u"status":status , u"q_status":q_status, u"validresponse":"true", u"qid":currentQuestion, u"test_name":test_name}
    app.logger.info(responseobj)
    # app.logger.info([data.q_section, data.emailid, data.submittedans, data.q_status])
    return responseobj

@app.route('/submitanswer', methods=["POST"])
@login_required
def submitanswer(email=None):
    email = email if email else get_email_from_session()
    #app.logger.info([email, "im submitanswer"])
    request_data = str(request.get_data(),'utf-8')
    email, currentQuestion, submittedans, responsetime, test_name = getsubmittedresponse(email,request_data)

    td=TestDetails.query.filter_by(email=email,test_name=test_name).first()
    #app.logger.info([td, "im submitanswer"])
    if td and not td.testend:
        #app.logger.info([td, "im submitanswer, in loop"])

        #app.logger.info([email, currentQuestion, "im submitanswer, in loop1"])
        app.logger.info(test_name)
        responseobj = storeresponse(test_name, email, currentQuestion, submittedans, responsetime)
        #app.logger.info([responseobj, "im submitanswer, in loop2"])
    else:
        responseobj = {u"testEnd" : True}

    return json.dumps(responseobj)

def getResultOfStudent(email=None, test_name=None):
    if email == None or email == "" or test_name == None or test_name == "":
        return json.dumps({"totalscore": 0, "question": []})
    totalscore = 0
    q1= Response.query.filter(Response.emailid==email, Response.test_name==test_name) \
        .order_by(Response.serialno, Response.time.desc()).all()
    questionresponses_dict = {}
    question_records=[]
    totalscore=0
    s1="0"
    for q in q1:
        if q.responsetime is not None:
            if q.currentQuestion != s1 :
                s1=q.currentQuestion
                #totalscore=q.responsetime+q.q_score
                question = {"user":email,"submittedans":q.submittedans, "q_score":q.q_score,"currentQuestion":s1,"responsetime":q.responsetime, "ip":q.ip}
                question_records.append(question)
    questionresponses_dict["question"]=question_records
    questionresponses_dict["totalscore"]=totalscore
    ss=json.dumps(questionresponses_dict)
    return ss

@app.route('/getResult/<test_name>', methods=["GET", "POST"])
@login_required
def getResult(test_name):
    app.logger.info("Im in get result for %s"%test_name)
    if request.method=="POST":
        email = request.form['emailid']
        return getResultOfStudent(email, test_name)
        #app.logger.info(["post", email])

    if request.method == "GET":
        email = get_email_from_session()
        return getResultOfStudent(email, test_name)


@app.route('/getstudentscore/<test_name>/<email>', methods=["GET"])
@admin_login_required
def getstudentscore(test_name, email):
    return render_template('studentscore.html', test_name=test_name, email=email)

@app.route('/testresult/<test_name>', methods=["GET"])
@admin_login_required
def testresult(test_name):
    return render_template("testresult.html", test_name=test_name)

@app.route('/viewresults', methods=["GET"])
@admin_login_required
def viewresults():
    result = Tests.query.filter_by(creator=get_email_from_session()).all()
    return render_template("viewresults.html", tests=result)

@app.route('/getScore', methods=["GET"])
@admin_login_required
def getScore(email=None):
    if not email:
        email = session["user"]['email']
    score=0
    q1= Response.query.filter_by(emailid=email).all()
    for q in q1:
        score=score+1
    template_values = {
        'p': q1,
        'score1':score,
        }
    return render_template("testresult.html")

#pending
def getessayresponse(data):
    vals = json.loads(data.decode("utf-8"))
    vals = vals['jsonData']
    qid = vals['currentQuestion']
    ans = vals['draft'] if 'draft' in vals else ""
    qattemptedtime = vals['responsetime']
    test_name = vals['test_name']
    return vals, qid, ans, qattemptedtime, test_name

def saveessay(test_name,row=None,email=None,qid=None,ansText=None,qattemptedtime=None):
    if email == None or email == "":
        return False
    try:
        if row:
            row.qattemptedtime=qattemptedtime
            row.ansText = ansText
            db.session.add(row)
            db.session.commit()
        else:
            data = EssayTypeResponse(useremailid=email, qid=qid, qattemptedtime=qattemptedtime, ansText = ansText, test_name=test_name)
            db.session.add(data)
            db.session.commit()
        return True
    except Exception as e:
        #app.logger.info(e)
        return False

@app.route('/autosaveEssay', methods=["POST"])
@login_required
def autosaveEssay(email=None):
    email = email if email else get_email_from_session()

    data = request.get_data()
    essay_response, qid, ans, qattemptedtime, test_name = getessayresponse(data)

    data = EssayTypeResponse.query.filter_by(useremailid = email, qid = qid, test_name=test_name).first()
    saveessay(test_name,data,email,qid,ans,qattemptedtime)

    return json.dumps(essay_response)

@app.route('/uploadredirect', methods=["POST"])
def uploadredirect():
    return redirect(url_for("/upload_audio"))

@app.route('/upload_audio', methods=["POST"])
@login_required
def upload_audio():
    try:
        files = request.files.getlist('file')
        if files:
            useraudio = UserAudio(user=session['user']['email'], blob1=files[0].file.read())
            db.session.add(useraudio)
            db.session.commit()
    except Exception as e:
        return "Record Not Saved.\n\n"+str(e)

@app.route('/view_audio/<link>', methods=["GET"])
@login_required
def view_audio(link):
    event = UserAudio.query.get_or_404(link)
    return app.response_class(event.blob1, mimetype='application/octet-stream')

# @app.route('/audio')
# def audio():
#pending
def getendtestdata(request_data):
    try:
        val = request_data['jsonData']
        testend = val['testend']
        score = val['finalScore']
        spklink = val['spklink']
        test_name = val['test_name']
    except Exception as e:
        app.logger.info(e)
        return False
    return val, testend, score, spklink, test_name

def getlearningcentre(email=None):
    if email == None or email == "":
        return False
    try:
        userdata=userDetails.query.filter_by(email = email).first()
        learningcenter=userdata.learningcenter
        return learningcenter
    except Exception as e:
        app.logger.info(e)
        return False

#pending
def updatetestdetails(data=None,testend=None,score=None,learningcenter=None):
    if data == None:
        return False
    try:
        data.testend = testend
        data.score = score
        data.learningcenter = learningcenter
        db.session.add(data)
        db.session.commit()
        return True
    except Exception as e:
        app.logger.info(e)
        return False

@app.route('/endtest', methods=["POST"])
@login_required
def endtest(email=None):
    email = email if email else get_email_from_session()

    data = json.loads(cgi.escape(str(request.get_data(), 'utf-8')))
    end_test_data, testend, score, spkling, test_name = getendtestdata(data)

    data1 = TestDetails.query.filter_by(email = email, test_name=test_name).first()
    if data1:
        learningcenter = getlearningcentre(email)
        if not learningcenter:
            learningcenter = ""
        updatetestdetails(data1,testend,score,learningcenter)

def get_rollno(email=None):
    if email:
        student = Students.query.filter_by(emailid=email).first()
        if student:
            return student.rollno
    return None

@app.route('/startquiz/<test_name>')
@login_required
def startquiz(test_name):
    if test_name:
        email = session['user']['email']
        rollno = get_rollno(email)
        rollno = email if not rollno else rollno
        test = Tests.query.filter_by(name=test_name).first()
        mode = test.test_mode

        return render_template('quiz.html', rollno=rollno, test_name=test_name, mode=mode)
    return redirect("/")

def generate_unique_code():
    return str(uuid.uuid1()).replace("-", "")

def valid_user_login(email, password):
    #app.logger.info("Im in valid user login method")
    user = Users.query.filter_by(emailid=email, password=hashlib.md5(password.encode('utf-8')).hexdigest()).first()
    #app.logger.info([user,email,password])
    if user:
        return user
    return None

@app.route('/student', methods=['GET'])
@login_required
def student():
    if request.method == "GET":
        return render_template('student.html')

def makestatusbutton(email,hosted, testid):
    if hosted:
        td = TestDetails.query.filter(TestDetails.email==email, TestDetails.test_name==testid).first()
        if td:
            if td.testend:
                button = "<a href='/quiz/"+str(testid)+"' class='btn btn-sm btn-default'>View Result (score: "+str(td.score)+")</a>"
            else:
                button = "<a href='/quiz/"+str(testid)+"' class='btn btn-sm btn-warning'>Resume Test</a>"
        else:
            button = "<a href='/quiz/"+str(testid)+"' class='btn btn-sm btn-primary'>Attempt Test</a>"

    else:
        button = "<a href='#' class='btn btn-sm btn-warning' disabled>Locked</a>"
    return button

def gettestdetails(test_name, email=None):
    if email==None or email=="" or test_name == None or test_name == "":
        return []
    test_details = []
    app.logger.info("tests for testid is %s"%test_name)
    result = Tests.query.filter_by(name=str(test_name)).first()
    app.logger.info("tests %s"%result)
    if result:
        test_details = str(result).split("::")
        button = makestatusbutton(email, result.isHosted(), test_name)
        test_details.append(button)
        # tests.append(test_details)
        app.logger.info("gettestdetails function output %s for test name %s"%(test_details, test_name))
    return test_details

@app.route('/studenttests', methods=['GET'])
@login_required
def studenttests(emailid=None):
    if not emailid:
        emailid = get_email_from_session()
    result = getAllTestRecord(emailid)
    final = {"data": []}
    app.logger.info("All tests student with email %s invited for %s"%(emailid, result))
    if result != None:
        tests = result
        # app.logger.info([tests, type(getavailabletests(tests[0]))])
        for test in tests:
            app.logger.info(test)
            test_details = gettestdetails(test,emailid)
            if test_details:
                final["data"].append(test_details)

    app.logger.info("studenttests output %s for email %s"%(final, emailid))
    return json.dumps(final)

def set_session(email=None, role=None):
    session['user'] = {}
    session['user']['email'] = email
    session['user']['role'] = role
    session['user']['allow_to_set_password'] = True

@app.route('/verify/<email>/<code>', methods=['GET'])
def verify_unique_code(email, code):
    if request.method == 'GET':
        email = base64.b64decode(email).decode()
        #app.logger.info("Verifying code for %s with code %s"%(email, code))

        user = Users.query.filter_by(emailid=email, password=code).first()
        if user:
            try:
                user.verified = True
                db.session.add(user)
                db.session.commit()
                set_session(user.emailid)
                return render_template("set_password.html",
                    success="You are successfully activated your account.\n Please login")
            except Exception as e:
                return render_template("error.html", error=e)
        return render_template("unauthorized.html", error="Your verification code is invalid, contact admin")

def add_default_user_admin_if_not_exist():
    admin = Users.query.filter_by(user_type="admin").first()
    if admin is None:
        if add_user_if_not_exist("admin@quiz.in","admin","admin",True):
            return True
    return False

def add_user_if_not_exist(email=None, password=generate_unique_code(), user_type="student", verified=False):
    user = Users.query.filter_by(emailid=email).first()
    if user is None:
        try:
            password = hashlib.md5(password.encode('utf-8')).hexdigest()
            user = Users(email, password, user_type, verified)
            db.session.add(user)
            db.session.commit()
            return user
        except Exception as e:
            app.logger.error(e)
    return False

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Create default admin credentials if not already exists
    add_default_user_admin_if_not_exist()
    role = get_role_from_session()
    if role:
            return redirect(url_for(role))
    if request.method == "GET":
        return render_template('login.html')
    if request.method == "POST":
        #app.logger.info('Login page post request')
        ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
        email = request.form['email']
        password = request.form['password']
        #app.logger.info([email, password])
        user = valid_user_login(email, password)
        if user:
            if user.verified != "false":
                email = user.emailid
                role = user.user_type
                set_session(email, role)
                if role == "admin" and password == "admin":
                    return redirect(url_for("setpassword"))
                message = "You are logged in as %s" % email
                #app.logger.info(["is user verified ", user.verified])
                # app.logger.info("Logged in as %s with IP %s" % (email, ip_address))
                db.session.add(LoginLog(emailid=email, ip=ip_address))
                db.session.commit()
                return redirect(url_for(role))
            else:
                error = "Please activate your account, using the link we sent to your registered email"
                app.logger.info("Tried to login in as %s from IP %s, but Account not activated." % (email, ip_address))
        else:
            error = "Invalid Credentials"
            app.logger.info("Tried to login in as %s from IP %s, but Invalid Credentials." % (email, ip_address))
        return render_template('login.html', error=error)

@app.route('/logout')
@login_required
def logout():
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
    login_log.debug("%s logged out with IP %s." % (session['user']["email"], ip_address))
    session.clear()
    # session.pop('user', None)
    # session.pop('TestID', None)
    return redirect(url_for('login'))

def sendMail(encode='Testing', code='Testing', email='rguktemailtest@gmail.com'):
    try:
        #app.logger.debug("send mail function")
        body = """Dear Student,<br> This email message is sent by the online quiz portal.
        By clicking the link below you are verifying that this email belongs to you and your account will be activated.
        Click on the link below and follow the instructions to complete the registration process.
        <h1><a href=%s/verify/%s/%s>Verify</a></h1> """ % (request.host, encode, code)
        #app.logger.info(body)
        response = requests.post(
            "https://api.mailgun.net/v3/"+app.config['NUZVID_MAIL_GUN_DOMAIN']+"/messages",
            auth=("api", app.config['NUZVID_MAIL_GUN_KEY']),
            data={"from": "RGUKT QUIZ <news@"+app.config['NUZVID_MAIL_GUN_DOMAIN']+">",
                  "to": [email],
                  "subject": 'Account Verification for RGUKT QUIZ',
                  "text": '',
                  "html": body})
        #app.logger.info([response.status_code, response.text])
        if response.status_code == 200:
            return True
    except Exception as e:
        app.logger.debug("Something went wrong in sending verification mail, please try again "+str(e))
    return False

@app.route('/registration', methods=['GET', 'POST'])
def registration():
    if get_role_from_session():
        return redirect(url_for(get_role_from_session()))
    if request.method == "GET":
        login_log.debug("Get registration Form")
        return render_template('registration.html')
    elif request.method == "POST":
        login_log.debug("post registration Form")

        message = ""
        message_staus = ""
        login_log.debug("post registration Form")

        email = request.form["email"]
        exists = db.session.query(Users).filter_by(emailid=email).scalar() is not None
        # if email[-9:] != ".rgukt.in":
        #     message = "Email ID must be from RGUKT"
        #     message_staus = "danger"

        if not exists:
            code = generate_unique_code()
            user = add_user_if_not_exist(email, code,"student",False)
            if user:
                encode = base64.b64encode(email.encode()).decode()
                code = hashlib.md5(code.encode('utf-8')).hexdigest()
                #app.logger.info("Verifying code for %s with code %s"%(email, code))

                sent = sendMail(encode, code, email)
                if sent:
                    #app.logger.debug("an email has been sent to your email address "+email+". Please go to your inbox and click on the link to verify and activate your account")
                    message = "An email has been sent to your email address "+email+". Please go to your inbox and click on the link to verify and activate your account"
                    message_staus = "success"
                else:
                    db.session.delete(user)
                    db.session.commit()
                    #app.logger.debug("Something went wrong in sending verification mail, please try again")
                    message = "Something went wrong in sending verification mail, please try again"
                    message_staus = "danger"
            else:
                #app.logger.debug("Something went wrong in creating user, please try again")
                message = "Something went wrong in creating user, please try again"
                message_staus = "danger"
        else:
            message = str(email) + " already exists, Please check your inbox for verification mail or contact admin"
            message_staus = "danger"

        return render_template('registration.html', message=message, status=message_staus)

def update_password(user, password):
    try:
        user.password = hashlib.md5(password.encode('utf-8')).hexdigest()
        # db.session.add(user)
        db.session.commit()
        return True
    except Exception as e:
        app.logger.error(e)
    return False

def send_email_with_password(email, password):
    try:
        #app.logger.debug("send mail function")
        body = """Dear Student,<br> This email message is sent by the online quiz portal.
        Use below password to <h1><a href=%s/login>Login</a></h1>
        <br><br>Login : %s <br>Password : %s
        """ % (request.host, email, password)
        #app.logger.info(body)
        response = requests.post(
            "https://api.mailgun.net/v3/"+app.config['NUZVID_MAIL_GUN_DOMAIN']+"/messages",
            auth=("api", app.config['NUZVID_MAIL_GUN_KEY']),
            data={"from": "RGUKT QUIZ <news@"+app.config['NUZVID_MAIL_GUN_DOMAIN']+">",
                  "to": [email],
                  "subject": 'Account Verification for RGUKT QUIZ',
                  "text": '',
                  "html": body})
        #app.logger.info([response.status_code, response.text])
        if response.status_code == 200:
            return True
    except Exception as e:
        app.logger.debug("Something went wrong in sending password mail, please try again "+str(e))
    return False

@app.route('/setpassword', methods=['GET', 'POST'])
@login_required
def setpassword():
    if 'allow_to_set_password' not in session['user']:
        return redirect(url_for("login"))
    if request.method == "GET":
        return render_template('set_password.html')
    elif request.method == "POST":
        email = session["user"]['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        if password == confirm_password:
            user = Users.query.filter_by(emailid=email).first()
            if user:
                updated = update_password(user, password)
                if updated:
                    if not send_email_with_password(email, password):
                        app.logger.info("An email with password sending is failed")
                    message = "Password successfully change, Please login"
                    return render_template('login.html', success=message)
                else:
                    message = "Password change failed, Please try again"
                    message_staus = "error"
                    return render_template("set_password.html", message=message, status=message_staus)
            else:
                message = "Your email address dosen't exist, Please register"
                message_staus = "error"
                return render_template("registration.html", message=message, status=message_staus)

        else:
            message = "Password and ConfirmPassword should match"
            message_staus = "error"

            return render_template("set_password.html", message=message, status=message_staus)

@app.route('/audio', methods=['GET', 'POST'])
@login_required
def audio():
    return render_template("audio.html")

def get_today_ddmmyyyy():
    fmt = '%d-%m-%Y'
    today = datetime.now(IST)
    todayf = today.strftime(fmt)
    return todayf

def today_ddmmyy():
    fmt = '%d-%m-%y'
    today = datetime.now(IST)
    todayf = today.strftime(fmt)
    return str(todayf)

def is_safe_path(basedir, path, follow_symlinks=True):
  # resolves symbolic links
  if follow_symlinks:
    return os.path.realpath(path).startswith(basedir)

  return os.path.abspath(path).startswith(basedir)

def convert_string_date(date):
    try:
        return datetime.strptime(date, '%d-%m-%Y').date()
    except Exception as e:
        app.logger.info("Error while converting string_to_date funciton %s"%e)
        return datetime.now().date()

@app.route('/content/<test_mode>/<datetoday>/<filename>')
@login_required
def send_content(test_mode, datetoday,filename):
    app.logger.info("Im in send_content with %s/%s"%(test_mode, datetoday))
    email = get_email_from_session()
    role = get_role_from_session()
    # if setquizstatus(email) == "INPROGRESS":
    #     return redirect("/")
    date1 = convert_string_date(get_today_ddmmyyyy())
    date2 = convert_string_date(datetoday)
    app.logger.info("date %s and type %s result %s"%(date1, date2, date1 >= date2))
    safe = is_safe_path(APP_ROOT, '/content/%s/%s/%s'%(test_mode, datetoday, filename))
    app.logger.info("safe %s"%safe)
    app.logger.info("app root %s"%APP_ROOT+'/../dep_content/%s/%s/'%(test_mode, datetoday))
    #the below link is tested by putting the folder outside of the root
    # return send_from_directory(APP_ROOT+'/../dep_content/%s/%s/'%(test_mode, datetoday), filename)
    if date1 >= date2:
        return send_from_directory('static/content/%s/%s/'%(test_mode, datetoday), filename)
    else:
        return "<h3>Error 404 in displaying the content you requested. Please contact Exam Admin.</h3>"
#
# Reading Task Handlers
#

def build_reading_task():
    task = {}
    today = today_ddmmyy()
    filepath = "/content/"+today+"/reading.pdf"
    task["filepath"] = filepath
    return task

def str_date_filepath(date):
    if date:
        date = date.split()[0]
    return date

@app.route("/readingtask/<test_name>", methods=["GET"])
@login_required
def readingtask(test_name):
    try:
        email = get_email_from_session()
        reading_task = None
        test = Tests.query.filter_by(name=test_name).first()
        path = ""
        if test:
            path = "/content/%s/%s/reading.pdf"%(test.test_mode, str_date_filepath(test.start_date))
            app.logger.info("constructed path %s"%path)
        if setquizstatus(email, test_name) != "INPROGRESS":
            reading_task = build_reading_task()
            if path != "":
                reading_task = {"filepath":path}
            return render_template('readingtask.html', task=reading_task, test_name=test_name)
        else:
            return redirect("/")
    except Exception as e:
        app.logger.info(e)
        return render_template('error.html', error="RTExec: Exception while presenting Reading Task")

def send_file_partial(path):
    # logging.info(path)
    # path = "static/content/02-08-17/listening.mp4"
    # path = "static/content/"+str(today_ddmmyy())+"/"+path
    """
        Simple wrapper around send_file which handles HTTP 206 Partial Content
        (byte ranges)
        TODO: handle all send_file args, mirror send_file's error handling
        (if it has any)
    """
    range_header = request.headers.get('Range', None)
    if not range_header: return send_file(path)

    size = os.path.getsize(path)
    byte1, byte2 = 0, None

    m = re.search('(\d+)-(\d*)', range_header)
    g = m.groups()

    if g[0]: byte1 = int(g[0])
    if g[1]: byte2 = int(g[1])

    length = size - byte1
    if byte2 is not None:
        length = byte2 + 1 - byte1

    data = None
    with open(path, 'rb') as f:
        f.seek(byte1)
        data = f.read(length)

    rv = ress(data,
        206,
        mimetype=mimetypes.guess_type(path)[0],
        direct_passthrough=True)
    rv.headers.add('Content-Range', 'bytes {0}-{1}/{2}'.format(byte1, byte1 + length - 1, size))

    return rv

@app.after_request
def after_request(response):
    response.headers.add('Accept-Ranges', 'bytes')
    return response

@app.route('/play/<path:song>')
def play(song):
    app.logger.info("listening video path %s"%"static/"+song)
    return send_file_partial("static/"+song)


#
# Listening Task Handlers
#
def build_listening_task():
    task = {}
    today = today_ddmmyy()
    filepath = "/content/"+today+"/listening.mp4"
    task["filepath"] = filepath
    return task

@app.route("/listeningtask/<test_name>", methods=["GET"])
@login_required
def listeningtask(test_name):
    try:
        email = get_email_from_session()
        listening_task = None
        test = Tests.query.filter_by(name=test_name).first()
        path = ""
        if test:
            path = "/content/%s/%s/listening.mp4"%(test.test_mode, str_date_filepath(test.start_date))
            app.logger.info("constructed path for listening %s"%path)
        if setquizstatus(email, test_name) != "INPROGRESS":
            listening_task = build_listening_task()
            if path != "":
                listening_task = {"filepath":path}
            return render_template('listeningtask.html', task=listening_task, test_name=test_name)
        else:
            return redirect("/")
    except Exception as e:
        app.logger.info(e)
        return render_template('error.html', error="LTExec: Exception while presenting Listening Task")

#==================================================== ADMIN PAGE =====================================================
# def valid_admin_login(email, password):
#     result = AdminDetails.query.filter_by(email=email).first()
#     if str(result) == str(password):
#         return True
#     return False

# @app.route('/adminlogin', methods=['GET', 'POST'])
# def adminlogin():
#     ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)

#     if db.session.query(AdminDetails).first() is None:
#         row = AdminDetails("admin@quiz.in","admin")
#         db.session.add(row)
#         db.session.commit()

#         login_log.debug("Created Default Admin Credentials.")

#     message = None
#     error = None

#     if request.method == "POST":
#         email = request.form['email']
#         password = request.form['password']

#         if valid_admin_login(email,password):
#             session['adminemail'] = email
#             message = "You are logged in as %s" % email

#             login_log.debug("Logged in as %s with IP %s" % (email, ip_address))
#             return redirect(url_for('admin'))
#         else:
#             error = "Invalid Credentials"

#             login_log.debug("Tried to login in as %s from IP %s, but Invalid Credentials." % (email, ip_address))
#             return render_template('login.html', error=error)

#     return render_template('login.html')

# @app.route('/logout')
# def logout():
#     ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
#     login_log.debug("%s logged out with IP %s." % (session["user"]['email'], ip_address))

#     session.pop('adminemail', None)
#     return redirect(url_for('adminlogin'))

def createDefaultTest(TestID, author, start_date,end_date, test_mode):
    try:
        test = Tests(TestID,author, start_date, end_date, test_mode)
        db.session.add(test)
        db.session.commit()
        return True
    except Exception as e:
        app.logger.info(e)
        return False

def settestsession(TestID,start_date,end_date):
    try:
        session["TestID"] = TestID
        session["start_date"] = start_date
        session["end_date"] = end_date
        return True
    except Exception as e:
        app.logger.error(e)
        return redirect(url_for("error", error="settestsession: unable to save the tesr session."))

@app.route('/admin')
@admin_login_required
def admin(email=None):
    try:
        tests = Tests.query.all()
        if len(tests) != 0:

            return render_template('admin.html')
        else:
            return redirect(url_for('create'))
    except Exception as e:
        app.logger.info(e)

def getAllTestRecord(emailid):
    results = db.session.query(StudentTests.test_name) \
        .filter(StudentTests.emailid == emailid).all()

    return [r for (r, ) in results]

def validate_name(name):
    result = Tests.query.filter_by(name=name).first()
    return result == None

#Change the the now() to utcnow() and add replace method
def validate_date(date):
    fmt = '%d-%m-%Y %H:%M'
    today = datetime.now(IST)
    date = IST.localize(datetime.strptime(date, fmt))
    today = IST.localize(datetime.strptime(today.strftime(fmt), fmt))
    app.logger.info([date, today])

    return date >= today

def get_date_from_string(date):
    if date:
        return IST.localize(datetime.strptime(date, '%d-%m-%Y %H:%M'))
    else:
        return None

def validate_file(file_name,data):
    file_report = {}
    file_report["name"] = file_name
    if file_name != '' and allowed_file(file_name):
        if file_name == "QP_template.json":
            if not validate_qp_template.validate(data):
                file_report["isValid"] = validate_qp_template.errors
            else:
                file_report["isValid"] = True
        else:
            if schema_type_mapping[data["types"]].validate(data):
                file_report["isValid"] = True
            else:
                file_report["isValid"] = schema_type_mapping[data["types"]].errors
    else:
        file_report["isValid"] = 'Invalid Filename or Extension.'
    return file_report

@app.route('/uninvite/<testid>', methods=["POST"], defaults={'email': None})
@app.route('/uninvite/<email>/<testid>', methods=["GET"])
@admin_login_required
def uninvite(email, testid):
    if request.method == "GET":
        result = StudentTests.query.filter_by(emailid=email).delete()

        db.session.commit()
        return redirect("/edit/"+testid)
    if request.method == "POST":
        try:
            students_list = eval(request.get_data())['jsonData']
            app.logger.info(students_list)
            # students = updateStudents(testid, students_list)
            for email in students_list:
                result = StudentTests.query.filter_by(emailid=email).delete()
            db.session.commit()

        except Exception as e:
            app.logger.info(e)
        return ""

def save_file(folder_name,file_name,data):
    filename = secure_filename(file_name)
    path = os.path.join(app.config['UPLOAD_FOLDER'], folder_name+"/")
    if not os.path.exists(path):
        os.makedirs(path)
    with open(os.path.join(path, filename), "w+") as f:
        fJson.dump(data, f)
    # file.save(os.path.join(path, filename))
    # file.close()

def updatetests(test_name=None,email=None,start_date=None,end_date=None):
    if not test_name or not email or not start_date or not end_date:
        return False
    try:
        if not Tests.query.filter_by(name=test_name).first():

            test = Tests(test_name, email, start_date, end_date)
            db.session.add(test)
            db.session.commit()
            return True
    except Exception as e:
        app.logger.info(e)
    return False

def create_test(test_name, test_mode, start_date, end_date):

    if test_name and test_mode and start_date and end_date:
        # if not test_name:
        # test_name = test["name"]
        # test_mode = test["test_mode"] if "test_mode" in test else "TOEFL"
        #app.logger.info(test_name)
        nameValid = validate_name(test_name)

        # start_date = test["start_date"]
        startdateValid = validate_date(start_date)

        # end_date = test["end_date"]
        enddateValid = validate_date(end_date)


        if nameValid and startdateValid and enddateValid:
            #app.logger.info('%s created a Test - %s' %(admin,test_name))
            is_created = createDefaultTest(test_name,"admin@quiz.in", start_date, end_date, test_mode)
            if is_created:
                return True
            # settestsession(test_name,start_date,end_date)
        else:
            message = 'Failed to create Test - %s: %s, start_date: %s, end_date: %s' %(test_name,nameValid,startdateValid,enddateValid)
            app.logger.info('Failed to create Test - %s: %s, start_date: %s, end_date: %s' %(test_name,nameValid,startdateValid,enddateValid))
    else:
        message = 'Test - %s arguments are missing %s' %(test_name, [test_name, test_mode, start_date, end_date])
        app.logger.info('Test - %s arguments are missing %s' %(test_name, [test_name, test_mode, start_date, end_date]))

    return message

@app.route('/create', methods=["GET","POST"])
@admin_login_required
def create(admin=None, test_name=None):
    if not admin:
        admin = session["user"]['email']

    if request.method == "GET":
        tests= []
        tests.append({"name":"Daily English Practice 1","start_date":"30-08-2017 12:00","end_date":"30-09-2017 12:00", "test_mode":"DEP"})
        tests.append({"name":"Daily English Practice 2","start_date":"30-08-2017 12:00","end_date":"30-09-2017 12:00", "test_mode":"DEP"})
        tests.append({"name":"Daily English Practice 3","start_date":"30-08-2017 12:00","end_date":"30-09-2017 12:00", "test_mode":"DEP"})
        tests.append({"name":"Daily English Practice 4","start_date":"30-08-2017 12:00","end_date":"30-09-2017 12:00", "test_mode":"DEP"})
        tests.append({"name":"Daily English Practice 5","start_date":"30-08-2017 12:00","end_date":"30-09-2017 12:00", "test_mode":"DEP"})
        for test in tests:
            # definition : create_test(test_name, test_mode, start_date, end_date)
            testValid = create_test(test["name"], test["test_mode"], test["start_date"], test["end_date"])
            app.logger.info("%s test is created %s"%(test["name"], testValid))
        return redirect(url_for("admin"))

def loadTestSet():
    student = Users.query.filter_by(user_type="student").first()
    if student is None:
        for num in range(20):
            row = Users("student"+str(num)+"@quiz.in","student","student",True)
            db.session.add(row)
            db.session.commit()

def isRegistered(studentemail):
    registered = Users.query.filter(Users.emailid == studentemail).first()
    if registered:
        verified = registered.verified
        if verified == 'true':
            return True
    return False

@app.context_processor
def invited():
    def _invited(studentemail,testid):
        app.logger.info("invited function called for %s for email %s"%(testid, studentemail))
        studentrow = StudentTests.query.filter(StudentTests.emailid == studentemail,
                                                StudentTests.test_name == testid
            ).first()
        if studentrow != None:
            return True
        return False
    return dict(invited=_invited)

def updateDate(testid=None, start_date=None,end_date=None):
    if testid is not None or start_date is not None or end_date is not None:
        try:
            test = Tests.query.filter_by(name=testid).first()
            test.start_date = start_date
            test.end_date = end_date
            db.session.commit()
            return True
        except Exception as e:
            app.logger.info(e)
    return False

def updateStudents(testid, students_list):

    slist = []
    students = []
    student_table = {}
    app.logger.info("In updateStudents funtion Students %s and testid %s"%(students_list, testid))
    for student in students_list:
        student = student.lstrip()
        student = student.rstrip()
        if student == "":
            continue
        if student == "admin@quiz.in":
            student_table[student] = " Admin cannot be Invited. Admin has preview option to take the test"

        if isRegistered(student):
            tests = getAllTestRecord(student)
            app.logger.info("all tests %s"%tests)
            # if tests != None:
            if testid in tests:
                app.logger.info("%s is already Invited to %s."%(student, testid))
                student_table[student] = "is already Invited"
            else:
                studenttests = StudentTests(student, testid)
                db.session.add(studenttests)
                db.session.commit()
                # students.append(student+" is Invited.")
                app.logger.info("%s is now Invited to %s."%(student, testid))
                student_table[student] = "is Invited"
                #app.logger.info('%s is Invited' %student)
                # slist.append(student)
        else:
            # students.append(student+" is not Registered.")
            student_table[student] = "is not Registered"

            #app.logger.info('%s is not registered' %student)
    return student_table

def get_all_students():
    return Users.query.filter(Users.user_type!="admin").all()

@app.context_processor
def invitation_mail_sent():
    def _invitation_mail_sent(email, testid):
        student = StudentTests.query.filter_by(emailid=email).first()
        app.logger.info("is invitation sent to %s for test %s -> %s", email, testid, student)
        if student:
            if student.invitation_email_sent:
                return True
            app.logger.info("is invitation sent to %s for test %s -> %s", email, testid, student.invitation_email_sent)
        return False
    return dict(invitation_mail_sent=_invitation_mail_sent)

@app.route("/edit/<testid>/", defaults={'option': None})
@app.route("/edit/<testid>/<option>", methods=["GET", "POST"])
@admin_login_required
def edit(option, testid):

    # if not testid:
    #     testid = testid if testid else "English Comprehension Test"
        # app.logger.info('Edit Test Page (%s) accessed by %s' %(testid))

    if request.method == "GET" or option == None:
        invitedstudents = StudentTests.query.all()
        app.logger.info("All invited students %s"%invitedstudents)
        # db.session.add(Users("ss@fju.us", "password", "student", True))
        # db.session.commit()
        all_registered_students = get_all_students()
        app.logger.info("All registered students %s"% all_registered_students)
        return render_template("add_students.html", testid=testid, messages=False, invitedstudents=invitedstudents, allstudents=all_registered_students)

    if request.method == "POST":
        invitedstudents = False
        if option == "set_exam_time":
            invitedstudents = StudentTests.query.all()

            startdatevalid = ""
            enddatevalid = ""
            error = False
            try:
                start_date = request.form["datetimepicker1"]
                end_date = request.form["datetimepicker2"]
                if start_date != "" and end_date != "":
                    validate_start_date = validate_date(start_date)
                    validate_end_date = validate_date(end_date)

                    if validate_start_date:
                        if validate_end_date:
                            updatedate = updateDate(testid, start_date,end_date)
                            if updatedate:
                                startdatevalid = "Start Date %s is Valid and Updated." %str(start_date)
                                enddatevalid = "End Date %s is Valid and Updated." %str(end_date)
                            else:
                                startdatevalid = "Something went wrong. Please log in again to make updates."
                                enddatevalid = ""
                        else:
                            enddatevalid = "End Date %s is not Valid." %str(end_date)
                    else:
                        startdatevalid = "Start Date %s is not Valid." %str(start_date)
                else:
                    startdatevalid = "Both Start Date and End Date are required"

            except Exception as e:
                app.logger.info(e)
                # students.append(e)
                error = e

            app.logger.info('%s %s %s' %(error, startdatevalid, enddatevalid))
            return render_template("add_students.html", invitedstudents=invitedstudents,testid=testid, error=error, messages=True, startdatevalid=startdatevalid, enddatevalid=enddatevalid)
        elif option == "invite_students":
            # app.logger.info("im in invite students functionality")
            students = {}
            students_list = eval(request.get_data())['jsonData']
            app.logger.info("List of students for test invitaion %s"%students_list)
            students = updateStudents(testid, students_list)

            # try:

            #     students_list = request.form["studentslist"]
            #     if len(students_list) != 0:
            #         students_list = students_list.split("\n")
            #         #app.logger.info('Students List %s' %students_list)
            #         students = updateStudents(testid, students_list)
            # except Exception as e:
            #     app.logger.info(e)
            #     # students.append(e)
            #     students["error"] = e

            invitedstudents = StudentTests.query.all()
            #app.logger.info('%s added %s to %s' %(admin,students,testid))
            return render_template("add_students.html", invitedstudents=invitedstudents,testid=testid, students=students)
        else:
            return "No " + option + " option exist"


@app.route('/getStudentsList/<test>', methods=["GET"])
@admin_login_required
def getStudentsList(test):
    # test = session["TestID"]
    result = StudentTests.query.all()
    students = []
    for i in result:
        if test in i.test_name:
            students.append(i.emailid)
    return json.dumps({"students":students})

@app.route('/prefiledit/<name>', methods=["GET"])
@admin_login_required
def prefiledit(name):
    #app.logger.info(name)
    test = Tests.query.filter_by(name=name).first()
    if test:
        start_date = test.start_date
        end_date = test.end_date
        students = eval(getStudentsList(name))["students"]
        return json.dumps({"start_date":start_date, "end_date":end_date, "students":students})
    return False

def sendNotifyMail(email='rguktemailtest@gmail.com', testid=None, start_date=None, end_date=None):
    try:
        #app.logger.debug("send notify mail function")
        body = """Dear Student,<br> This email message is sent by the online quiz portal.
        The test starts at %s and ends by %s
        Click on the link below and follow the instructions to take the test.
        <a href=%s/quiz/%s>Test Link</a> """ % (start_date, end_date, request.host, testid)
        # app.logger.info(body)
        response = requests.post(
            "https://api.mailgun.net/v3/"+app.config['NUZVID_MAIL_GUN_DOMAIN']+"/messages",
            auth=("api", app.config['NUZVID_MAIL_GUN_KEY']),
            data={"from": "RGUKT QUIZ <news@"+app.config['NUZVID_MAIL_GUN_DOMAIN']+">",
                  "to": [email],
                  "subject": 'RGUKT QUIZ LINK',
                  "text": '',
                  "html": body})
        #app.logger.info([email, response.status_code, response.text])
        student = StudentTests.query.filter_by(emailid=email).first()
        if student:
            student.invitation_email_sent = True
            db.session.commit()
        else:
            app.logger.info(["Unknow email received quiz link", email])
        return response
    except Exception as e:
        app.logger.info(["Error in sendnotifymail module ", e])
        return False

# +++++++++++++++++++++++++++++++++++++++++++++++++++++++
#THIS FUNCITONALITY IMPLEMENTED FOR INDIVIDUAL MAIL ID
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++
# @app.route('/notify/<testid>', methods=["GET", "POST"])
# @admin_login_required
# def notify(testid):
#     testID = testid
#     if testID == None or testID == "":
#         return json.dumps([{}])

#     student_emails = eval(getStudentsList(testID))['students']
#     mail_responses = []
#     for email in student_emails:
#         response = sendNotifyMail(email=email)
#         if response:
#             mail_responses.append({
#                 "mail":email,
#                 "status_code":response.status_code,
#                 "status_message":response.text
#             })
#         else:
#             mail_responses.append({
#                 "mail":email,
#                 "status_code":"400",
#                 "status_message":"Mail Not Sent"
#             })
#     #app.logger.info(mail_responses)
#     return json.dumps(mail_responses)

@app.route('/notify/<testid>/<emailid>/<start_date>/<end_date>', methods=["GET", "POST"])
@admin_login_required
def notify(testid, emailid, start_date, end_date):
    if testid == None or testid == "":
        return json.dumps([{
                "mail":emailid,
                "status_code":"Error",
                "status_message":"TestID not received"
            }])

    app.logger.info(testid)
    invitation_email_sent = StudentTests.query.filter(StudentTests.emailid==emailid and StudentTests.invitation_email_sent.is_(True)).first()
    app.logger.info(invitation_email_sent.invitation_email_sent)
    if not invitation_email_sent.invitation_email_sent:
        response = sendNotifyMail(testid=testid, email=emailid, start_date=start_date, end_date=end_date)
        if response:
            return json.dumps([{
                "mail":emailid,
                "status_code":response.status_code,
                "status_message":response.text
            }])
        else:
            return json.dumps([{
                "mail":emailid,
                "status_code":"Error",
                "status_message":{"id":"Error","message":"Mail Not Sent"}
            }])
    else:
        return json.dumps([{
                "mail":emailid,
                "status_code":"Error",
                "status_message":{"id":"Error","message":"Mail already sent"}
            }])
    #app.logger.info(mail_responses)


def get_all_test_created_by(creator=None):
    if not creator:
        return {}
    result = Tests.query.filter_by(creator=creator).all()
    final = {}
    final["data"] = []
    count = 0
    for test in result:
        count+=1
        test = str(test).split("::")
        #app.logger.info(test)
        test.append(eval(getStudentsList(test[0]))["students"])
        #app.logger.info(test)
        button = "<a href='/edit/"+test[0]+"' class='btn btn-sm btn-primary'>Edit Test</a>"
        test.append(button)
        button = "<a href='/quiz/"+test[0]+"' class='btn btn-sm btn-success'>Preview Test</a>"
        test.append(button)
        button = "<a data-toggle='modal' data-target='#NotifyMailResponses' id='notify"+str(count)+"' name='/notify/"+test[0]+"' class='btn btn-sm btn-warning'>Notify</a>"
        test.append(button)
        final["data"].append(test)

    return final

@app.route('/loadtests', methods=["GET"])
@admin_login_required
def loadtests(creator=None):
    if not creator:
        creator = get_email_from_session()
    #app.logger.info("Getting all tests created by " + creator)
    final = get_all_test_created_by(creator)
    #app.logger.info(str(json.dumps(final)))
    return json.dumps(final)


@app.route('/autocomplete', methods=['GET'])
@admin_login_required
def autocomplete(search=None):
    if not search:
        search = request.args.get('q')
    testid = request.args.get('testid')
    students = []
    if testid:
        students = eval(getStudentsList(testid))['students']
    query = db.session.query(Users.emailid).filter(Users.emailid.like('%' + str(search) + '%'))
    results = [mv[0] for mv in query.all()]
    #The below line will remove students already invited or assigned to test
    results = list(set(results) - set(students))
    #app.logger.info(["autocomple result", results])
    return jsonify(matching_results=results)

def get_all_student_details(test_name):
    test_students = StudentTests.query.filter_by(test_name=test_name).all()
    # students = userDetails.query.filter(userDetails.email != "admin@quiz.in").all()
    student_table = {}
    for student in test_students:
        student = get_student_details(student.emailid)
        if student.email not in student_table:
            student_table[student.email] = {"name": student.name, "rollno":student.rollno}
    # app.logger.info(json.dumps(student_table))
    return json.dumps(student_table)

def get_student_details(student):
    return userDetails.query.filter(userDetails.email == student).first()

@app.route('/getAllStudentDetails/<test_name>', methods=['GET'])
@admin_login_required
def getAllStudentDetails(test_name):
    return get_all_student_details(test_name)

def get_test_responses_as_dict(testid=None):

        result = Response.query.filter_by(test_name=testid).all()

        students = json.loads(get_all_student_details(testid))
        questions = ""
        # app.logger.info(students)
        table = {}
        for entry in result:
            id = entry.id
            name = entry.name
            rollno = ""
            emailid = entry.emailid
            pin = entry.pin
            testctime = entry.testctime
            submittedans = entry.submittedans
            responsetime = entry.responsetime
            q_score = entry.q_score
            q_status = entry.q_status
            time = entry.time
            currentQuestion = entry.currentQuestion
            serialno = entry.serialno
            if emailid in students:
                student = students[emailid]
                name = student['name']
                rollno = student['rollno']


            if rollno not in table:
                table[rollno] = {
                    "rollno":rollno,
                    "name":name,
                    "emailid":emailid,
                    "testctime":testctime,
                    "count": 1
                }

            if currentQuestion is None:
                continue

            table[rollno].update({
                            "Question_"+str(table[rollno]['count'])+"_Submittedans":submittedans,
                            "Question_"+str(table[rollno]['count'])+"_Responsetime":convert_to_minutes(responsetime),
                            "Question_"+str(table[rollno]['count'])+"_Score":q_score,
                            "Question_"+str(table[rollno]['count'])+"_Status":q_status,
                            "Question_"+str(table[rollno]['count'])+"_Time":time,
                            "Question_"+str(table[rollno]['count'])+"":currentQuestion,
                        })
            table[rollno]['count'] += 1
        # app.logger.info(table)
        return table

def render_csv_from_test_responses(data, test_name):
        csvList = []
        header = [
                    "name",
                    "rollno",
                    "emailid",
                    "testctime",
                ]
        # app.logger.info(list(data)[0])

        user = Randomize.query.filter_by(test_name=test_name).first()
        if user:
            Questions_count = Randomize.query.filter_by(test_name=test_name, user1=user.user1).count()
            app.logger.info(["number is ", Questions_count])
            # return ""
            for i in range(1, Questions_count + 1):
                # app.logger.info("hi ra --> Question"+ str(i))
                header.extend(
                        [
                            "Question_"+str(i)+"",
                            "Question_"+str(i)+"_Score",
                            "Question_"+str(i)+"_Submittedans",
                            "Question_"+str(i)+"_Responsetime",
                            "Question_"+str(i)+"_Status",
                            "Question_"+str(i)+"_Time"
                        ]
                    )
            csvList.append(header)

            for csv_line in data:
                #app.logger.info(csv_line)
                row = [csv_line["name"],
                        csv_line["rollno"],
                        csv_line["emailid"],
                        csv_line["testctime"]
                        ]
                for i in range(1, Questions_count + 1):
                    row.extend(
                            [
                                csv_line["Question_"+str(i)+""] if "Question_"+str(i)+"" in csv_line else "",
                                csv_line["Question_"+str(i)+"_Score"] if "Question_"+str(i)+"_Score" in csv_line else "",
                                csv_line["Question_"+str(i)+"_Submittedans"] if "Question_"+str(i)+"_Submittedans" in csv_line else "",
                                csv_line["Question_"+str(i)+"_Responsetime"] if "Question_"+str(i)+"_Responsetime" in csv_line else "",
                                csv_line["Question_"+str(i)+"_Status"] if "Question_"+str(i)+"_Status" in csv_line else "",
                                csv_line["Question_"+str(i)+"_Time"] if "Question_"+str(i)+"_Time" in csv_line else "",
                            ]
                        )
                csvList.append(row)
        si = io.StringIO()
        cw = csv.writer(si)
        cw.writerows(csvList)
        output = make_response(si.getvalue())
        output.headers["Content-Disposition"] = "attachment; filename=Complete_Data.csv"
        output.headers["Content-type"] = "text/csv"
        return output

def get_test_responses_summary_as_dict(testid=None):

        result = Response.query.filter_by(test_name=testid).all()

        students = json.loads(get_all_student_details(testid))
        questions = ""
        # app.logger.info(students)
        table = {}
        table_q_touched = {}
        student_temp = {"name":None, "rollno":None, "Speaking":0, "Writing":0, "Listening":0, "Reading":0}
        for entry in result:
            id = entry.id
            name = entry.name
            emailid = entry.emailid
            rollno = ""
            q_score = entry.q_score
            q_section = entry.q_section
            currentQuestion = entry.currentQuestion

            if emailid in students:
                student = students[emailid]
                name = student['name']
                rollno = student['rollno']

            if rollno not in table:
                table[rollno] = student_temp.copy()
                table[rollno]['name'] = name
                table[rollno]['rollno'] = rollno
                table_q_touched[rollno] = []

            if q_section == "Speaking":
                if currentQuestion not in table_q_touched[rollno]:
                    table_q_touched[rollno].append(currentQuestion)
                    table[rollno]["Speaking"] += q_score
            elif q_section == "Listening":
                if currentQuestion not in table_q_touched[rollno]:
                    table_q_touched[rollno].append(currentQuestion)
                    table[rollno]["Listening"] += q_score
            elif q_section == "Reading":
                if currentQuestion not in table_q_touched[rollno]:
                    table_q_touched[rollno].append(currentQuestion)
                    table[rollno]["Reading"] += q_score
            elif q_section == "Writing":
                if currentQuestion not in table_q_touched[rollno]:
                    table_q_touched[rollno].append(currentQuestion)
                    table[rollno]["Writing"] += q_score
        # app.logger.info(table)
        return table

def render_csv_from_test_responses_summary(data):
        csvList = []
        header = [
                    "name",
                    "rollno",
                    "Speaking",
                    "Listening",
                    "Reading",
                    "Writing",
                    "Total"
                ]

        csvList.append(header)

        for csv_line in data:
            # app.logger.info(csv_line)
            row = [csv_line["name"],
                    csv_line["rollno"],
                    csv_line["Speaking"],
                    csv_line["Listening"],
                    csv_line["Reading"],
                    csv_line["Writing"],
                    csv_line["Speaking"]+csv_line["Listening"]+csv_line["Reading"]+csv_line["Writing"]
                ]

            csvList.append(row)
        si = io.StringIO()
        cw = csv.writer(si)
        cw.writerows(csvList)
        output = make_response(si.getvalue())
        output.headers["Content-Disposition"] = "attachment; filename=Summary_Sheet.csv"
        output.headers["Content-type"] = "text/csv"
        return output


@app.route('/downloadTestResults/<testid>')
@admin_login_required
def downloadTestResults(testid):
    if request.method == 'GET':

        #app.logger.info(["Requested result for test with id ",testid])
        table = get_test_responses_as_dict(testid)

        data = table.values()
        return render_csv_from_test_responses(data, testid)

@app.route('/downloadTestResultsSummary/<testid>')
@admin_login_required
def downloadTestResultsSummary(testid):
    if request.method == 'GET':

        #app.logger.info(["Requested result summary for test with id ",testid])
        table = get_test_responses_summary_as_dict(testid)

        data = table.values()
        return render_csv_from_test_responses_summary(data)

@app.route('/downloadInvitedStudents/<testid>')
@admin_login_required
def downloadInvitedStudents(testid):
    if request.method == 'GET':

        #app.logger.info(["Requested result for test with id ",testid])
        students = json.loads(getStudentsList(testid))['students']
        csvList = []
        header = [
                    "EmailID",
                ]
        csvList.append(header)
        for student in students:
            csvList.append([student])
        si = io.StringIO()
        cw = csv.writer(si)
        cw.writerows(csvList)
        output = make_response(si.getvalue())
        output.headers["Content-Disposition"] = "attachment; filename=Invited_Students.csv"
        output.headers["Content-type"] = "text/csv"
        return output


@app.route('/test_recorder', methods=['GET'])
def testrecorder():
    if request.method == "GET":
        html = '''
        <!DOCTYPE html>
        <html>
        <head>
        <link rel="stylesheet" href="css/bootstrap.min.css">
        <script src="javascripts/jquery.min.js"></script>
        </head>
        <body>
        <div id="recordercontainer">
        <div class="container">
        <div>
        <h3>Record: </h3>
        <hr>
        <button class="btn btn-primary" id="record">Record</button>
        <button class="btn btn-primary" id="stop" disabled>Stop</button>
        </div>
        <div data-type="wav">
        <h3>Recorded Audio: </h3>
        <div id="recorded"></div>
        </div>

        </div>
        </div>
        <script type="text/javascript">
        // $(document).ready(function(){
        // 	$.get('/getrecorder', function(data){
        // 		$("#recordercontainer").html(data);
        // 	});
        // })

        $(document).ready(function() {
        function createAudioElement(blobURL) {
        const audioEl = document.createElement("audio");
        audioEl.controls = true;
        const sourceEl = document.createElement("source");
        sourceEl.src = blobURL;
        sourceEl.type = "audio/webm";
        audioEl.appendChild(sourceEl);
        $("#recorded").html(audioEl);
        }
        var blobkey = ""
        navigator.mediaDevices.getUserMedia({
        audio: true
        }).then(stream => {
        const chunks = [];
        const recorder = new MediaRecorder(stream);
        recorder.ondataavailable = e => {
        chunks.push(e.data);
        if (recorder.state == "inactive") {
        const blob = new Blob(chunks, {
            type: "audio/webm"
        });
        createAudioElement(URL.createObjectURL(blob));
        blobkey = blob;
        }
        }
        $("#record").click(function() {
        $("#message").text("");
        this.innerHTML = "Recording...";
        this.disabled = true;
        while(chunks.length){
        chunks.pop();
        }
        recorder.start(1000);
        $("#stop").prop("disabled", false);
        });
        $("#stop").click(function() {
        $("#record").html("Record");
        $("#record").prop("disabled", false);
        recorder.stop();
        });
        $("#save").click(function() {

        // console.log(blobkey.type);

        });
        setTimeout(() => {
        recorder.stop();
        }, 300000)
        }).catch(console.error);
        });
        </script>
        </body>
        </html>
        '''
        return html;

@app.route('/showrecorder/<test_name>', methods=['GET'])
@login_required
def showrecorder(test_name):
    if request.method == "GET":
        # app.logger.info(request.host)
        if request.is_secure or "localhost" in request.host:
            return render_template('recorder.html', test_name=test_name)
        else:
            #To show audio recording for students on only HTTPS, flip the commenting below two lines
            # return render_template('recorder.html')
            return render_template('error.html', error="Audio recording is not supported in insecure origins, Contact Examination Admin")

@app.route('/getrecorder', methods=['GET'])
def getrecorder():
    if request.method == "GET":
        return '<div class="container"> <div> <h3>Record: </h3> <hr> <button class="btn btn-primary" id="record">Record</button> <button class="btn btn-primary" id="stop" disabled>Stop</button> </div> <div data-type="wav"> <h3>Recorded Audio: </h3> <div id="recorded"></div> </div> <div data-type="wav"> <h3>Save Audio: </h3> <button class="btn btn-primary" id="save">Save</button> </div> </div>'

    # if request.method == "POST":

def sublist(child, parent):
    return set(child) <= set(parent)

@app.route('/createexam', methods=['GET', 'POST'])
@admin_login_required
def createexam():
    if request.method == 'GET':
        return render_template('create_exam.html')

    if request.method == 'POST':

        # check if the post request has the file part
        mode = request.form['mode']
        flash("Selected mode is %s"%mode)

        if mode=="TOEFL":
            test_name = request.form['toefl_testname']
            flash("Test Name is %s"%test_name)
            startdate = request.form['datetimepicker1']
            flash("Start Date is %s"%startdate)
            enddate = request.form['datetimepicker2']
            flash("End Date is %s"%enddate)
        else:
            test_name = request.form['dep_testname']
            flash("Test Name is %s"%test_name)
            date = request.form['datepicker']
            flash("Exam Date is %s"%date)
            startdate = date+" 09:00"
            enddate = date+" 23:59"

        if not test_name or not mode or not date:
            flash('Error: One or more fields of form are Invalid. [test_name:%s,startdate:%s,enddate:%s]'%(test_name,startdate,enddate))
            return redirect(request.url)

        if test_name=="" or mode=="" or date=="":
            flash('Error: One or more fields of form are missing. [test_name:%s,startdate:%s,enddate:%s]'%(test_name,startdate,enddate))
            return redirect(request.url)

        if 'file' not in request.files:
            flash('Error: No File selected. Please upload a .zip file.')
            return redirect(request.url)

        try:
            test = create_test(test_name, mode, startdate, enddate)
            flash("Success: Test Status is %s"%test)
        except Exception as e:
            flash(e)
            return redirect(request.url)

        folder_structure = {"DEP":
            ["E1-Reading.json",
             "E3-Speaking.json",
             "listening.mp4",
             "reading.pdf",
             "E2-Listening.json",
             "E4-Writing.json",
             "QP_template.json"
            ]
            ,"TOEFL":
            ["audio1.mp3",
             "E1-Reading.json",
             "E3-Speaking.json",
             "QP_template.json",
             "E2-Listening.json",
             "E4-Writing.json"
             ]
            }

        file = request.files['file']
        # if user does not select file, browser also
        # submit a empty part without filename
        if file.filename == '':
            flash('Error: File not selected. Please upload a .zip file.')
            return redirect(request.url)
        if file:
            flash('Uploading content from %s'%file.filename)
            filename = secure_filename(file.filename)
            file.save(os.path.join('static/tmp_upload', filename))
            flash("Success: %s is valid. \nExtracting contents..."%filename)
            zip_exist = zipfile.is_zipfile('static/tmp_upload/'+filename)
            if zip_exist:
                zf = zipfile.ZipFile('static/tmp_upload/'+filename, 'r')
                file_list = zf.namelist()
                if sublist(folder_structure[mode], file_list):
                    if mode=="DEP":
                        zf.extractall("static/content/"+mode+"/"+date)
                    else:
                        zf.extractall("static/content/"+mode+"/"+filename.split(".")[0])
                    zf.close()
                    flash("Success in extracting: Folder uploaded in test environment")
                else:
                    flash("Error in extracting: Uploaded zip file doesn't contain necessary files/folder structure.")
            else:
                flash("Error: %s file is not a zip file"%filename)
            return redirect(url_for('createexam'))
        else:
            flash("Error: file format is not allowed")
        return redirect("createexam")
            # flash("Test Created: %s"%test)
# ==================================================
                    # UNIT Tests
# ==================================================

def test_handler(name, expected, actual, function):
    output = {"testcase_name":name, "result":None, "response":None}
    try:
        if function == "equal":
            if actual == expected:
                result = "Pass"
                response = "OK"
            else:
                result = "Fail"
                response = "Expected %s got %s"%(expected, actual)
        if function == "contains":
            if expected in actual:
                result = "Pass"
                response = "OK"
            else:
                result = "Fail"
                response = "Expected %s got %s"%(expected, actual)
        if function == "notNone":
            if actual:
                result = "Pass"
                response = "OK"
            else:
                result = "Fail"
                response = "Expected %s got %s"%(expected, actual)

    except Exception as e:
        response = e
        result = "Fail"
    output['result'] = result
    output['response'] = response
    return output

def datetime_handler(x):
    if isinstance(x, datetime):
        return x.isoformat()
    if isinstance(x, datetime.datetime):
        return x.isoformat()
    raise TypeError("Unknown type")

def test_get_test_responses_as_dict():
    output = {"function_name": inspect.stack()[0][3], "testcases":[]}
    # expected = {'128': {'Question_1_Score': 1, 'Question_5_Score': 0, 'Question_3_Time': datetime(2017, 7, 8, 7, 45, 47, 254924), 'Question_3': '104', 'Question_6': '201', 'Question_6_Score': 0, 'count': 7, 'Question_6_Submittedans': '#', 'Question_6_Time': datetime(2017, 7, 8, 7, 50, 7, 829351), 'Question_4_Status': 'submitted', 'Question_3_Status': 'submitted', 'Question_2_Score': 1, 'Question_3_Submittedans': 'False', 'name': 'Sreenath', 'Question_1_Status': 'submitted', 'Question_4_Time': datetime(2017, 7, 8, 7, 45, 48, 870909), 'Question_5': '106', 'rollno': '128', 'Question_5_Submittedans': 'Partly true', 'Question_2_Submittedans': 'By the Prime Minister of India in an unscheduled, real time, televised address to the nation', 'emailid': 'sirimala.sreenath@gmail.com', 'Question_2_Time': datetime(2017, 7, 8, 7, 45, 44, 958977), 'Question_5_Status': 'submitted', 'Question_1': '102', 'Question_1_Time': datetime(2017, 7, 8, 7, 45, 43, 599523), 'Question_6_Status': 'submitted', 'Question_1_Submittedans': 'All of the above', 'Question_2': '103', 'Question_5_Time': datetime(2017, 7, 8, 7, 45, 50, 917283), 'Question_2_Status': 'submitted', 'Question_1_Responsetime': 4.737, 'Question_5_Responsetime': 2.021, 'Question_3_Responsetime': 2.279, 'testctime': datetime(2017, 7, 8, 7, 45, 24, 463860), 'Question_3_Score': 0, 'Question_2_Responsetime': 1.317, 'Question_6_Responsetime': 257.088, 'Question_4': '105', 'Question_4_Score': 0, 'Question_4_Responsetime': 1.591, 'Question_4_Submittedans': 'None of these'}, '1234': {'Question_5_Score': 0, 'Question_3_Time': datetime(2017, 7, 8, 7, 41, 56, 276504), 'count': 9, 'Question_4_Status': 'submitted', 'Question_6_Time': datetime(2017, 7, 8, 7, 42, 4, 291266), 'Question_3_Submittedans': 'By the Prime Minister of India in an unscheduled, real time, televised address to the nation', 'Question_4_Submittedans': 'Not sure', 'Question_1_Status': 'submitted', 'rollno': '1234', 'Question_2_Submittedans': 'Maoist extremism', 'Question_7': '201', 'emailid': 'vy@fju.us', 'Question_5_Status': 'submitted', 'Question_3_Score': 1, 'Question_2': '102', 'Question_5_Time': datetime(2017, 7, 8, 7, 42, 2, 361560), 'Question_1_Responsetime': 3.99, 'Question_5_Responsetime': 1.768, 'Question_3': '103', 'Question_6_Submittedans': 'True', 'Question_2_Responsetime': 1.472, 'Question_7_Score': 0, 'Question_4_Responsetime': 4.249, 'Question_7_Status': 'submitted', 'Question_8_Score': 0, 'Question_1_Score': 0, 'Question_6_Score': 0, 'Question_8_Responsetime': 6.418, 'Question_6': '106', 'Question_7_Submittedans': '#', 'Question_1_Submittedans': '3.26 million people', 'Question_2_Score': 0, 'name': 'Veda', 'Question_7_Time': datetime(2017, 7, 8, 7, 42, 6, 512938), 'Question_4_Time': datetime(2017, 7, 8, 7, 42, 0, 559407), 'Question_5': '105', 'Question_5_Submittedans': 'Safety fee', 'Question_7_Responsetime': 2.181, 'Question_8': '1', 'Question_8_Submittedans': 'The answer to all the problems', 'Question_2_Time': datetime(2017, 7, 8, 7, 41, 54, 570905), 'Question_1': '101', 'Question_1_Time': datetime(2017, 7, 8, 7, 41, 53, 51284), 'Question_6_Status': 'submitted', 'Question_3_Status': 'submitted', 'Question_2_Status': 'submitted', 'Question_8_Time': datetime(2017, 7, 8, 7, 42, 12, 949458), 'Question_3_Responsetime': 1.668, 'testctime': datetime(2017, 7, 8, 7, 41, 47, 277874), 'Question_8_Status': 'submitted', 'Question_6_Responsetime': 1.89, 'Question_4': '104', 'Question_4_Score': 0}}
    expected = {}
    testcases = [
        ("test1", expected, get_test_responses_as_dict(None), "equal"),
        ("test2",expected,get_test_responses_as_dict(12), "equal"),
        ("test3",expected,get_test_responses_as_dict("12"), "equal"),
        ("test4",expected,get_test_responses_as_dict(16), "equal"),
        ("test5",expected,get_test_responses_as_dict(122), "equal")
    ]
    for testcase in testcases:
        testcase_output = test_handler(testcase[0], testcase[1], testcase[2], testcase[3])
        # app.logger.info(testcase_output)
        output['testcases'].append(testcase_output)
    # app.logger.info(output)
    return output

def test_add_user_if_not_exist():

    output = {"function_name": inspect.stack()[0][3], "testcases":[]}
    existed = Users.query.filter_by(emailid="sirimala.sreenath@gmail.com").all()
    for exist in existed:
        db.session.delete(exist)
    db.session.commit()
    testcases = [
        ("test1", not None, add_user_if_not_exist(email="sirimala.sreenath@gmail.com", password="generate_unique_code"), "notNone"),
        ("test2",False, add_user_if_not_exist(email="sirimala.sreenath@gmail.com", password="generate_unique_code"), "equal"),
        ("test3",True, add_user_if_not_exist(email="vy@fju.us", password="generate_unique_code"), "notNone"),
    ]

    for testcase in testcases:
        testcase_output = test_handler(testcase[0], testcase[1], testcase[2], testcase[3])
        # app.logger.info(testcase_output)
        output['testcases'].append(testcase_output)
    #app.logger.info(output)
    existed = Users.query.filter_by(emailid="sirimala.sreenath@gmail.com").all()
    for exist in existed:
        db.session.delete(exist)
    db.session.commit()
    return output

def test_allowed_to_take_test():
    output = {"function_name": inspect.stack()[0][3], "testcases":[]}
    student = StudentTests("sirimala.sreenath@gmail.com", ["English Comprehension Test"])
    db.session.add(student)
    # db.session.commit()
    testcases = [
        ("test1", False, allowed_to_take_test("", "", ""), "equal"),
        ("test2",False, allowed_to_take_test("", "sirimala.sreenath@gmail.com", ""), "equal"),
        ("test3",True, allowed_to_take_test("English Comprehension Test", "sirimala.sreenath@gmail.com","student"), "equal"),
    ]

    for testcase in testcases:
        testcase_output = test_handler(testcase[0], testcase[1], testcase[2], testcase[3])
        # app.logger.info(testcase_output)
        output['testcases'].append(testcase_output)
    #app.logger.info(output)
    db.session.delete(student)
    return output

def test_add_first_response():
    output = {"function_name": inspect.stack()[0][3], "testcases":[]}
    testcases = [
        ("test1", False, add_first_response(""), "equal"),
        ("test1", False, add_first_response(), "equal"),
        ("test2",True, add_first_response("sirimala.sreenath@gmail.com"), "equal"),
        ("test3",False, add_first_response("sirimala.sreenath@gmail.com"), "equal"),
    ]

    for testcase in testcases:
        testcase_output = test_handler(testcase[0], testcase[1], testcase[2], testcase[3])
        # app.logger.info(testcase_output)
        output['testcases'].append(testcase_output)
    #app.logger.info(output)
    existed = Response.query.filter_by(emailid="sirimala.sreenath@gmail.com").all()
    for exist in existed:
        db.session.delete(exist)
    db.session.commit()
    return output

def test_add_user_profile():
    output = {"function_name": inspect.stack()[0][3], "testcases":[]}
    existed = userDetails.query.filter_by(email="vy@fju.us").all()
    for exist in existed:
        db.session.delete(exist)
    db.session.commit()
    testcases = [
        ("test1", True, add_user_profile("Veda","vy@fju.us",8686093417,1234,"Basara"), "equal"),
        ("test1", False, add_user_profile(), "equal"),
        ("test2",False, add_user_profile("","","","",""), "equal"),
    ]

    for testcase in testcases:
        testcase_output = test_handler(testcase[0], testcase[1], testcase[2], testcase[3])
        # app.logger.info(testcase_output)
        output['testcases'].append(testcase_output)
    #app.logger.info(output)

    return output

def test_qidlisttodict():
    output = {"function_name": inspect.stack()[0][3], "testcases":[]}
    testcases = [
        ("test1", type({}), type(qidlisttodict(checkrandomizetable("vy@fju.us"))), "equal"),
        ("test1", len(checkrandomizetable("vy@fju.us")), len(qidlisttodict(checkrandomizetable("vy@fju.us"))), "equal"),
        ("test2", False, qidlisttodict(None), "equal"),
    ]

    for testcase in testcases:
        testcase_output = test_handler(testcase[0], testcase[1], testcase[2], testcase[3])
        output['testcases'].append(testcase_output)
    return output

def test_add_to_randomize():
    output = {"function_name": inspect.stack()[0][3], "testcases":[]}
    testcases = [
        ("test1", True, add_to_randomize("vy@fju.us",1,101), "equal"),
        ("test1", False, add_to_randomize(), "equal"),
        ("test2",False, add_to_randomize("","",""), "equal"),
    ]

    for testcase in testcases:
        testcase_output = test_handler(testcase[0], testcase[1], testcase[2], testcase[3])
        # app.logger.info(testcase_output)
        output['testcases'].append(testcase_output)
    #app.logger.info(output)
    existed = Randomize.query.filter_by(user1="vy@fju.us").all()
    for exist in existed:
        db.session.delete(exist)
    db.session.commit()
    return output

def test_setquizstatus():
    output = {"function_name": inspect.stack()[0][3], "testcases":[]}
    existed = TestDetails.query.filter_by(email="vy@fju.us").first()
    if not existed:
        td = TestDetails(email="vy@fju.us",testend=True)
        db.session.add(td)
        db.session.commit()
    testcases = [
        ("test1", "END", setquizstatus("vy@fju.us"), "equal"),
        ("test1", False, setquizstatus(), "equal"),
        ("test2","START", setquizstatus(""), "equal"),
    ]
    for testcase in testcases:
        testcase_output = test_handler(testcase[0], testcase[1], testcase[2], testcase[3])
        output['testcases'].append(testcase_output)
    if existed:
        db.session.delete(existed)
        db.session.commit()
    return output

def test_addtestdetails():
    output = {"function_name": inspect.stack()[0][3], "testcases":[]}
    testcases = [
        ("test1", True, addtestdetails("vy@fju.us",True,0.5), "equal"),
        ("test2", False, addtestdetails(), "equal"),
        ("test3",False, addtestdetails("","",0.0), "equal"),
    ]

    for testcase in testcases:
        testcase_output = test_handler(testcase[0], testcase[1], testcase[2], testcase[3])
        output['testcases'].append(testcase_output)
    existed = TestDetails.query.filter_by(email="vy@fju.us").all()
    for exist in existed:
        db.session.delete(exist)
    db.session.commit()
    return output

def test_storeresponse():
    output = {"function_name": inspect.stack()[0][3], "testcases":[]}
    expected = {u"status":"success" , u"q_status":"skip", u"validresponse":"true", u"qid":101}
    expected2 = {u"status":"success" , u"q_status":"submitted", u"validresponse":"true", u"qid":102}
    expected3 = {u"status":"error" , u"q_status":None, u"validresponse":"false", u"qid":None}
    testcases = [
        ("test1", expected, storeresponse("vy@fju.us",101,"skip",1.254), "equal"),
        ("test2", expected2, storeresponse("vy@fju.us",102,"submitted",1.26), "equal"),
        ("test3", expected3, storeresponse(), "equal"),
        ("test4", expected3, storeresponse("","","",""), "equal")
    ]
    for testcase in testcases:
        testcase_output = test_handler(testcase[0], testcase[1], testcase[2], testcase[3])
        # app.logger.info(testcase_output)
        output['testcases'].append(testcase_output)
    existed = Response.query.filter_by(emailid="vy@fju.us").all()
    for exist in existed:
        db.session.delete(exist)
    db.session.commit()
    return output

def test_getResultOfStudent():
    output = {"function_name": inspect.stack()[0][3], "testcases":[]}
    giveninput = getResultOfStudent("vy@fju.us")
    expected = {"totalscore": 0, "question": []}
    storeresponse("vy@fju.us",101,"submitted",1.26)
    storeresponse("vy@fju.us",102,"skip",1.80)
    giveninput2 = getResultOfStudent("vy@fju.us")
    expected2 = {"totalscore": 0, "question": [{"user": "vy@fju.us", "submittedans": "submitted", "currentQuestion": "101", "q_score": 0, "responsetime": 1.26}, {"user": "vy@fju.us", "submittedans": "skip", "currentQuestion": "102", "q_score": 0, "responsetime": 1.8}]}
    giveninput3 = getResultOfStudent()
    testcases = [
        ("test1", expected, json.loads(giveninput), "equal"),
        ("test2", expected2, json.loads(giveninput2), "equal"),
        ("test3", expected, json.loads(giveninput3), "equal"),
        ("test4", expected, json.loads(getResultOfStudent("")), "equal"),
    ]
    for testcase in testcases:
        testcase_output = test_handler(testcase[0], testcase[1], testcase[2], testcase[3])
        # app.logger.info(testcase_output)
        output['testcases'].append(testcase_output)
    # app.logger.info(output)
    existed = Response.query.filter_by(emailid="vy@fju.us").all()
    for exist in existed:
        db.session.delete(exist)
    db.session.commit()
    return output

def test_saveessay():
    output = {"function_name": inspect.stack()[0][3], "testcases":[]}
    row = EssayTypeResponse.query.filter_by(useremailid = "vy@fju.us", qid = "201").first()
    giveninput = saveessay(row,"vy@fju.us","201","This is a test paragraph",3.5789)
    giveninput2 = saveessay(row,"vy@fju.us","201","This is a test paragraph2",3.5789)
    testcases = [
        ("test1", True, giveninput, "equal"),
        ("test2", True, giveninput, "equal"),
        ("test3", False, saveessay(), "equal"),
        ("test4", False, saveessay(row,"","","",0.0), "equal")

    ]

    for testcase in testcases:
        testcase_output = test_handler(testcase[0], testcase[1], testcase[2], testcase[3])
        output['testcases'].append(testcase_output)
    existed = EssayTypeResponse.query.filter_by(useremailid="vy@fju.us").all()
    for exist in existed:
        db.session.delete(exist)
    db.session.commit()
    return output

def test_getlearningcentre():
    output = {"function_name": inspect.stack()[0][3], "testcases":[]}
    add_user_profile("Veda","vy@fju.us",8686093417,1234,"Basara")
    testcases = [
        ("test1", "Basara", getlearningcentre("vy@fju.us"), "equal"),
        ("test2", False, getlearningcentre(), "equal"),
        ("test3",False, getlearningcentre(""), "equal"),
    ]

    for testcase in testcases:
        testcase_output = test_handler(testcase[0], testcase[1], testcase[2], testcase[3])
        output['testcases'].append(testcase_output)
    existed = userDetails.query.filter_by(email="vy@fju.us").all()
    for exist in existed:
        db.session.delete(exist)
    db.session.commit()
    return output

def test_generate_unique_code():
    output = {"function_name": inspect.stack()[0][3], "testcases":[]}
    testcases = [
        ("test1", False, generate_unique_code()==generate_unique_code(), "equal")
    ]

    for testcase in testcases:
        testcase_output = test_handler(testcase[0], testcase[1], testcase[2], testcase[3])
        output['testcases'].append(testcase_output)
    return output

def test_valid_user_login():
    output = {"function_name": inspect.stack()[0][3], "testcases":[]}
    existed = Users.query.filter_by(emailid="vy@fju.us").all()
    #app.logger.info(existed)
    for exist in existed:
        #app.logger.info(['deleting', exist.emailid])
        db.session.delete(exist)

    #app.logger.info(Users.query.filter_by(emailid="vy@fju.us").all())
    user = Users("vy@fju.us",hashlib.md5("veda1996".encode('utf-8')).hexdigest(),"student",True)
    db.session.add(user)
    # update_password(user,)

    testcases = [
        ("test1", True, valid_user_login("vy@fju.us", "veda1996"), "notNone")
    ]

    for testcase in testcases:
        testcase_output = test_handler(testcase[0], testcase[1], testcase[2], testcase[3])
        output['testcases'].append(testcase_output)

    db.session.delete(user)
    return output

def test_makestatusbutton():
    output = {"function_name": inspect.stack()[0][3], "testcases":[]}
    input1 = makestatusbutton("vy@fju.us",True)
    existed = TestDetails.query.filter_by(email="vy@fju.us").first()
    if not existed:
        td = TestDetails(email="vy@fju.us",testend=False)
        db.session.add(td)
        db.session.commit()
    input2 = makestatusbutton("vy@fju.us",True)
    testcases = [
        ("test1", "<a href='#' class='btn btn-sm btn-warning' disabled>Locked</a>", makestatusbutton("vy@fju.us",False), "equal"),
        ("test2", "<a href='/quiz' class='btn btn-sm btn-primary'>Attempt Test</a>", input1, "equal"),
        ("test3", "<a href='/quiz' class='btn btn-sm btn-warning'>In Progress!</a>", input2, "equal"),
    ]

    for testcase in testcases:
        testcase_output = test_handler(testcase[0], testcase[1], testcase[2], testcase[3])
        output['testcases'].append(testcase_output)
    if existed:
        db.session.delete(existed)
        db.session.commit()
    return output

def test_gettestdetails():
    output = {"function_name": inspect.stack()[0][3], "testcases":[]}
    existed = Tests.query.filter_by(name="English Literacy Test").first()
    if existed:
        db.session.delete(existed)
        db.session.commit()
    input1 = gettestdetails("vy@fju.us","English Literacy Test")
    expected = []
    td = Tests("English Literacy Test","vy@fju.us",'06-07-2017 15:30', '02-08-2017 12:00')
    db.session.add(td)
    db.session.commit()
    input2 = gettestdetails("vy@fju.us","English Literacy Test")
    testcases = [
        ("test1", expected, input1, "equal"),
        ("test2", ['English Literacy Test', '06-07-2017 15:30', '02-08-2017 12:00', "<a href='/quiz' class='btn btn-sm btn-warning'>In Progress!</a>"], input2, "equal"),
    ]

    for testcase in testcases:
        testcase_output = test_handler(testcase[0], testcase[1], testcase[2], testcase[3])
        output['testcases'].append(testcase_output)
    return output

def test_add_default_user_admin_if_not_exist():
    output = {"function_name": inspect.stack()[0][3], "testcases":[]}
    testcases = [
        ("test1", True, add_default_user_admin_if_not_exist(), "equal"),
        ("test2", False, add_default_user_admin_if_not_exist(), "equal"),
    ]
    for testcase in testcases:
        testcase_output = test_handler(testcase[0], testcase[1], testcase[2], testcase[3])
        output['testcases'].append(testcase_output)
    return output

def test_sendMail():
    output = {"function_name": inspect.stack()[0][3], "testcases":[]}
    testcases = [
        ("test1", True, sendMail("UnitTesting","UnitTesting","vy@fju.us"), "equal"),
        ("test2", True, sendMail(), "equal")
    ]
    for testcase in testcases:
        testcase_output = test_handler(testcase[0], testcase[1], testcase[2], testcase[3])
        output['testcases'].append(testcase_output)
    return output

def test_sendNotifyMail():
    output = {"function_name": inspect.stack()[0][3], "testcases":[]}
    testcases = [
        ("test1", True, sendNotifyMail("vy@fju.us"), "notNone"),
        ("test2", True, sendNotifyMail("admin@quiz.in"), "notNone")
    ]
    for testcase in testcases:
        testcase_output = test_handler(testcase[0], testcase[1], testcase[2], testcase[3])
        output['testcases'].append(testcase_output)
    return output

def test_update_password():
    output = {"function_name": inspect.stack()[0][3], "testcases":[]}
    user = Users.query.filter_by(emailid="vy@fju.us").all()
    if not user:
        user = Users("vy@fju.us","","student",True)
        db.session.add(user)
        db.session.commit()
    input1 = update_password(user,"veda1997")
    input2 = update_password(user,"veda1996")
    testcases = [
        ("test1", True, input1, "equal"),
        ("test2", True, input2, "equal")
    ]
    for testcase in testcases:
        testcase_output = test_handler(testcase[0], testcase[1], testcase[2], testcase[3])
        output['testcases'].append(testcase_output)
    return output

def test_getQuestionPaper():
    output = {"function_name": inspect.stack()[0][3], "testcases":[]}
    testcases = [
        ("test1", [], getQuestionPaper([0])["section"][0]["subsection"][0]['questions'], "notNone"),
        ("test2", [], getQuestionPaper([])["section"][0]["subsection"][0]['questions'], "equal")
    ]
    for testcase in testcases:
        testcase_output = test_handler(testcase[0], testcase[1], testcase[2], testcase[3])
        output['testcases'].append(testcase_output)
    return output

def test_generateQuestionPaper():
    output = {"function_name": inspect.stack()[0][3], "testcases":[]}
    testcases = [
        ("test1", not None, generateQuestionPaper()["section"][0]["subsection"][0]['questions'], "notNone"),
        ("test2", not None, generateQuestionPaper()["section"][0]["subsection"][0]['questions'], "notNone")
    ]
    for testcase in testcases:
        testcase_output = test_handler(testcase[0], testcase[1], testcase[2], testcase[3])
        output['testcases'].append(testcase_output)
    return output

def test_render_csv_from_test_responses():
    output = {"function_name": inspect.stack()[0][3], "testcases":[]}
    data = get_test_responses_as_dict()
    testcases = [
        ("test1", not None, render_csv_from_test_responses(data), "notNone"),
        ("test2", not None, render_csv_from_test_responses(data), "notNone")
    ]
    for testcase in testcases:
        testcase_output = test_handler(testcase[0], testcase[1], testcase[2], testcase[3])
        output['testcases'].append(testcase_output)
    return output

def test_get_all_test_created_by():
    output = {"function_name": inspect.stack()[0][3], "testcases":[]}
    testcases = [
        ("test1", {}, get_all_test_created_by(None), "equal"),
        ("test2", [], get_all_test_created_by("admin@quiz.in")['data'], "notNone"),
        ("test3", type([]), type(get_all_test_created_by("admin@quiz.in")['data']), "notNone")
    ]
    for testcase in testcases:
        testcase_output = test_handler(testcase[0], testcase[1], testcase[2], testcase[3])
        output['testcases'].append(testcase_output)
    return output

def test_isRegistered():
    output = {"function_name": inspect.stack()[0][3], "testcases":[]}
    user = Users(emailid="admin@quiz.in",password="sree", user_type="admin", verified=True)
    db.session.add(user)
    db.session.commit()
    testcases = [
        ("test1", True, isRegistered("admin@quiz.in"), "equal"),
        ("test2", False, isRegistered("sirimala.sirimala@gmail.com"), "equal")
    ]
    for testcase in testcases:
        testcase_output = test_handler(testcase[0], testcase[1], testcase[2], testcase[3])
        output['testcases'].append(testcase_output)

    db.session.delete(user)
    db.session.commit()

    return output

def test_getAnswer():
    output = {"function_name": inspect.stack()[0][3], "testcases":[]}
    testcases = [
        ("test1", "Other measures to restructure the economy", getAnswer(10), "equal"),
        ("test2", "Forerunner", getAnswer(11), "equal")
    ]
    for testcase in testcases:
        testcase_output = test_handler(testcase[0], testcase[1], testcase[2], testcase[3])
        output['testcases'].append(testcase_output)
    return output

def test_getendtestdata():
    output = {"function_name": inspect.stack()[0][3], "testcases":[]}
    request_data = {'jsonData':{}}
    val = request_data['jsonData']
    val['testend'] = 'true'
    val['finalScore'] = '12'
    val['spklink'] = 'http://link'
    testcases = [
        ("test1", (val, 'true', '12', 'http://link'), getendtestdata(request_data), "equal"),
        ("test2", False, getendtestdata({}), "equal")
    ]
    for testcase in testcases:
        testcase_output = test_handler(testcase[0], testcase[1], testcase[2], testcase[3])
        output['testcases'].append(testcase_output)
    return output

def test_get_all_student_details():
    output = {"function_name": inspect.stack()[0][3], "testcases":[]}
    input1 = get_all_student_details()
    name = "Veda"
    email = "vy@fju.us"
    rollno = 1234
    add_user_profile("Veda","vy@fju.us",8686093417,1234,"Basara")
    expected = json.dumps({email: {"name": name, "rollno": str(rollno)}})
    input2 = get_all_student_details()
    testcases = [
        ("test1", json.dumps({}), input1, "equal"),
        ("test2", expected, input2, "equal")
    ]
    for testcase in testcases:
        testcase_output = test_handler(testcase[0], testcase[1], testcase[2], testcase[3])
        output['testcases'].append(testcase_output)
    return output

def test_validate_name():
    output = {"function_name": inspect.stack()[0][3], "testcases":[]}
    name = "English Comprehension Test"
    test = Tests.query.filter_by(name=name).first()
    if test:
        db.session.delete(test)
        db.session.commit()
    input1 = validate_name(name)
    td = Tests("English Comprehension Test","vy@fju.us",'06-07-2017 15:30', '02-08-2017 12:00')
    db.session.add(td)
    db.session.commit()
    input2 = validate_name(name)
    testcases = [
        ("test1", True, input1, "equal"),
        ("test2", False, input2, "equal")
    ]
    for testcase in testcases:
        testcase_output = test_handler(testcase[0], testcase[1], testcase[2], testcase[3])
        output['testcases'].append(testcase_output)
    return output

def test_validate_date():
    output = {"function_name": inspect.stack()[0][3], "testcases":[]}
    testcases = [
        ("test1", False, validate_date("30-06-2017 12:00"), "equal"),
        ("test2", True, validate_date("30-08-2017 12:00"), "equal")
    ]
    for testcase in testcases:
        testcase_output = test_handler(testcase[0], testcase[1], testcase[2], testcase[3])
        output['testcases'].append(testcase_output)
    return output

def test_updatetests():
    output = {"function_name": inspect.stack()[0][3], "testcases":[]}
    name = "English Comprehension Test"
    test = Tests.query.filter_by(name=name).first()
    if test:
        db.session.delete(test)
        db.session.commit()
    input1 = updatetests("English Comprehension Test","vy@fju.us",'16-07-2017 15:30', '02-08-2017 12:00')
    input2 = updatetests("English Comprehension Test","vy@fju.us",'16-07-2017 15:30', '02-08-2017 12:00')

    testcases = [
        ("test1", True, input1, "equal"),
        ("test2", False, input2, "equal"),
        ("test3", False, updatetests(), "equal")
    ]
    for testcase in testcases:
        testcase_output = test_handler(testcase[0], testcase[1], testcase[2], testcase[3])
        output['testcases'].append(testcase_output)
    return output

def test_updateDate():
    output = {"function_name": inspect.stack()[0][3], "testcases":[]}
    updatetests("English Comprehension Test","vy@fju.us",'16-07-2017 15:30', '02-08-2017 12:00')
    testcases = [
        ("test1", True, updateDate("English Comprehension Test",'15-07-2017 15:30', '02-08-2017 12:00'), "equal"),
        ("test2", False, updateDate("English Literacy",'16-07-2017 15:30', '02-08-2017 12:00'), "equal"),
        ("test3", False, updateDate(), "equal")
    ]
    for testcase in testcases:
        testcase_output = test_handler(testcase[0], testcase[1], testcase[2], testcase[3])
        output['testcases'].append(testcase_output)
    return output

@app.route('/unit_test')
def unit_test():
    if eval(os.environ['DEBUG']):
        db.drop_all()
        db.create_all()
        return render_template("unit_tests.html", tests = [
            test_get_all_student_details(),
            test_validate_name(),
            test_validate_date(),
            test_updatetests(),
            test_updateDate(),
            test_getendtestdata(),
            test_getAnswer(),
            test_isRegistered(),
            test_get_all_test_created_by(),
            test_render_csv_from_test_responses(),
            test_getQuestionPaper(),
            test_generateQuestionPaper(),
            test_add_user_if_not_exist(),
            test_get_test_responses_as_dict(),
            test_allowed_to_take_test(),
            test_add_user_profile(),
            test_qidlisttodict(),
            test_add_to_randomize(),
            test_setquizstatus(),
            test_addtestdetails(),
            test_storeresponse(),
            test_getResultOfStudent(),
            test_saveessay(),
            test_getlearningcentre(),
            test_generate_unique_code(),
            test_valid_user_login(),
            test_makestatusbutton(),
            test_gettestdetails(),
            test_add_default_user_admin_if_not_exist(),
            test_update_password(),
        ])
    else:
        return redirect("/")

if __name__ == "__main__":
        app.debug = True
        db.create_all()
        app.run(host="0.0.0.0")
