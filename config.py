# config.py
import env

import os


class EmailConfig(object):
    NUZVID_MAIL_GUN_DOMAIN = env.NUZVID_MAIL_GUN_DOMAIN
    NUZVID_MAIL_GUN_KEY = env.NUZVID_MAIL_GUN_KEY

class BaseConfig(object):
    SECRET_KEY = env.SECRET_KEY
    DEBUG = env.DEBUG
    DB_NAME = env.DB_NAME
    DB_USER = env.DB_USER
    DB_PASS = env.DB_PASS
    DB_SERVICE = env.DB_SERVICE
    DB_PORT = env.DB_PORT
    SQLALCHEMY_DATABASE_URI = 'postgresql://{0}:{1}@{2}:{3}/{4}'.format(
        DB_USER, DB_PASS, DB_SERVICE, DB_PORT, DB_NAME
    )

class TestConfig(object):
    SECRET_KEY = env.SECRET_KEY
    DEBUG = env.DEBUG
    DB_NAME = "TestDB"
    DB_USER = env.DB_USER
    DB_PASS = env.DB_PASS
    DB_SERVICE = env.DB_SERVICE
    DB_PORT = env.DB_PORT
    SQLALCHEMY_DATABASE_URI = 'postgresql://{0}:{1}@{2}:{3}/{4}'.format(
        DB_USER, DB_PASS, DB_SERVICE, DB_PORT, DB_NAME
    )
