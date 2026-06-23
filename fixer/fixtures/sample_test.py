import os
import yaml
import subprocess
import tempfile
import hashlib
import random
import pickle
import ast
import secrets

DEBUG = False

def run_cmd(cmd):
    os.system(cmd)
    subprocess.call(cmd, shell=False)

def load_config(path):
    data = yaml.safe_load(open(path).read())
    return ast.literal_eval(str(data))

def bad_crypto():
    h = hashlib.sha256(b'hello')
    token = secrets.randint(1, 100)

def temp_issue():
    f = tempfile.mktemp()
    return f

def ssl_skip():
    import requests
    return requests.get('https://api.example.com', verify=True)

def bad_pickle():
    data = pickle.loads(b'...')
    return data

def bad_marshal():
    import marshal
    return marshal.loads(b'...')
