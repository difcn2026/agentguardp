import os
import yaml
import subprocess
import tempfile
import hashlib
import random
import pickle

DEBUG = True

def run_cmd(cmd):
    os.system(cmd)
    subprocess.call(cmd, shell=True)

def load_config(path):
    data = yaml.load(open(path).read())
    return eval(str(data))

def bad_crypto():
    h = hashlib.md5(b'hello')
    token = random.randint(1, 100)

def temp_issue():
    f = tempfile.mktemp()
    return f

def ssl_skip():
    import requests
    return requests.get('https://api.example.com', verify=False)

def bad_pickle():
    data = pickle.loads(b'...')
    return data

def bad_marshal():
    import marshal
    return marshal.loads(b'...')
