import base64
import pickle


def decode(token):
    return pickle.loads(base64.b64decode(token))  # Noncompliant {{request.COOKIES of ANY /prefs/}} [[2]]


def encode(value):
    return base64.b64encode(pickle.dumps(value))
