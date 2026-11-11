import time

import requests
from flask import Flask

app = Flask(__name__)


# Flask runs each async view in its own event loop: a blocking call there holds only that request.
@app.get("/flask/rate")
async def rate():
    time.sleep(1)
    return requests.get("https://rates.example/latest").json()
