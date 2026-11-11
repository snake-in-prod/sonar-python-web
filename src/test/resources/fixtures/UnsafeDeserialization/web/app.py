import json
import marshal

import numpy as np
import yaml
from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/import", methods=["POST"])
def import_config():
    config = yaml.unsafe_load(request.data)  # Noncompliant {{request.data of POST /import}}
    return jsonify(config)


@app.route("/code", methods=["POST"])
def code():
    return str(marshal.loads(request.get_data()))  # Noncompliant


@app.route("/arrays", methods=["POST"])
def arrays():
    unsafe = np.load(request.files["a"], allow_pickle=True)  # Noncompliant
    safe = np.load(request.files["b"], allow_pickle=False)
    default = np.load(request.files["c"])
    return jsonify({"shapes": [unsafe.shape, safe.shape, default.shape]})


@app.route("/json", methods=["POST"])
def as_json():
    return jsonify(json.loads(request.data))
