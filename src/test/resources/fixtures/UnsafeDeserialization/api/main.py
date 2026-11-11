import pickle

import joblib
import jsonpickle
from fastapi import FastAPI, File, UploadFile

app = FastAPI()


@app.post("/models")
async def upload_model(file: UploadFile = File(...)):
    model = pickle.loads(await file.read())  # Noncompliant {{parameter file of POST /models}}
    return {"type": type(model).__name__}


@app.post("/models/joblib")
def upload_joblib(file: UploadFile):
    return {"model": str(joblib.load(file.file))}  # Noncompliant


@app.get("/objects")
def objects(payload: str):
    return jsonpickle.decode(payload)  # Noncompliant


@app.get("/objects/encoded")
def encoded(count: int):
    return jsonpickle.encode(list(range(count)))


@app.post("/models/{model_id}")
def load_saved(model_id: int):
    with open(f"/srv/models/{model_id}.pkl", "rb") as f:
        return {"model": str(pickle.load(f))}
