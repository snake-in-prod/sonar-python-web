import requests

RATES_URL = "https://rates.example/latest"
HOOK_URL = "https://hooks.example/notify"


def fetch_rates():
    return requests.get(RATES_URL).json()


def load_report(name):
    return _download(name)


def _download(name):
    return requests.get(RATES_URL + "/" + name).content


def read_config(path):
    with open(path) as f:
        return f.read()


async def notify_async(message):
    requests.post(HOOK_URL, json={"text": message})  # Noncompliant {{async POST /v1/notify}}


def unused_sync_helper():
    return requests.get(RATES_URL)
