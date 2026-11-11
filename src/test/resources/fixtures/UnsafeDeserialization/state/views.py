import json
import pickle

import yaml
from django.core import signing
from django.core.cache import cache
from django.http import JsonResponse

from .codec import decode, encode


class StrictSafeLoader(yaml.SafeLoader):
    pass


def restore(request):
    state = pickle.loads(request.body)  # Noncompliant {{Do not deserialize request.body of ANY /restore/ with pickle.loads()}}
    return JsonResponse({"keys": list(state)})


def config(request):
    unsafe = yaml.load(request.body, Loader=yaml.Loader)  # Noncompliant
    safe = yaml.load(request.body, Loader=yaml.SafeLoader)
    fast = yaml.load(request.body, Loader=yaml.CSafeLoader)
    strict = yaml.load(request.body, Loader=StrictSafeLoader)
    full = yaml.load(request.body, Loader=yaml.FullLoader)
    plain = yaml.safe_load(request.body)
    return JsonResponse({"n": len([unsafe, safe, fast, strict, full, plain])})


def upload(request):
    blob = request.FILES["state"]
    data = pickle.load(blob)  # Noncompliant
    meta = json.load(blob)
    return JsonResponse({"data": data, "meta": meta})


def prefs(request):
    prefs = decode(request.COOKIES.get("prefs", ""))
    signed = signing.loads(request.COOKIES.get("signed", ""))
    response = JsonResponse({"prefs": prefs, "signed": signed})
    response.set_cookie("prefs", encode(prefs))
    return response


def cached(request):
    key = request.GET["key"]
    return JsonResponse({"value": pickle.loads(cache.get(key))})
