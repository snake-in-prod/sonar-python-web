from urllib.parse import urlparse

import requests
from django.http import JsonResponse

ALLOWED_HOSTS = {"api.partner.example"}


def preview(request):
    url = request.GET["url"]
    resp = requests.get(url, timeout=5)  # Noncompliant {{request.GET of ANY /preview/}} [[2]]
    return JsonResponse({"status": resp.status_code})


def webhook_test(request):
    target = request.POST.get("callback")
    requests.post(target, json={"ping": True})  # Noncompliant
    return JsonResponse({})


def profile(request):
    user = request.GET["user"]
    data = requests.get(f"https://api.partner.example/users/{user}").json()
    return JsonResponse(data)


def checked(request):
    url = request.GET["url"]
    if urlparse(url).hostname not in ALLOWED_HOSTS:
        return JsonResponse({}, status=400)
    return JsonResponse(requests.get(url).json())


def proxied(request):
    url = request.GET["url"]
    parsed = urlparse(url)
    if parsed.netloc != "cdn.partner.example":
        return JsonResponse({}, status=400)
    return JsonResponse(requests.get(url).json())


class ImporterBase:
    @classmethod
    def auth_url(cls, server, key):
        return requests.post(server + "/oauth/request-token", data={"key": key})  # Noncompliant {{request.QUERY_PARAMS of ANY /jira/auth/}}


class JiraImporter(ImporterBase):
    pass


def jira_auth(request):
    # DRF 2 names: request.QUERY_PARAMS and request.DATA
    server = request.QUERY_PARAMS.get("url")
    return JsonResponse({"url": JiraImporter.auth_url(server, "k").text})
