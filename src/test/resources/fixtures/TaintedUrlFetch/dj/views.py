from urllib.parse import urlparse

import requests
from django.conf import settings
from django.http import JsonResponse
from django.views import View

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


class MirrorView(View):
    def setup(self, request, *args, **kwargs):
        super().setup(request, *args, **kwargs)
        self.source = request.GET["source"]

    def get(self, request):
        return JsonResponse(self.fetch())

    def fetch(self):
        return requests.get(self.source).json()  # Noncompliant {{request.GET of GET /mirror/}}


class StatusView(View):
    def setup(self, request, *args, **kwargs):
        super().setup(request, *args, **kwargs)
        self.api_url = settings.STATUS_API_URL
        self.page = int(request.GET.get("page", 1))

    def get(self, request):
        return JsonResponse(requests.get(self.api_url, params={"page": self.page}).json())
