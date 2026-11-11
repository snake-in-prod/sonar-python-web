from urllib.parse import urlparse

from django.http import HttpResponseRedirect
from django.shortcuts import redirect
from django.utils.http import url_has_allowed_host_and_scheme


def login_done(request):
    return redirect(request.GET.get("next", "/"))  # Noncompliant {{request.GET of ANY /login/done/}} [[1]]


def logout_done(request):
    target = request.POST["next"]
    return HttpResponseRedirect(target)  # Noncompliant


def safe_done(request):
    target = request.GET.get("next", "/")
    if not url_has_allowed_host_and_scheme(target, allowed_hosts={request.get_host()}):
        target = "/"
    return redirect(target)


def back(request):
    # the Referer sends the user back where they came from
    return HttpResponseRedirect(request.META.get("HTTP_REFERER", "/"))


def to_item(request, slug):
    return redirect(f"/items/{slug}/")


def _allow_redirect(url):
    parsed = urlparse(url)
    return not parsed.netloc


def after_login(request):
    target = request.GET.get("next")
    if target and _allow_redirect(target):
        return redirect(target)
    return redirect("/")


def same_page(request):
    return redirect(request.path)
