from django.http import HttpResponse
from django.template import Context, Template
from django.utils.html import escape, format_html
from django.utils.safestring import mark_safe


def greet(request):
    name = request.GET.get("name", "")
    return HttpResponse(mark_safe(f"<h1>Hello {name}</h1>"))  # Noncompliant {{request.GET of ANY /greet/}} [[2]]


def card(request):
    tpl = Template("<p>" + request.POST["bio"] + "</p>")  # Noncompliant
    return HttpResponse(tpl.render(Context({})))


def greet_escaped(request):
    name = escape(request.GET.get("name", ""))
    return HttpResponse(mark_safe(f"<h1>Hello {name}</h1>"))


def greet_html(request):
    return HttpResponse(format_html("<h1>Hello {}</h1>", request.GET.get("name", "")))


def card_safe(request):
    tpl = Template("<p>{{ bio }}</p>")
    return HttpResponse(tpl.render(Context({"bio": request.POST["bio"]})))
