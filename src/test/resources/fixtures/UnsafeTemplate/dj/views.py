from django.http import HttpResponse, HttpResponseNotFound, JsonResponse
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


def breadcrumb(request):
    # request.path is decoded: "<" and ">" sent percent-encoded come back as they are
    return HttpResponse(mark_safe('<a href="%s">here</a>' % request.path))  # Noncompliant


def pager(request):
    # get_full_path() percent-encodes quotes and angle brackets
    return HttpResponse(mark_safe('<a href="%s?page=2">next</a>' % request.get_full_path()))


def hello(request):
    name = request.GET.get("name", "you")
    return HttpResponse(f"<h1>Hello {name}</h1>")  # Noncompliant {{request.GET of ANY /hello/ instead of writing it in the HTML of HttpResponse()}}


def search(request):
    q = request.GET["q"]
    return HttpResponse("<p>You searched for %s</p>" % q, content_type="text/html; charset=utf-8")  # Noncompliant


def theme(request):
    return HttpResponse(content="<b>{}</b>".format(request.COOKIES.get("theme")))  # Noncompliant


def board(request, board_id):
    return HttpResponseNotFound("<p>No board " + board_id + "</p>")  # Noncompliant


def note(request):
    note = request.POST["note"]
    if not note:
        return HttpResponse("Empty note " + note)
    return HttpResponse(f"<p>File '{note}' saved</p>", content_type="text/plain")


def page(request, page):
    return HttpResponse(f"<p>Page {page}</p>")


def hello_plain(request):
    return HttpResponse(f"<h1>Hello {request.GET['name']}</h1>", "text/plain")


def hello_json(request):
    return JsonResponse({"html": f"<h1>Hello {request.GET['name']}</h1>"})


def hello_escaped(request):
    name = request.GET.get("name", "")
    return HttpResponse(f"<h1>Hello {escape(name)}</h1>" + format_html("<p>{}</p>", name))


def hello_text(request):
    return HttpResponse(f"Value must be < {request.GET['max']}")


def hello_typed(request):
    kind = request.GET.get("format", "text/html")
    return HttpResponse(f"<h1>Hello {request.GET['name']}</h1>", content_type=kind)


def customer(request, customer_name):
    # the route lets letters and spaces through only
    return HttpResponse(f"<h1>Welcome, {customer_name}!</h1>")


def animals(request, count, animals):
    return HttpResponse(f"<p>{count} {animals}</p>")  # Noncompliant {{parameter animals}}


def welcome(request, title):
    # title comes from kwargs= of path(), not from the URL
    return HttpResponse(f"<h1>{title}</h1>")


def archive(request, year):
    # a project converter
    return HttpResponse(f"<p>Year: {year}</p>")
