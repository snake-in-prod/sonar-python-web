import os

from django.conf import settings
from django.http import FileResponse, HttpResponse

REPORTS = "/srv/reports"


def export(request):
    name = request.GET["file"]
    with open(os.path.join(REPORTS, name)) as fh:  # Noncompliant {{request.GET of ANY /export/}} [[2]]
        return HttpResponse(fh.read())


def avatar(request):
    upload = request.FILES["avatar"]
    target = os.path.join(settings.MEDIA_ROOT, upload.name)
    with open(target, "wb") as out:  # Noncompliant
        out.write(upload.read())
    return HttpResponse("ok")


def doc(request, name):
    # a str converter never matches "/": the name cannot leave the directory
    return FileResponse(open(os.path.join(REPORTS, name + ".pdf"), "rb"))


def raw(request, rest):
    return FileResponse(open(os.path.join(REPORTS, rest), "rb"))  # Noncompliant {{parameter rest}}


def safe_export(request):
    name = os.path.basename(request.GET["file"])
    with open(os.path.join(REPORTS, name)) as fh:
        return HttpResponse(fh.read())


def by_id(request):
    report_id = int(request.GET["id"])
    with open(os.path.join(REPORTS, "%d.csv" % report_id)) as fh:
        return HttpResponse(fh.read())
