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
    # Django keeps only the base name of an uploaded file's name: it cannot leave MEDIA_ROOT
    target = os.path.join(settings.MEDIA_ROOT, upload.name)
    with open(target, "wb") as out:
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


def task_zip(request, task_id):
    # the route's group (\d+) matches digits only
    return FileResponse(open("task_%s.zip" % task_id, "rb"))


def task_file(request, task_id, name):
    return FileResponse(open(os.path.join(REPORTS, task_id, name), "rb"))  # Noncompliant {{parameter name}}


def upload_dir(request, random_str):
    # (\w+) holds no "/" and no ".": the directory stays under REPORTS
    return FileResponse(open("%s/tmp/%s/list.txt" % (REPORTS, random_str), "rb"))
