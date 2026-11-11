import os
import re
import shlex
import subprocess

from django.http import HttpResponse
from django.views.decorators.http import require_POST

from .shell import run, run_args

TOOLS = {"traceroute", "mtr"}


def ping(request):
    host = request.GET["host"]
    os.system("ping -c 1 " + host)  # Noncompliant {{Do not pass request.GET of ANY /ping/ to os.system() through a shell}}
    os.system("ping -c 1 " + shlex.quote(host))
    subprocess.run(["ping", "-c", "1", host])
    return HttpResponse("ok")


@require_POST
def archive(request):
    name = request.POST["name"]
    out = run(f"tar czf /tmp/{name}.tgz /srv/data")
    run_args(["tar", "czf", "/tmp/" + name + ".tgz", "/srv/data"])
    return HttpResponse(out)


def trace(request):
    tool = request.GET.get("tool", "mtr")
    host = request.GET.get("host", "")
    if tool not in TOOLS:
        return HttpResponse(status=400)
    if not re.fullmatch(r"[a-z0-9.-]+", host):
        return HttpResponse(status=400)
    return HttpResponse(subprocess.check_output(f"{tool} {host}", shell=True))


def lookup(request, count):
    limit = int(request.GET.get("limit", "5"))
    return HttpResponse(os.popen(f"tail -n {limit} /var/log/app.log | head -{count}").read())
