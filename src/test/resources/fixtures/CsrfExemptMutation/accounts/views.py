from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST
from rest_framework.decorators import api_view

from .models import Account, Event, Like


@csrf_exempt
@login_required
def transfer(request):  # Noncompliant {{Remove the CSRF exemption of ANY /transfer/}} [[1]]
    Account.objects.filter(owner=request.user).update(balance=0)


@csrf_exempt
@require_POST
def like(request, pk):  # Noncompliant {{uses the session user}}
    Like.objects.create(user=request.user, post_id=pk)


@method_decorator(csrf_exempt, name="dispatch")
class EditProfile(LoginRequiredMixin, View):
    def post(self, request):  # Noncompliant {{LoginRequiredMixin}}
        request.user.profile.save()


@login_required
def bulk_delete(request):  # Noncompliant
    Account.objects.filter(owner=request.user).delete()


def close_account(request):  # Noncompliant
    Account.objects.filter(owner=request.user).delete()


@csrf_exempt
@require_POST
def stripe_hook(request):
    Event.objects.create(payload=request.body)


@csrf_exempt
@login_required
def balance(request):
    return Account.objects.get(owner=request.user).balance


@csrf_exempt
@require_POST
def api_sync(request):
    if request.headers.get("Authorization") != "Bearer x":
        return None
    Event.objects.create(payload=request.body)


@csrf_exempt
@api_view(["POST"])
def drf_update(request):
    Account.objects.filter(owner=request.user).update(balance=1)


@login_required
@require_POST
def rename(request):
    Account.objects.filter(owner=request.user).update(name=request.POST["name"])


@csrf_exempt
@login_required
@require_GET
def touch(request):
    Account.objects.filter(owner=request.user).update(seen=True)


class SettingsView(LoginRequiredMixin, View):
    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)

    def get(self, request):
        return Account.objects.get(owner=request.user)
