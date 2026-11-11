from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.http import require_POST
from django.views.generic import CreateView, UpdateView
from rest_framework import viewsets
from rest_framework.permissions import AllowAny, IsAuthenticated

from .models import Note, Tag


@require_POST
def delete_note(request, pk):  # Noncompliant {{POST /notes/<int:pk>/delete/}}
    Note.objects.filter(pk=pk).delete()


@require_POST
@login_required
def archive_note(request, pk):
    Note.objects.filter(pk=pk).update(archived=True)


def pin_note(request, pk):
    if not request.user.is_authenticated:
        return None
    note = Note.objects.get(pk=pk)
    note.save()


class NoteEdit(UpdateView):  # Noncompliant {{GET|POST /notes/<int:pk>/edit/}}
    model = Note


class NoteMove(View):
    @method_decorator(login_required)
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)

    def post(self, request, pk):
        Note.objects.filter(pk=pk).update(folder=request.POST["folder"])


class NoteCreate(LoginRequiredMixin, CreateView):
    model = Note


@require_POST
def signup(request):
    Note.objects.create(title="welcome")


def like_note(request, pk):
    note = Note.objects.get(pk=pk)
    return note.title


@require_POST
def delivery_status(request, code):
    """Handle delivery status callbacks of the SMS provider."""
    Note.objects.filter(code=code).update(delivered=True)


@require_POST
def create_demo(request):
    rate_limit_request_by_ip(request, domain="demo")
    Note.objects.create(title=request.POST["title"])


@require_POST
def multi_delete(request):  # Noncompliant {{POST /notes/multi/a/ and 1 more endpoint of multi_delete}}
    Note.objects.all().delete()


class NoteViewSet(viewsets.ModelViewSet):  # Noncompliant {{POST /notes/api/notes/ and 3 more endpoints of NoteViewSet}}
    queryset = Note.objects.all()


class TagViewSet(viewsets.ModelViewSet):
    queryset = Tag.objects.all()
    permission_classes = [IsAuthenticated]


class PublicViewSet(viewsets.ModelViewSet):
    queryset = Note.objects.all()
    permission_classes = [AllowAny]
