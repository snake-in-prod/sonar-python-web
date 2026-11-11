from django.contrib.auth.mixins import LoginRequiredMixin
from django.views import View

from .models import Note, Tag
from .viewreg import register_view


@register_view(Note, "purge", detail=False)
class NotePurge(View):
    def post(self, request):  # Noncompliant {{POST /notes/bulk/purge/}}
        Note.objects.all().delete()


@register_view(Note, "lock")
class NoteLock(LoginRequiredMixin, View):
    def post(self, request, pk):
        Note.objects.filter(pk=pk).update(locked=True)


@register_view(Tag, "wipe", detail=False)
class TagWipe(View):
    def post(self, request):
        Tag.objects.all().delete()
