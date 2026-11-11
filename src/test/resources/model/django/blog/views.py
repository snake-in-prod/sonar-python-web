from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import render
from django.views.decorators.http import require_POST
from django.views.generic import ListView, UpdateView

from .models import Comment, Post


class PostList(ListView):
    model = Post


class PostEdit(LoginRequiredMixin, UpdateView):
    model = Post


@login_required
@require_POST
def new_post(request):
    Post.objects.create(title=request.POST["title"])


def comment(request, slug):
    if request.method == "POST":
        Comment.objects.create(slug=slug, text=request.POST["text"])
    return render(request, "comment.html")


def about(request):
    return render(request, "about.html")


def secret(request):
    return render(request, "secret.html")
