from django.urls import path, re_path

from . import views

urlpatterns = [
    path("", views.PostList.as_view(), name="list"),
    path("<int:pk>/edit/", views.PostEdit.as_view()),
    path("new/", views.new_post),
    re_path(r"^comment/(?P<slug>[-\w]+)/$", views.comment),
]
