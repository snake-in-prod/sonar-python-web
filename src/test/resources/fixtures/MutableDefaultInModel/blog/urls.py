from django.urls import path

from . import views

urlpatterns = [
    path("counter/", views.counter),
    path("options/", views.options),
    path("copied/", views.copied),
    path("optional/", views.optional),
    path("items/", views.ItemView.as_view()),
]
