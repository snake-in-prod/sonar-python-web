from django.urls import path

from . import views

urlpatterns = [
    path("restore/", views.restore),
    path("config/", views.config),
    path("upload/", views.upload),
    path("prefs/", views.prefs),
    path("cached/", views.cached),
]
