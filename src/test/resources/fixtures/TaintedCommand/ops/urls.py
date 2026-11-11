from django.urls import path

from . import views

urlpatterns = [
    path("ping/", views.ping),
    path("archive/", views.archive),
    path("trace/", views.trace),
    path("lookup/<int:count>/", views.lookup),
]
