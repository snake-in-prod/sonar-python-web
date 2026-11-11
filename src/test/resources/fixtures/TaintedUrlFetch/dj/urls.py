from django.urls import path

from . import views

urlpatterns = [
    path("preview/", views.preview),
    path("webhook/test/", views.webhook_test),
    path("profile/", views.profile),
    path("checked/", views.checked),
    path("proxied/", views.proxied),
    path("jira/auth/", views.jira_auth),
]
