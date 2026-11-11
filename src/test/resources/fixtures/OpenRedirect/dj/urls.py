from django.urls import path

from . import views

urlpatterns = [
    path("login/done/", views.login_done),
    path("logout/done/", views.logout_done),
    path("safe/done/", views.safe_done),
    path("back/", views.back),
    path("to/<str:slug>/", views.to_item),
    path("after/", views.after_login),
    path("same/", views.same_page),
]
