from django.urls import path

from . import views

urlpatterns = [
    path("login/done/", views.login_done),
    path("logout/done/", views.logout_done),
    path("safe/done/", views.safe_done),
    path("back/", views.back),
    path("to/<str:slug>/", views.to_item),
    path("find/", views.find_page),
    path("export/", views.ExportView.as_view()),
    path("after/", views.after_login),
    path("avatar/<path:name>", views.avatar),
    path("join/", views.join_host),
    path("after2/", views.after_login_parsed),
    path("same/", views.same_page),
]
