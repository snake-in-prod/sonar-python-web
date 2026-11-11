from django.urls import include, path

urlpatterns = [
    path("notes/", include("notes.urls")),
]
