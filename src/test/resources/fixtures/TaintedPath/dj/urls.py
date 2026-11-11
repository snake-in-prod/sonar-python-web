from django.urls import path

from . import views

urlpatterns = [
    path("export/", views.export),
    path("avatar/", views.avatar),
    path("doc/<str:name>/", views.doc),
    path("raw/<path:rest>/", views.raw),
    path("safe-export/", views.safe_export),
    path("by-id/", views.by_id),
    path("files/<path:rest>", views.stored),
]
