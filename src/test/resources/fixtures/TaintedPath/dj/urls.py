from django.urls import path, re_path

from . import views

urlpatterns = [
    path("export/", views.export),
    path("avatar/", views.avatar),
    path("doc/<str:name>/", views.doc),
    path("raw/<path:rest>/", views.raw),
    path("safe-export/", views.safe_export),
    path("by-id/", views.by_id),
    path("files/<path:rest>", views.stored),
    re_path(r"^tasks/(\d+)/zip/$", views.task_zip),
    re_path(r"^tasks/(\d+)/(.+)$", views.task_file),
    re_path(r"^uploads/(\w+)/$", views.upload_dir),
]
