from django.urls import include, path
from rest_framework.routers import DefaultRouter

from . import views

router = DefaultRouter()
router.register("api/notes", views.NoteViewSet)
router.register("api/tags", views.TagViewSet)
router.register("api/public", views.PublicViewSet)

urlpatterns = [
    path("<int:pk>/delete/", views.delete_note),
    path("<int:pk>/archive/", views.archive_note),
    path("<int:pk>/pin/", views.pin_note),
    path("<int:pk>/edit/", views.NoteEdit.as_view()),
    path("<int:pk>/move/", views.NoteMove.as_view()),
    path("new/", views.NoteCreate.as_view()),
    path("signup/", views.signup),
    path("<int:pk>/like/", views.like_note),
    path("<uuid:code>/status/", views.delivery_status),
    path("demo/", views.create_demo),
    path("multi/a/", views.multi_delete),
    path("multi/b/", views.multi_delete),
    path("", include(router.urls)),
]
