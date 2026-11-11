from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import ArticleViewSet, PublicViewSet, ping

router = DefaultRouter()
router.register(r"articles", ArticleViewSet, basename="article")
router.register(r"public", PublicViewSet)

urlpatterns = [
    path("", include(router.urls)),
    path("ping/", ping),
]
