from django.contrib import admin
from django.contrib.auth.decorators import login_required
from django.urls import include, path

from blog import views as blog_views

urlpatterns = [
    path("admin/", admin.site.urls),
    path("blog/", include("blog.urls")),
    path("api/", include("api.urls")),
    path("about/", blog_views.about),
]
urlpatterns += [path("secret/", login_required(blog_views.secret))]
