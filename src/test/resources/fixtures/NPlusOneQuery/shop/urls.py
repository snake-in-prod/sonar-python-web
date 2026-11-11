from django.urls import path

from . import views

urlpatterns = [
    path("orders/", views.order_names),
    path("tags/", views.order_tags),
    path("emails/", views.emails),
]
