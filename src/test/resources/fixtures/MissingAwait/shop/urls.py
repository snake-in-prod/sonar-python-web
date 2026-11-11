from django.urls import path

from . import views

urlpatterns = [
    path("checkout/", views.checkout),
    path("checkout/awaited/", views.checkout_awaited),
]
