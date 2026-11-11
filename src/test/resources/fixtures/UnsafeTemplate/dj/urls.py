from django.urls import path

from . import views

urlpatterns = [
    path("greet/", views.greet),
    path("card/", views.card),
    path("greet/escaped/", views.greet_escaped),
    path("greet/html/", views.greet_html),
    path("card/safe/", views.card_safe),
]
