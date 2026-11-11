from django.urls import path

from . import views

urlpatterns = [
    path("items/<int:pk>/", views.item_detail),
    path("items/", views.item_list),
    path("items/total/", views.item_total),
    path("prices/", views.PriceView.as_view()),
    path("items/<int:pk>/async/", views.item_detail_async),
    path("items/async/", views.item_list_async),
    path("items/wrapped/", views.item_list_wrapped),
    path("items/<int:pk>/sync/", views.item_detail_sync),
    path("items/lazy/", views.item_lazy),
    path("items/<int:pk>/ref/", views.item_by_reference),
]
