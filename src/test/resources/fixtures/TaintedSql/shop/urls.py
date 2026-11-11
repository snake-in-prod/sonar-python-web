from django.urls import path

from . import views

urlpatterns = [
    path("search/", views.search),
    path("by-name/", views.by_name),
    path("filter/", views.filtered),
    path("report/", views.report),
    path("items/<int:item_id>/", views.item),
    path("sorted/", views.sorted_items),
    path("safe/", views.safe_search),
    path("graph/", views.graph),
]
