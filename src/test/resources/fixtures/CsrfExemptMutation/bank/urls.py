from django.urls import path
from django.views.decorators.csrf import csrf_exempt

from accounts import views

urlpatterns = [
    path("transfer/", views.transfer),
    path("like/<int:pk>/", views.like),
    path("profile/", views.EditProfile.as_view()),
    path("bulk-delete/", csrf_exempt(views.bulk_delete)),
    path("nested/", csrf_exempt(views.login_required(views.close_account))),
    path("hooks/stripe/", views.stripe_hook),
    path("balance/", views.balance),
    path("api/sync/", views.api_sync),
    path("api/drf/", views.drf_update),
    path("rename/", views.rename),
    path("touch/", views.touch),
    path("settings/", views.SettingsView.as_view()),
]
