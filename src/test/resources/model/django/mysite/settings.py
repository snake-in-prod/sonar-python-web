ROOT_URLCONF = "mysite.urls"
INSTALLED_APPS = ["django.contrib.auth", "rest_framework", "blog", "api"]
REST_FRAMEWORK = {
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
}
