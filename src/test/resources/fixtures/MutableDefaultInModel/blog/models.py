from django.contrib.postgres.fields import ArrayField
from django.db import models


class Post(models.Model):
    title = models.CharField(max_length=100, default="")
    meta = models.JSONField(default={})  # Noncompliant {{shared by every Post; use default=dict}}
    tags = ArrayField(models.CharField(max_length=20), default=[])  # Noncompliant
    extra = models.JSONField(default=dict)
    flags = models.JSONField(default=list, blank=True)
    choices = models.CharField(max_length=10, choices=[("a", "A")])
    LIMITS = {"title": 100}


class Draft:
    meta = models.JSONField(default={})
