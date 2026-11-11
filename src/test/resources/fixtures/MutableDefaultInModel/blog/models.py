from django.contrib.auth.models import AbstractUser
from django.contrib.postgres.fields import ArrayField, JSONField
from django.db import models
from django_extensions.db.models import TimeStampedModel
from jsonfield import JSONField as PackageJSONField


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


class Member(AbstractUser):
    settings = models.JSONField(default={})  # Noncompliant {{shared by every Member; use default=dict}}
    tags = models.JSONField(default=list)


class Stamped(TimeStampedModel):
    data = JSONField(default=[])  # Noncompliant


class Imported(TimeStampedModel):
    # jsonfield.JSONField deep-copies its default
    data = PackageJSONField(default={})
