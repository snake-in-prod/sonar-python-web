from django.db import models


class Account(models.Model):
    balance = models.IntegerField()


class Event(models.Model):
    payload = models.TextField()


class Like(models.Model):
    post_id = models.IntegerField()
