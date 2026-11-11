from django.db import connection


def fetch(sql):
    with connection.cursor() as cursor:
        cursor.execute(sql)  # Noncompliant {{request.GET of ANY /items/}} [[3]]
        return cursor.fetchall()
