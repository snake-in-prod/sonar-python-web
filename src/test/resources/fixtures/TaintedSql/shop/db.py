from django.db import connection


def fetch(sql):
    with connection.cursor() as cursor:
        cursor.execute(sql)  # Noncompliant {{request.GET of ANY /report/}} [[4]]
        return cursor.fetchall()


def fetch_with(sql, params):
    with connection.cursor() as cursor:
        cursor.execute(sql, params)
        return cursor.fetchall()
