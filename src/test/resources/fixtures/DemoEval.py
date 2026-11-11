from flask import Flask, request


def calc():
    return eval(request.args["expr"])  # Noncompliant {{eval()}}


def safe():
    return "eval"
