import subprocess


def run(cmd):
    return subprocess.check_output(cmd, shell=True)  # Noncompliant {{request.POST of POST /archive/}} [[3]]


def run_args(args):
    return subprocess.check_output(args)
