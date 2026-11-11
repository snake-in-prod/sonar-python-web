package io.github.snakeinprod.pythonweb.taint;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.snakeinprod.pythonweb.TestProjects;
import io.github.snakeinprod.pythonweb.model.WebModel;
import java.util.List;
import org.junit.jupiter.api.Test;

class TaintEngineTest {

  private static final String DJANGO_URLS = """
    from django.urls import path
    from . import views

    urlpatterns = [
        path("search/", views.search),
        path("go/", views.go),
        path("safe/", views.safe),
    ]
    """;

  private static List<Finding> findings(String... files) {
    WebModel model = TestProjects.model(files);
    return TaintEngine.run(model, TaintModels.defaults()).findings();
  }

  private static List<String> messages(Finding f) {
    return f.path().stream().map(Step::message).toList();
  }

  @Test
  void django_get_parameter_into_an_f_string_query() {
    List<Finding> found = findings("shop/urls.py", DJANGO_URLS, "shop/views.py", """
      from django.db import connection
      from django.shortcuts import redirect

      def search(request):
          q = request.GET.get("q", "")
          with connection.cursor() as cursor:
              cursor.execute(f"SELECT * FROM item WHERE name = '{q}'")
              cursor.execute("SELECT * FROM item WHERE name = %s", [q])

      def go(request):
          return redirect(request.GET["next"])

      def safe(request):
          item_id = int(request.GET["id"])
          with connection.cursor() as cursor:
              cursor.execute("SELECT * FROM item WHERE id = %d" % item_id)
      """);
    assertThat(found).extracting(Finding::kind).containsExactly("sql", "redirect");
    Finding sql = found.get(0);
    assertThat(sql.sinkName()).isEqualTo("cursor.execute");
    assertThat(sql.label()).isEqualTo("request.GET");
    assertThat(sql.sink().token().line()).isEqualTo(7);
    assertThat(sql.source().token().line()).isEqualTo(5);
    assertThat(messages(sql)).containsExactly("request.GET read here", "assigned to q", "reaches cursor.execute()");
    assertThat(sql.endpoint().path()).isEqualTo("/search/");
    assertThat(sql.where()).isEqualTo("ANY /search/");
    assertThat(found.get(1).endpoint().label()).isEqualTo("go");
  }

  @Test
  void through_helpers_in_other_modules_both_ways() {
    List<Finding> found = findings("app/main.py", """
      from fastapi import FastAPI
      from .queries import build, run
      from . import service

      app = FastAPI()

      @app.get("/a")
      def a(term: str):
          sql = build(term)
          return run(sql)

      @app.get("/b")
      def b(term: str):
          return service.search(term)
      """, "app/queries.py", """
      from sqlalchemy import text
      from .db import engine

      def build(t):
          return "SELECT * FROM x WHERE n = '%s'" % t

      def run(statement):
          with engine.connect() as conn:
              return conn.execute(text(statement))
      """, "app/service.py", """
      from .repo import Repo

      def search(term):
          clean = term.strip()
          return Repo().find(clean)

      def find_all(term):
          return Repo.find(None, term)
      """, "app/repo.py", """
      from django.db import connection

      class Repo:
          def find(self, name):
              connection.cursor().execute("SELECT 1 WHERE n = '" + name + "'")
      """);
    // a: build() returns its parameter formatted, run() passes it to text(); b: Repo().find is not followed (no types)
    assertThat(found).hasSize(1);
    Finding f = found.get(0);
    assertThat(f.kind()).isEqualTo("sql");
    assertThat(f.sinkName()).isEqualTo("text");
    assertThat(f.sink().module().path()).isEqualTo("app/queries.py");
    assertThat(f.label()).isEqualTo("parameter term");
    assertThat(f.endpoint().path()).isEqualTo("/a");
    assertThat(messages(f)).containsExactly("request input term", "passed to build()", "returned", "returned by build()",
      "assigned to sql", "passed to run()", "reaches text()");
  }

  @Test
  void class_method_called_through_the_class_and_two_levels_deep() {
    List<Finding> found = findings("app.py", """
      import subprocess
      from flask import Flask, request

      app = Flask(__name__)

      def shell(cmd):
          return subprocess.run(cmd, shell=True)

      def wrap(prefix, arg):
          return shell(prefix + " " + arg)

      def tidy(arg):
          return shell("ls " + shlex_quote(arg))

      @app.route("/run", methods=["POST"])
      def run():
          wrap("echo", request.form["arg"])
          subprocess.run(["echo", request.form["arg"]])
          return "ok"
      """);
    assertThat(found).singleElement().satisfies(f -> {
      assertThat(f.kind()).isEqualTo("command");
      assertThat(f.sink().token().line()).isEqualTo(7);
      assertThat(f.label()).isEqualTo("request.form");
      assertThat(f.endpoint().path()).isEqualTo("/run");
      assertThat(messages(f)).containsExactly("request.form read here", "passed to wrap()", "passed to shell()",
        "reaches subprocess.run()");
    });
  }

  @Test
  void sanitizers_and_guards() {
    List<Finding> found = findings("app.py", """
      import os
      import shlex
      from flask import Flask, redirect, request, send_file
      from django.utils.http import url_has_allowed_host_and_scheme

      app = Flask(__name__)
      ALLOWED = {"/home", "/account"}

      @app.route("/a")
      def a():
          os.system("ls " + shlex.quote(request.args["d"]))
          return send_file(os.path.join("/srv", os.path.basename(request.args["f"])))

      @app.route("/b")
      def b():
          nxt = request.args.get("next", "/")
          if not url_has_allowed_host_and_scheme(nxt, allowed_hosts=None):
              nxt = "/"
          return redirect(nxt)

      @app.route("/c")
      def c():
          target = request.args.get("to")
          if target not in ALLOWED:
              return redirect("/")
          return redirect(target)

      @app.route("/d")
      def d():
          name = request.args["f"]
          path = os.path.realpath(os.path.join("/srv", name))
          if not path.startswith("/srv/"):
              return "no"
          return send_file(path)

      @app.route("/e")
      def e():
          os.system(shlex.quote(request.args["d"]) + " && true")
          return send_file(shlex.quote(request.args["f"]))
      """);
    // shlex.quote clears command only: the path sink in e() still gets it
    assertThat(found).singleElement().satisfies(f -> {
      assertThat(f.kind()).isEqualTo("path");
      assertThat(f.sink().token().line()).isEqualTo(39);
    });
  }

  @Test
  void containers_join_format_and_mutating_calls() {
    List<Finding> found = findings("views.py", """
      from django.db import connection
      from django.urls import path

      def report(request):
          clauses = []
          for key, value in request.GET.items():
              clauses.append(f"{key} = '{value}'")
          where = " AND ".join(clauses)
          query = "SELECT * FROM t WHERE {}".format(where)
          params = {"q": query}
          cur = connection.cursor()
          cur.execute(params["q"])
          cur.execute("SELECT 1 WHERE a = %(a)s", {"a": request.GET["a"]})

      urlpatterns = [path("report/", report)]
      """);
    assertThat(found).singleElement().satisfies(f -> {
      assertThat(f.kind()).isEqualTo("sql");
      assertThat(f.sink().token().line()).isEqualTo(12);
      assertThat(messages(f)).startsWith("request.GET read here", "assigned to key");
    });
  }

  @Test
  void fastapi_parameters_body_models_and_uploads() {
    List<Finding> found = findings("api.py", """
      import os
      import pickle
      import subprocess
      import yaml
      import httpx
      from fastapi import Depends, FastAPI, Request, UploadFile
      from pydantic import BaseModel

      app = FastAPI()

      class Job(BaseModel):
          command: str

      def get_db():
          yield None

      @app.post("/jobs")
      async def jobs(job: Job, cmd: str, db=Depends(get_db)):
          os.system(job.command)
          subprocess.run(cmd, shell=False)
          os.system(db)

      @app.post("/restore")
      async def restore(file: UploadFile, request: Request):
          data = await file.read()
          pickle.loads(data)
          yaml.load(await request.body(), Loader=yaml.SafeLoader)
          yaml.load(await request.body())

      @app.get("/fetch")
      async def fetch(url: str):
          async with httpx.AsyncClient() as client:
              r = await client.get(url)
          return r.text
      """);
    assertThat(found).extracting(f -> f.kind() + ":" + f.sink().token().line() + ":" + f.label()).containsExactly(
      "command:19:parameter job", "deserialization:26:parameter file", "deserialization:28:request.body", "ssrf:33:parameter url");
  }

  @Test
  void flask_helper_reading_the_request_is_found_through_its_caller() {
    List<Finding> found = findings("site.py", """
      from flask import Flask, render_template_string, request
      from markupsafe import escape

      app = Flask(__name__)

      def visitor():
          return request.args.get("name", "guest")

      @app.route("/hello")
      def hello():
          page = "<h1>Hello " + visitor() + "</h1>"
          render_template_string("<p>" + escape(visitor()) + "</p>")
          return render_template_string(page)
      """);
    assertThat(found).singleElement().satisfies(f -> {
      assertThat(f.kind()).isEqualTo("template");
      assertThat(f.function().name()).isEqualTo("visitor");
      assertThat(f.endpoint().path()).isEqualTo("/hello");
      assertThat(f.source().module().path()).isEqualTo("site.py");
      assertThat(messages(f)).containsExactly("request.args read here", "returned", "returned by visitor()", "assigned to page",
        "reaches render_template_string()");
    });
  }

  @Test
  void class_based_views_read_self_request_and_branches_join() {
    List<Finding> found = findings("blog/views.py", """
      from django.http import HttpResponseRedirect
      from django.views import View

      class Jump(View):
          def get(self, request, slug):
              if slug == "home":
                  target = "/"
              else:
                  target = self.request.GET.get("to")
              return HttpResponseRedirect(target)

          def post(self, request, slug):
              return HttpResponseRedirect(slug)
      """, "blog/urls.py", """
      from django.urls import path
      from .views import Jump

      urlpatterns = [path("jump/<slug>/", Jump.as_view())]
      """);
    assertThat(found).extracting(f -> f.sink().token().line() + ":" + f.label() + ":" + f.where())
      .containsExactly("10:request.GET:GET /jump/<slug>/", "13:parameter slug:POST /jump/<slug>/");
  }

  @Test
  void recursion_and_a_mutual_loop_terminate() {
    List<Finding> found = findings("app.py", """
      import os
      from flask import Flask, request

      app = Flask(__name__)

      def ping(x, n):
          if n > 0:
              return pong(x, n - 1)
          os.system(x)
          return x

      def pong(y, n):
          return ping(y + "!", n)

      @app.route("/loop")
      def loop():
          return pong(request.args["x"], 3)
      """);
    assertThat(found).singleElement().satisfies(f -> assertThat(f.sink().token().line()).isEqualTo(9));
  }

  @Test
  void summaries_say_what_a_function_does_with_its_parameters() {
    WebModel model = TestProjects.model("lib.py", """
      import os

      def passthrough(a, b):
          return a.upper()

      def run(cmd):
          os.popen(cmd)
      """, "app.py", "from flask import Flask\n");
    TaintResult r = TaintEngine.run(model, TaintModels.defaults());
    Summary pass = r.summary(model.module("lib.py").function("passthrough"));
    assertThat(pass.returns()).containsOnlyKeys(0);
    assertThat(pass.sinks()).isEmpty();
    Summary run = r.summary(model.module("lib.py").function("run"));
    assertThat(run.sinks()).singleElement().satisfies(s -> {
      assertThat(s.param()).isZero();
      assertThat(s.kind()).isEqualTo("command");
      assertThat(s.sinkName()).isEqualTo("os.popen");
    });
    assertThat(r.findings()).isEmpty();
  }
}
