package io.github.snakeinprod.pythonweb.model;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.snakeinprod.pythonweb.TestProjects;
import java.util.List;
import org.junit.jupiter.api.Test;

class WebModelTest {

  private static Endpoint endpoint(WebModel model, String method, String path) {
    return model.endpoints().stream().filter(e -> e.methods().contains(method) && e.path().equals(path)).findFirst()
      .orElseThrow(() -> new AssertionError(method + " " + path + " not in " + model.endpoints()));
  }

  @Test
  void fastapi_routes_prefixes_and_dependencies() {
    WebModel model = TestProjects.model("fastapi");
    assertThat(model.frameworks()).containsExactly(Framework.FASTAPI);
    assertThat(model.usesAuth()).isTrue();
    assertThat(model.endpoints()).hasSize(10).allMatch(e -> e.framework() == Framework.FASTAPI);

    Endpoint health = endpoint(model, "GET", "/health");
    assertThat(health.async()).isTrue();
    assertThat(health.auth().present()).isFalse();
    assertThat(health.label()).isEqualTo("health");

    assertThat(endpoint(model, "GET", "/api/items/").auth().present()).isFalse();
    Endpoint create = endpoint(model, "POST", "/api/items/");
    assertThat(create.async()).isTrue();
    assertThat(create.mutating()).isTrue();
    assertThat(create.writes()).isTrue();
    assertThat(create.auth().evidence()).isEqualTo("Depends(get_current_user) on parameter user");

    Endpoint delete = endpoint(model, "DELETE", "/api/items/{item_id}");
    assertThat(delete.mutating()).isTrue();
    assertThat(delete.auth().present()).isFalse();

    assertThat(endpoint(model, "PUT", "/api/items/{item_id}").auth().evidence()).isEqualTo("Depends(require_admin) on the route");
    assertThat(endpoint(model, "PATCH", "/api/items/{item_id}/tag").auth().evidence()).isEqualTo("Depends(lookup) on parameter who");
    Endpoint bulk = endpoint(model, "POST", "/api/items/bulk");
    assertThat(bulk.methods()).containsExactly("PATCH", "POST");
    assertThat(bulk.auth().present()).isFalse();

    // a dependency reading a session cookie, and one from an auth module
    assertThat(endpoint(model, "POST", "/api/items/{item_id}/star").auth().evidence())
      .isEqualTo("Depends(who_is_calling) on parameter caller");
    assertThat(endpoint(model, "POST", "/api/items/{item_id}/hide").auth().evidence()).isEqualTo("Depends(gate) on the route");
    assertThat(endpoint(model, "POST", "/api/users/").auth().evidence()).isEqualTo("Depends(get_current_user) on include_router");
    // test files are read but give no endpoint
    assertThat(model.module("tests/test_items.py").isTest()).isTrue();
  }

  @Test
  void django_urlconfs_class_views_viewsets_and_permissions() {
    WebModel model = TestProjects.model("django");
    assertThat(model.frameworks()).containsExactlyInAnyOrder(Framework.DJANGO, Framework.DRF);
    assertThat(model.endpoints()).hasSize(16);

    Endpoint list = endpoint(model, "GET", "/blog/");
    assertThat(list.function()).isNull();
    assertThat(list.viewClass().name()).isEqualTo("PostList");
    assertThat(list.mutating()).isFalse();

    Endpoint edit = endpoint(model, "POST", "/blog/<int:pk>/edit/");
    assertThat(edit.methods()).containsExactly("GET", "POST");
    assertThat(edit.auth().evidence()).isEqualTo("LoginRequiredMixin");

    Endpoint post = endpoint(model, "POST", "/blog/new/");
    assertThat(post.methods()).containsExactly("POST");
    assertThat(post.auth().evidence()).isEqualTo("@login_required");

    Endpoint comment = endpoint(model, "POST", "/blog/comment/(?P<slug>[-\\w]+)/");
    assertThat(comment.methods()).containsExactly("GET", "POST");
    assertThat(comment.auth().present()).isFalse();
    assertThat(comment.writes()).isTrue();

    Endpoint about = endpoint(model, "ANY", "/about/");
    assertThat(about.mutating()).isFalse();
    assertThat(endpoint(model, "ANY", "/secret/").auth().evidence()).isEqualTo("login_required in mysite/urls.py");

    Endpoint create = endpoint(model, "POST", "/api/articles/");
    assertThat(create.framework()).isEqualTo(Framework.DRF);
    assertThat(create.function().label()).isEqualTo("ArticleViewSet.create");
    assertThat(create.auth().evidence()).startsWith("DEFAULT_PERMISSION_CLASSES");
    Endpoint destroy = endpoint(model, "DELETE", "/api/articles/{pk}/");
    assertThat(destroy.function()).isNull();
    assertThat(destroy.label()).isEqualTo("ArticleViewSet.destroy");
    assertThat(destroy.auth().present()).isTrue();
    assertThat(endpoint(model, "POST", "/api/articles/{pk}/publish/").function().name()).isEqualTo("publish");

    Endpoint pub = endpoint(model, "GET", "/api/public/{pk}/");
    assertThat(pub.auth().present()).isFalse();
    assertThat(pub.auth().evidence()).contains("AllowAny");
    assertThat(model.endpoints().stream().filter(e -> e.path().startsWith("/api/public/"))).hasSize(2);

    Endpoint ping = endpoint(model, "POST", "/api/ping/");
    assertThat(ping.methods()).containsExactly("GET", "POST");
    assertThat(ping.auth().present()).isFalse();
  }

  @Test
  void flask_blueprints_and_before_request_guards() {
    WebModel model = TestProjects.model("flask");
    assertThat(model.frameworks()).containsExactly(Framework.FLASK);
    assertThat(model.endpoints()).hasSize(5);
    assertThat(endpoint(model, "GET", "/").auth().present()).isFalse();
    Endpoint notes = endpoint(model, "POST", "/notes");
    assertThat(notes.methods()).containsExactly("GET", "POST");
    assertThat(notes.auth().evidence()).isEqualTo("@login_required");
    assertThat(endpoint(model, "POST", "/notes/<int:note_id>/delete").auth().present()).isFalse();
    assertThat(endpoint(model, "GET", "/files/<path:name>").mutating()).isFalse();
    assertThat(endpoint(model, "DELETE", "/admin/users/<int:uid>").auth().evidence()).isEqualTo("before_request check_admin");
  }

  @Test
  void imports_resolve_to_project_functions_and_classes() {
    WebModel model = TestProjects.model("fastapi");
    Module items = model.module("app/routers/items.py");
    assertThat(model.function(items, "get_db")).extracting(Function::toString).isEqualTo("app/deps.py#get_db");
    assertThat(model.cls(items, "ItemIn").module().path()).isEqualTo("app/schemas.py");
    Module main = model.module("app/main.py");
    assertThat(model.locate(main, "items.router")).isEqualTo(new WebModel.Ref(items, "router"));
    assertThat(model.locate(main, "FastAPI")).isNull();
    // a relative name the package does not define stays inside the package
    assertThat(Imports.split(".deps.get_db", "app/routers/items.py", model.paths()))
      .isEqualTo(new Imports.Target("app/routers/__init__.py", "deps.get_db"));
    assertThat(model.function(items, "requests.get")).isNull();
    assertThat(Imports.split("..deps.get_db", "app/routers/items.py", model.paths()))
      .isEqualTo(new Imports.Target("app/deps.py", "get_db"));
  }

  @Test
  void no_framework_no_endpoints_and_test_paths() {
    WebModel model = TestProjects.model("lib/util.py", "import os\n\ndef f(x):\n    return os.path.join(x)\n");
    assertThat(model.hasFramework()).isFalse();
    assertThat(model.endpoints()).isEmpty();
    for (String p : List.of("test_app.py", "pkg/app_test.py", "conftest.py", "tests/x.py", "a/fixtures/b.py")) {
      assertThat(Module.isTestPath(p)).as(p).isTrue();
    }
    for (String p : List.of("app.py", "testing.py", "pkg/latest.py", "contest.py")) {
      assertThat(Module.isTestPath(p)).as(p).isFalse();
    }
  }

  @Test
  void function_params_defaults_and_decorators() {
    WebModel model = TestProjects.model("m.py", """
      from fastapi import FastAPI, Query
      app = FastAPI()

      @app.get("/x/{a}")
      async def f(a: int, *args, q: str = Query(None), **kw) -> dict:
          return {}
      """);
    Function f = model.module("m.py").function("f");
    assertThat(f.params()).extracting(Function.Param::name).containsExactly("a", "args", "q", "kw");
    assertThat(f.params().get(0).annotationText()).isEqualTo("int");
    assertThat(f.params().get(1).stars()).isEqualTo(1);
    assertThat(Exprs.text(f.params().get(2).defaultValue())).isEqualTo("Query(None)");
    assertThat(f.decorators()).singleElement().satisfies(d -> {
      assertThat(d.name()).isEqualTo("app.get");
      assertThat(d.receiver()).isEqualTo("app");
      assertThat(d.last()).isEqualTo("get");
    });
    assertThat(f.isAsync()).isTrue();
    assertThat(model.endpoints()).singleElement().extracting(Endpoint::path).isEqualTo("/x/{a}");
  }

  @Test
  void layouts_seen_in_real_apps() {
    // two Django projects in one repository, star imports, a list included by name, urlpatterns extended in an if,
    // Django 1.x string views and patterns() tuples
    WebModel django = TestProjects.model(
      "site/settings.py", "ROOT_URLCONF = 'site.urls'\n",
      "site/urls.py", """
        from django.conf import settings
        from django.urls import include, path
        urlpatterns = [path("shop/", include("shop.urls"))]
        if settings.DEBUG:
            urlpatterns = [path("debug/", include("debug_toolbar.urls"))] + urlpatterns
        """,
      "shop/urls.py", """
        from django.urls import include, path
        from .views import *
        extra = [path("tags", tags)]
        urlpatterns = [path("new", item_new), path("", include((extra, "tags")))]
        """,
      "shop/views.py", "def item_new(request):\n    pass\n\ndef tags(request):\n    pass\n",
      "lab/old/settings.py", "ROOT_URLCONF = 'old.urls'\n",
      "lab/old/urls.py", """
        from django.conf.urls import patterns, url, include
        urlpatterns = patterns("", url(r"^$", "pages.views.home"), (r"^p/(?P<pk>[\\d]+)/$", "pages.views.page"))
        """,
      "lab/pages/views.py", "def home(request):\n    pass\n\ndef page(request, pk):\n    pass\n");
    assertThat(django.endpoints()).extracting(Endpoint::path)
      .containsExactlyInAnyOrder("/shop/new", "/shop/tags", "/", "/p/(?P<pk>[\\d]+)/");

    // urlpatterns summed from list variables, one passed with a star
    WebModel lists = TestProjects.model(
      "proj/settings.py", "ROOT_URLCONF = 'proj.urls'\n",
      "proj/urls.py", """
        from django.conf.urls.i18n import i18n_patterns
        from django.urls import path
        from . import views
        i18n_urls = [path("home", views.home)]
        urls = [path("a", views.a)]
        urls += [path("b", views.b)]
        urlpatterns = i18n_patterns(*i18n_urls) + urls
        """,
      "proj/views.py", "def home(request):\n    pass\n\ndef a(request):\n    pass\n\ndef b(request):\n    pass\n");
    assertThat(lists.endpoints()).extracting(Endpoint::path).containsExactlyInAnyOrder("/home", "/a", "/b");

    // a Flask app made by a factory, a FastAPI router subclass
    WebModel apps = TestProjects.model(
      "web/app.py", """
        from flask import Flask
        def create_app():
            app = Flask(__name__)
            return app
        application = create_app()
        @application.route("/apks")
        def apks():
            pass
        """,
      "api/main.py", """
        from fastapi import APIRouter, FastAPI
        class SimpleRouter(APIRouter):
            pass
        api = SimpleRouter()
        @api.get("/status")
        def status():
            pass
        app = FastAPI()
        app.include_router(api)
        """);
    assertThat(apps.endpoints()).extracting(Endpoint::path).containsExactlyInAnyOrder("/apks", "/status");
  }
}
