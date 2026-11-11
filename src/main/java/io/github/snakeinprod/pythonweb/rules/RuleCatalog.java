package io.github.snakeinprod.pythonweb.rules;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.function.Supplier;

/**
 * Every rule with its metadata, in repository pythonweb-python (language py). {@code active}: in the built-in
 * "Python Web" profile. {@code sinkKind}: the taint sink kind a taint rule reports (see models/taint.json), null for
 * the others. A longer description, when a rule has one, is {@code /rules/<Key>.html} on the classpath.
 */
public final class RuleCatalog {

  public static final String LANGUAGE = "py";
  public static final String REPOSITORY = "pythonweb-python";

  private RuleCatalog() {
  }

  public enum Type { VULNERABILITY, BUG, CODE_SMELL }

  public record Spec(String key, Type type, String severity, boolean active, String sinkKind, String name, String description,
    String example, Supplier<PwRule> factory) {

    public String html() {
      try (InputStream in = RuleCatalog.class.getResourceAsStream("/rules/" + key + ".html")) {
        if (in != null) {
          return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
      } catch (IOException e) {
        // fall back to the generated description
      }
      return "<p>" + escape(description) + "</p>\n<h2>Noncompliant code example</h2>\n<pre>\n" + escape(example) + "\n</pre>\n";
    }

    private static String escape(String s) {
      return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
  }

  /** A rule not written yet: reports nothing. */
  private static final Supplier<PwRule> STUB = () -> ctx -> { };

  private static Spec spec(String key, Type type, String severity, boolean active, String sinkKind, String name, String description,
    String example, Supplier<PwRule> factory) {
    return new Spec(key, type, severity, active, sinkKind, name, description, example, factory);
  }

  public static final List<Spec> ALL = List.of(
    spec("TaintedSql", Type.VULNERABILITY, "CRITICAL", true, "sql", "SQL queries should not be built from request data",
      "Request data reaching raw SQL (cursor.execute, Django raw(), extra() and RawSQL, SQLAlchemy text() and execute()) through an f-string, % or + lets a caller change the query. Pass the values as query parameters.",
      "def search(request):\n    q = request.GET[\"q\"]\n    cursor.execute(f\"SELECT * FROM item WHERE name = '{q}'\")  # Noncompliant", STUB),
    spec("TaintedCommand", Type.VULNERABILITY, "CRITICAL", true, "command", "OS commands should not be built from request data",
      "Request data reaching a shell (subprocess with shell=True, os.system, os.popen) lets a caller run any command. Pass an argument list without a shell, or quote with shlex.quote.",
      "@app.post(\"/ping\")\ndef ping(host: str):\n    os.system(\"ping -c 1 \" + host)  # Noncompliant", STUB),
    spec("TaintedPath", Type.VULNERABILITY, "MAJOR", true, "path", "File paths should not be built from request data",
      "Request data reaching open(), pathlib, send_file, FileResponse or os.remove without a safe join or a check that the path stays in its directory lets a caller read or delete any file.",
      "@app.route(\"/files/<name>\")\ndef download(name):\n    return send_file(os.path.join(UPLOADS, name))  # Noncompliant", STUB),
    spec("TaintedUrlFetch", Type.VULNERABILITY, "MAJOR", true, "ssrf", "Server-side requests should not go to URLs from request data",
      "Request data used as the URL of requests, httpx, urllib or aiohttp lets a caller make the server call internal services (server-side request forgery). Check the host against an allow-list.",
      "@router.get(\"/preview\")\nasync def preview(url: str):\n    return httpx.get(url).text  # Noncompliant", STUB),
    spec("OpenRedirect", Type.VULNERABILITY, "MAJOR", true, "redirect", "Redirect targets from the request should be checked",
      "Request data passed to redirect(), RedirectResponse or HttpResponseRedirect without url_has_allowed_host_and_scheme or an allow-list sends users anywhere from a trusted link.",
      "def login_done(request):\n    return redirect(request.GET[\"next\"])  # Noncompliant", STUB),
    spec("UnsafeTemplate", Type.VULNERABILITY, "CRITICAL", true, "template", "Request data should not be rendered as markup or template source",
      "Request data reaching mark_safe, Markup, render_template_string, Template(...).render or an HTMLResponse built from an f-string is cross-site scripting or template injection. Let the template engine escape it.",
      "@app.route(\"/hello\")\ndef hello():\n    return render_template_string(\"Hello \" + request.args[\"name\"])  # Noncompliant", STUB),
    spec("UnsafeDeserialization", Type.VULNERABILITY, "CRITICAL", true, "deserialization", "Request data should not be deserialized with pickle or unsafe YAML",
      "Request data or uploaded files given to pickle.loads, yaml.load without a safe loader, marshal or jsonpickle let a caller run code on the server. Use JSON or yaml.safe_load.",
      "def restore(request):\n    state = pickle.loads(request.body)  # Noncompliant", STUB),
    spec("EndpointWithoutAuth", Type.VULNERABILITY, "MAJOR", true, null, "Endpoints that change data should check the caller",
      "A POST, PUT, PATCH or DELETE endpoint (or a Django view that writes) with no authentication: no auth dependency on the FastAPI route, router or app; no login_required, permission classes (DRF defaults included) or auth mixin on the Django view; no login_required or before_request guard on the Flask route. Apps without any authentication are skipped.",
      "@router.delete(\"/items/{item_id}\")\ndef delete_item(item_id: int, db: Session = Depends(get_db)):  # Noncompliant", STUB),
    spec("CsrfExemptMutation", Type.VULNERABILITY, "MAJOR", true, null, "Views that change data with cookie authentication should not be CSRF exempt",
      "@csrf_exempt on a Django view that changes data for a user authenticated by a session cookie lets any site make the user's browser call it.",
      "@csrf_exempt\n@login_required\ndef transfer(request):  # Noncompliant\n    Account.objects.filter(owner=request.user).update(balance=0)", STUB),
    spec("BlockingCallInAsync", Type.BUG, "MAJOR", true, null, "Async endpoints should not make blocking calls",
      "requests, time.sleep, blocking file IO, synchronous database drivers or the Django ORM inside an async def endpoint (or what it calls) block the event loop: every other request waits.",
      "@app.get(\"/rate\")\nasync def rate():\n    return requests.get(RATES_URL).json()  # Noncompliant", STUB),
    spec("MissingAwait", Type.BUG, "CRITICAL", true, null, "Coroutines should be awaited",
      "Calling an async function without await in async code creates a coroutine that never runs: the work silently does not happen.",
      "async def save(item):\n    db.commit_async()  # Noncompliant", STUB),
    spec("MutableDefaultInModel", Type.BUG, "MAJOR", true, null, "Model fields and endpoint parameters should not default to a shared mutable value",
      "A [] or {} default that is one object for every instance or call: a mutable default argument of an endpoint, or a Pydantic or dataclass field default shared between instances. Use default_factory, Field(default_factory=...) or None.",
      "@app.route(\"/visit\")\ndef visit(seen={}):  # Noncompliant: the same dict for every request", STUB),
    spec("ResponseModelLeak", Type.VULNERABILITY, "MAJOR", false, null, "FastAPI endpoints should not return password or secret fields",
      "A FastAPI endpoint returning an ORM object or a dict with password, hash or secret fields and no response_model that leaves them out sends them to the client.",
      "@app.get(\"/users/{id}\")\ndef get_user(id: int):\n    return db.get(User, id)  # Noncompliant: User has hashed_password", STUB),
    spec("NPlusOneQuery", Type.CODE_SMELL, "MINOR", false, null, "Related objects should be fetched with the queryset",
      "Reading a related object inside a loop over a Django queryset without select_related or prefetch_related makes one query per row.",
      "for order in Order.objects.all():\n    print(order.customer.name)  # Noncompliant", STUB));

  /** The spec of a rule key, or null. */
  public static Spec spec(String key) {
    return ALL.stream().filter(s -> s.key().equals(key)).findFirst().orElse(null);
  }
}
