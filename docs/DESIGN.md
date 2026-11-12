# Design

One plugin, key `pythonweb`, for SonarQube 10.12 and later (built against plugin API 14.2). It adds framework-aware
security and correctness rules for Django (Django REST framework included), FastAPI, Flask and aiohttp to SonarQube Community
Build, whose bundled Python analyzer has no taint analysis. It does not repeat the built-in Python rules (hard-coded
credentials, Django DEBUG, CSRF middleware disabled).

The core is a project model of the app (modules, functions, classes, endpoints) and an inter-procedural taint engine
over it. Rules are small checks on both.

## Flow

```
py files (model.Project: paths + read)
  -> WebModel.build: each file -> ParsedFile (PythonLexer -> tokens -> TreeBuilder -> PyModule statements)
     -> Module (functions, classes, module-level assignments, frameworks from imports)
     -> endpoints: FastApiRoutes, DjangoRoutes, FlaskRoutes, AiohttpRoutes
  -> TaintEngine.run: per-function summaries to a fixpoint, then findings (models/taint.json)
  -> sensor.Analyzer: every rule on every module -> issues with secondary locations
  -> PwMetrics.fileValues -> pw_* on files -> PwAggregator sums to directories and the project
  -> EndpointsJson -> pw_endpoints_json; PwMetrics.appJson -> pw_app_json (whole-app totals) on the project
```

`PythonWebSensor` (SonarQube), `cli.Scan` (command line) and the tests (`RuleVerifier`) all go through
`WebModel.build`, `TaintEngine.run` and `Analyzer`, so they see the same results. The sensor runs on py, builds the
model once and does nothing when no file imports django, rest_framework, fastapi, starlette, flask or the aiohttp server
(`aiohttp.web`, aiohttp_security, aiohttp_session; the aiohttp client alone does not count). The analyzer
runs every rule; the sensor saves the issues of the rules active in the quality profile. The issue counts in the
measures include inactive rules.

Test files (`test_*.py`, `*_test.py`, `conftest.py`, anything under `tests/` or `fixtures/`) are read but give no
framework, no endpoint, no summary and no issue.

## Parsing

No grammar and no external parser, as in the sibling plugins. `lang.python.PythonLexer` (Python 3.12: every string
prefix, f-strings with nested quotes, NEWLINE / INDENT / DEDENT) gives `Token`s; `parse.TreeBuilder` groups them by
brackets into a `Node` tree; `PyModule` splits the tree into `PyStatement`s (one logical line each, compound
statements with their body, decorators attached to their def or class) and reads the imports. `parse.Chains` finds
member and call chains (`request.GET.get("q")`, `os.path.join(a, b)`). The lexer never throws; a broken file still
gives statements.

## The model (package `model`)

| class | what |
|---|---|
| `Module` | one file: `path()`, `file()` (tokens, comments, tree, `py()` statements and imports), `functions()` (every def: module functions, methods, nested ones), `function(name)` (module level), `classes()`, `cls(name)`, `assignments()` / `assignment(name)` (module-level values, `+=` included), `frameworks()`, `resolve(dotted)` (through the imports), `functionAt(line)`, `isTest()` |
| `Function` | a def: `name()`, `label()` ("create" or "ItemViewSet.create"), `owner()` (class of a method), `parent()` (enclosing def), `params()` (`Param`: name, token, annotation and default nodes, stars), `param(name)`, `decorators()`, `isAsync()`, `body()`, `takesSelf()`, `firstLine()` / `lastLine()` |
| `PyClass` | a class: `bases()` as written, `resolvedBases()`, `decorators()`, `methods()`, `method(name)`, `attributes()` (class-body assignments such as `permission_classes`) |
| `Decorator` | `name()` as written ("app.get"), `resolved()` through imports, `receiver()`, `last()`, `call()` (arguments, or null) |
| `Endpoint` | `framework()`, `path()` (prefixes included), `methods()` (upper case; "ANY" for a Django view that does not restrict them), `function()` (null for a handler inherited from a framework class), `viewClass()`, `token()` (where to report), `label()`, `auth()`, `async()`, `writes()`, `mutating()` |
| `Endpoint.Auth` | `present()` and `evidence()`: what checks the caller ("Depends(get_current_user) on parameter user", "@login_required", "LoginRequiredMixin", "DEFAULT_PERMISSION_CLASSES [IsAuthenticated]", "before_request check_admin"), or what opens it explicitly ("permission_classes = [AllowAny]") |
| `Exprs` | readings of expressions: `chain(nodes)`, `head(chain)`, `firstCall`, `positional`, `kwargs`, `arg(call, index, name)`, `string(nodes)` (plain literals), `strings` (a list of literals), `dotted`, `text` |

`WebModel`: `modules()`, `module(path)`, `frameworks()`, `hasFramework()`, `endpoints()`, `endpointsOf(function)`,
`usesAuth()` (an auth package is imported or an endpoint checks the caller), and name resolution across modules:
`locate(module, dotted)` (the module and name a dotted name denotes; local definitions win, imports and
`__init__.py` re-exports followed; null for packages and builtins), `function(module, dotted)` (a module function, an
imported one or `Class.method`), `cls(module, dotted)`, `value(module, dotted)` (a module-level variable's value),
`moduleNamed(module, "blog.urls")`, `method(class, name)` and `hierarchy(class)` (project base classes followed),
`externalBases(class)` (the framework bases, resolved).

### Imports

`Imports.split(dotted, from, paths)`: the longest prefix that is a project module (`a/b.py`) or package
(`a/b/__init__.py`), and the rest. Relative imports start from the file's package; absolute ones from each directory
above the file (deepest first) and its `src/`, so a Django app beside manage.py and a src layout both resolve.

### Endpoints

- FastAPI: `FastAPI()` and `APIRouter(prefix=..., dependencies=[...])` objects (module level or in a factory; a
  project alias named `...Router` or a project subclass of APIRouter too),
  `@x.get/post/put/patch/delete/options/head/api_route(...)`, `include_router(router, prefix=..., dependencies=[...])`
  followed up to the app. Auth: a `Depends(...)` whose callable says auth by its name (get_current_user, oauth2_scheme,
  require_admin, current_session...), any `Security(...)`, a `fastapi.security` scheme, an `Annotated[..., Depends(...)]`
  alias, a project dependency that is defined in an auth module, reads a credential cookie or header, or itself
  depends on one of those, or a module-level instance (`_Write = Authenticator(...)`) of an auth-named class or defined
  in an auth module; on the route, a parameter, a router, an include or the app.
- Django: from every ROOT_URLCONF of the settings (several projects in one repository, a second urlconf set under an
  `if`; else every urlconf no other includes), `path` / `re_path` / `url` entries, `include()` of modules, inline lists,
  module-level pattern lists by name (`include((extra, "ns"))`, `i18n_patterns(*i18n_urls) + urls`, `+=`, `.append`,
  `.extend`, `urlpatterns = [...] + urlpatterns` under an `if`) and DRF routers; Django 1.x `patterns("", ...)`, tuple
  entries and string views (`"blog.views.index"`); views imported with `from .views import *`; then urlconfs that only
  a function includes (a hook returning `path("x/", include(urls))`). A project helper returning
  `path(route, dispatcher, handlers)` (`rest_path("users", GET=list_users, POST=create_user)`) gives one endpoint per
  method keyword. Function views (methods from `require_POST`, `require_http_methods`, `api_view`, else from
  `request.method` checks, else ANY), class-based views (one endpoint per handler method, one for what a generic base
  provides, one for a view that only has `dispatch`), ViewSets (one per action and per `@action`, `@list_route`,
  `@detail_route`). Auth: decorators (`login_required`, `permission_required`, `user_passes_test`,
  `permission_classes`...), a project decorator that tests the user or reads a credential and answers 401/403, or
  whose wrapper checks the caller (`@require_perm(P.EDIT)` testing `current_user`), wrappers in urls.py,
  `method_decorator`, auth mixins, `permission_classes` (AllowAny means open), DRF DEFAULT_PERMISSION_CLASSES,
  LoginRequiredMiddleware, checks of `request.user` in the body, a dispatcher that checks the user. View registries:
  a view class decorated by a project decorator whose name holds "register" (`@register_model_view(Site, "edit",
  path="x", detail=False)`), and a project function in `include(...)` that reads the same module-level registry
  (`include(get_model_urls("dcim", "site", detail=False))`, both subscripting `registry[...]`), give the class's
  endpoints under that prefix. A registration matches when the arguments both functions name alike are equal
  (defaults included) and every other string of the call is the registered model's class name in lower case or a
  directory of its module; the route is the decorator's `path`, else its `name`.
- Flask: `Flask()` apps (also `application = create_app()` with a project factory) and `Blueprint(url_prefix=...)`,
  `@x.route(rule, methods=[...])`, `@x.get/post/...`, `add_url_rule`, a project helper called with a blueprint and
  `view_func=` (`register_view(bp, routes=[...], view_func=V.as_view(...))`), `register_blueprint(url_prefix=...)`;
  `MethodView.as_view` gives one endpoint per verb method; a route decorator on an instance method (called without the
  instance) gives none. Flask-RESTful / RESTX: `Api()` (or a project subclass),
  `api.add_resource(Resource, "/url", ...)` and any project method of the subclass taking the resource first. A rule
  wrapped in a helper (`org_scoped_rule("/x")`) reads as its literal. Auth: decorators (`login_required`,
  `jwt_required`..., every one with its arguments: `@login_required @roles_required("Admin")`), project decorators
  that check the caller, a view class's `decorators` / `method_decorators`, checks in the body, `before_request`
  guards of the blueprint or the app whose body checks the user and can stop the request (abort, redirect, raise,
  return a response; a hook that only loads `g.user` is not one).
- aiohttp: `@routes.get/post/put/patch/delete/head/route/view(path)` of a `web.RouteTableDef()` (functions, and
  `web.View` classes for `view`), `x.router.add_get/add_post/.../add_route(method, path, h)/add_view(path, h)` on any
  receiver ending in "router", `web.get/post/.../route/view(path, h)` wherever they are built (in `app.add_routes([...])`
  or a list). The handler is a function (a nested one in the factory included), `self.method` of the registering class,
  or a class: one endpoint per verb method (all of them for "*" and views). A handler and path registered for several
  methods is one endpoint. An f-string path keeps its literal parts (`f"{base}/rooms/{{name}}"` gives "/rooms/{name}").
  Each registration is tied to the `web.Application()` it adds to (`AiohttpApps`): the receiver (`app`, `app.router`) is
  followed through assignments, `for` loops, imports, a factory that returns the app (`app.add_subapp("/api",
  make_api())`) and parameters (to what every caller passes: `setup_routes(app)`, `handler.register(app)` with
  `handler = Handler(...)`, only calls on an instance of the method's class when the type is known), not through
  `self.app`. `parent.add_subapp(prefix, child)` prefixes the child's routes, nested sub-apps joined, the trailing
  slash dropped as aiohttp does ("/api/v1" + "/secrets" + "/{key}"). A RouteTableDef is an endpoint only once some
  `x.add_routes(table)` (or `x.router.add_routes`) adds it, with the prefixes of that app; one added only in a test
  counts without a prefix; an argument that cannot be followed (`webapp.add_routes(method.routes)` over a registry)
  stands for every table of that name. Routes a registry builds at run time (`app.router.add_route(*r)` over a list)
  are not followed. Auth: an auth decorator or a project
  decorator that checks the caller, aiohttp_security `check_authorized` / `check_permission(s)` / `permits` in the
  handler, `authorized_userid` with an `HTTPUnauthorized` or a redirect to a login page, an aiohttp_session login
  check (`get_session` read, then `HTTPUnauthorized` or a redirect to a login page), a user test; the same in a helper
  the handler calls (two calls deep), or a helper that reads a credential and refuses with 401 / 403; else an auth
  middleware (`web.Application(middlewares=[...])`, `app.middlewares.append(...)`) whose code checks the caller,
  registered on the route's app or an app it is mounted in, since aiohttp runs a parent's middlewares for its sub-apps'
  routes (`AiohttpApps.lineage`); not on a sibling sub-app or an unrelated app. A middleware on an app that cannot be
  followed (`self.app.middlewares`), or any auth middleware for a route whose app cannot be followed, counts for every
  aiohttp endpoint. A middleware that skips paths (`if request.path in PUBLIC`) counts like any other. A handler
  defined inside several factories is the one of the factory that registers it.

## The taint engine (package `taint`)

`TaintEngine.run(model, TaintModels.defaults())` gives a `TaintResult`: `findings()`, `findings(kind)`,
`findingsIn(module)` (sinks in that module), `summary(function)`.

Sources: request objects (a parameter named request or typed Request / HttpRequest, `self.request` in methods,
`flask.request`) read through the `requestAttributes` of the models (GET, POST, body, FILES, COOKIES, META, headers,
data, query_params, json, form, args, values, files, get_json, path, aiohttp query, match_info, post, text...;
`request.rel_url.query` too; not request.url or get_full_path(), which
come percent-encoded); FastAPI endpoint parameters that are not dependencies, requests or responses (query, path and
body parameters, Pydantic models, UploadFile); Django and Flask URL parameters not declared int, float, uuid or slug,
nor matched by a digits-only regex group (`(\d+)`, `(?P<pk>[0-9]+)`).

Propagation inside a function: assignments (tuple targets, `x.attr`, `d[k] = v` stores into `d`), augmented
assignments, f-strings (each field parsed), `%`, `+`, `" ".join(...)`, `.format(...)`, containers and comprehensions,
attribute, index and method reads on a tainted value (except the `cleanMethods` such as isdigit), mutating calls
(`parts.append(x)` taints `parts`; `f.write(x)` taints the buffer's content, not a path), `with ... as x`,
`for x in ...`. Comparisons, `not`, lambdas and unknown calls
give clean values; `propagators` (str, os.path.join, json.loads, pathlib.Path...) pass their arguments through.
Branches of `if` and `try` are analysed apart and joined (a branch ending in return or raise does not reach the code
after the `if`); loop bodies run twice. A URL whose start the server fixes clears the URL kinds (ssrf, redirect): a
literal start (`"https://api.example/"`, `"/items/"`), or server values before a literal starting with "/", "?" or "#"
(`protocol + settings.HOST + "/live/" + name`), or a server value named for a URL base (`upload_root_url() + path`).

Inter-procedural: each project function gets a `Summary` with `returns()` (parameter index to the flow reaching the
return value), `returnSources()` (request inputs it returns itself) and `sinks()` (`ParamSink`: parameter, sink kind,
path to the sink). Calls of module functions, imported functions, `self.method()` and `Class.method()` use the
callee's summary, and so do methods of a module-level instance (`dao = Dao()`, then `dao.query(sql)`), of a local
instance (`repo = Repo()`, then `repo.find(x)`) and of one built in the same chain (`Repo().find(x)`); a constructor call
uses `__init__`'s summary (capitalised class names only). Request data a method stores on `self` (`self.url = request.GET["url"]`
in `__init__`, `setup` or `dispatch`, also `self.x += ...`, `self.items.append(...)`, `self.d[k] = ...`) is kept per
class and attribute and seeds `self.url` in every method of that class, its project base classes and its subclasses;
only request inputs are kept, not the method's parameters, so an attribute assigned from settings or constants stays
clean. Summaries and these attributes are recomputed over all functions until none changes or 8 rounds (the depth
bound); a last pass records the findings. A finding read in a method no one calls (`setup`, `dispatch`) takes the
endpoint of its view class.

Constructor arguments: what `__init__` stores on `self` from its parameters (`self.url = url`, also through
`super().__init__(url)` and `Base.__init__(self, url)`; a `@dataclass` or attrs class's fields, bases' first, with attrs
dropping a leading underscore from the parameter name) is kept per class as attribute to parameter. In a method of that
class, its bases or subclasses, such an attribute is a pseudo parameter of the summary (index `TaintEngine.ATTR` + an id
per attribute name), so `self.url` reaching a sink or the return value is recorded like a parameter. At
`client = Client(request.GET["u"])` the arguments are mapped onto those parameters and give `client.url`; a call
`client.fetch()` (or `Client(u).fetch()`, or `self.fetch()` inside the class) passes the receiver's attributes as the
pseudo parameters. Only the arguments' own taint is carried, so `Client(settings.API_URL)` stays clean. An instance
stored on another object (`self.client = Client(u)`) is followed within that method only; one returned by a factory
or held in a container is not.

Sanitizers clear a value for some sink kinds (`int` for all, `shlex.quote` for command, `os.path.basename` for path,
`html.escape` for template...). Guards clear a variable for the rest of the function when a condition checks it:
`url_has_allowed_host_and_scheme(url)` (redirect), `p.startswith(base)` (path), `x in ALLOWED` (all kinds),
`re.match(...)` (all kinds), and a lookup in a constant or configured map tested afterwards
(`port = app.config["PROXY"].get(host)`, then `if not port:`) for the key (all kinds). A project validation helper (`validate_*`, `is_valid*`, `is_safe*`, `sanitize*`,
`verify_*`, `assert_*`, `ensure_*`) called on a value, in a condition or as a statement (`err = verify_name(name)`),
clears it for all kinds; one named for cleaning a path (`clean_path`, `safe_filename`) clears its result for path.
`request.args.get("page", type=int)` (also float and bool), `hexdigest()`, `digest()` and an upload's `temporary_file_path()` give clean values.

`Finding`: `kind()` (sql, command, path, ssrf, redirect, template, deserialization), `sinkName()` (the call as
written), `label()` (the input: "request.GET", "parameter q"), `source()`, `sink()`, `path()` (every `Step` from the
source to the sink, each with its module, token and message: "request.GET read here", "assigned to q", "passed to
build()", "returned by build()", "reaches cursor.execute()"), `function()` (where the input is read), `endpoint()`
(that function's endpoint, else the nearest endpoint among its callers; null when none), `where()` ("POST /items").

### Models

`src/main/resources/models/taint.json`: `sources`, `sinks` (kind, call, args with -1 for the receiver, kwargs, `when`
and `unless` keyword values: `shell=True` for subprocess, a safe `Loader` for yaml.load), `sanitizers` and `guards`
(call and the kinds they clear), `propagators`, `mutators`, `cleanMethods`. A call pattern is a resolved dotted name
("subprocess.run", through imports and constructor types: `client = httpx.AsyncClient()` makes `client.get`
"httpx.AsyncClient.get"), or `*.name` for a method of that name on any receiver; `a.b.c|d` is a.b.c and a.b.d. New
sinks and sanitizers go there, not in rules.

Django `HttpResponse` (and its 400 / 403 / 404 / 500 subclasses) is a template sink there; UnsafeTemplate reports it
only when the content is a string written in the call (literal, f-string, `+`, `%`, `.format`) whose literal part holds
an HTML tag, and the response has no `content_type` or one naming html, the way it reads a string a Flask view
returns. It skips template findings whose input is a URL parameter that cannot hold markup (`TaintChecks.markupFreePathParam`:
a converter other than str and path, a regex group of letters, digits and spaces, a Django view argument no route
passes).

## Writing a rule

A rule is a class in `rules/` implementing `PwRule`, registered in `RuleCatalog` (key, type, severity, active in the
"Python Web" profile, sink kind for a taint rule, name, description, example, factory; a longer description can go
in `src/main/resources/rules/<Key>.html`). The catalog has every rule; those not written yet use a stub that reports
nothing.

```java
public class TaintedSql implements PwRule {
  @Override
  public void check(RuleContext ctx) {
    for (Finding f : ctx.taint().findingsIn(ctx.module())) {
      if (f.kind().equals("sql")) {
        ctx.report(f, "Pass " + f.label() + " of " + f.where() + " as a query parameter.");
      }
    }
  }
}
```

- `check` runs once per non-test module; the rule picks what it checks there.
- `ctx.module()`, `ctx.model()` (endpoints, name resolution), `ctx.taint()` (findings), `ctx.file()`.
- `ctx.report(token, message)`, `ctx.report(from, to, message, secondaries)` (secondary locations are `Step`s, in
  any module), or `ctx.report(finding, message)`: at the sink, the rest of the path as secondary locations. The sink
  must be in the checked module (`findingsIn` gives those). A line with a NOSONAR comment gets no issue. The analyzer
  keeps one issue per rule and place: a sink reached from two inputs or two endpoints is one issue; a rule should test
  every finding of its kind, so that one input it trusts does not hide another.
- Messages name the endpoint (`finding.where()`, `endpoint.path()`) and say what to do, in one sentence.
- One rule instance per analysis: a rule may cache what it computes from the model in its fields.

### Fixtures

`src/test/resources/fixtures/<Key>.py` (one file) or a directory `fixtures/<Key>/` holding a small app. A comment
`# Noncompliant` marks a line that must get one issue, `# Noncompliant 2` two, `# Noncompliant {{text}}` checks the
message, `[[n]]` after it the number of secondary locations; every other line must stay silent. A test calls
`RuleVerifier.verify("<Key>")`. `RuleVerifierTest` shows a token rule, a model rule and a taint rule.

### Quality bar

An issue must be a real defect in at least 9 of 10 cases on real public apps (`cli.Scan <dir> --endpoints
--findings` runs everything on a directory without SonarQube). When a pattern is ambiguous, stay silent.

## Measures

On files: pw_endpoints, pw_mutating_endpoints, pw_async_endpoints (from the model), pw_unprotected_endpoints (the
endpoints EndpointWithoutAuth reports: an issue of that rule on the handler; several endpoints of one handler or class
share one issue), pw_blocking_calls (issues of BlockingCallInAsync), pw_taint_findings (issues of the rules
with a sink kind); `PwAggregator` sums them. pw_endpoints_json, on the project: one object per endpoint with `path`,
`methods`, `framework` (django, drf, fastapi, flask, aiohttp), `function`, `file`, `line`, `auth` (the evidence or null),
`protected`, `unprotected`, `async`, `mutating`, `issues` (within the handler's lines). pw_app_json: the file measures summed over
every file, for pull requests, where SonarQube keeps only the changed files' measures.

## Page

`static/pythonweb.js`, registered as `pythonweb/pythonweb`. SonarQube mounts extension pages in a two-column grid:
the page sets `options.el.style.gridColumn = '1 / -1'` and `width = '100%'`, and uses no CSS container queries.
Plain DOM, charts as inline SVG built with `createElementNS`, no innerHTML with data, light and dark themes, on the
branch or pull request being viewed. Tiles (endpoints, endpoints without auth, taint findings, blocking calls), the
endpoint route tree from pw_endpoints_json (one row per path segment, chains without endpoints collapsed, method badges,
async and "no auth" tags, a dot coloured by issues, the handler), the framework split with mutating, without auth and
async counts, and open issues by rule coloured by rule type. On a pull request the tiles read the totals of
pw_app_json. "Without auth" (the tile, the column and the tree tag) is one set: the endpoints with the `unprotected`
flag, which pw_unprotected_endpoints counts (`PwMetrics.unprotected`).

## Conventions

- Java 21, gson is the only (shaded) dependency, no reflection, no network.
- One-line commit messages, author `snake-in-prod`.
- Public repository: generic names only.
