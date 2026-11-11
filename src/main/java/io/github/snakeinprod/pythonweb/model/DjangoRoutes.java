package io.github.snakeinprod.pythonweb.model;

import io.github.snakeinprod.pythonweb.lang.python.PyStatement;
import io.github.snakeinprod.pythonweb.parse.Chain;
import io.github.snakeinprod.pythonweb.parse.Chains;
import io.github.snakeinprod.pythonweb.parse.Node;
import io.github.snakeinprod.pythonweb.parse.Nodes;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Django and Django REST framework endpoints, walked from the root urlconf (ROOT_URLCONF, else every urlconf no
 * other includes): {@code path} / {@code re_path} / {@code url} entries of {@code urlpatterns} (and {@code +=}),
 * {@code include("app.urls")}, inline lists and DRF routers ({@code router.register(...)}, {@code include(router.urls)},
 * {@code urlpatterns += router.urls}). Views: functions, class-based views ({@code as_view()}) with one endpoint per
 * handler method and one for the methods a generic base provides, ViewSets with one endpoint per action and per
 * {@code @action}.
 */
final class DjangoRoutes {

  private static final List<String> HANDLERS = List.of("get", "post", "put", "patch", "delete");

  /** ViewSet actions: method and whether the path has the {pk} part. */
  private static final Map<String, String[]> ACTIONS = new LinkedHashMap<>();

  static {
    ACTIONS.put("list", new String[] {"GET", ""});
    ACTIONS.put("create", new String[] {"POST", ""});
    ACTIONS.put("retrieve", new String[] {"GET", "{pk}/"});
    ACTIONS.put("update", new String[] {"PUT", "{pk}/"});
    ACTIONS.put("partial_update", new String[] {"PATCH", "{pk}/"});
    ACTIONS.put("destroy", new String[] {"DELETE", "{pk}/"});
  }

  /** Actions or HTTP methods a framework base class gives, by its last name. */
  private static final Map<String, List<String>> PROVIDED = Map.ofEntries(
    Map.entry("ModelViewSet", List.of("list", "create", "retrieve", "update", "partial_update", "destroy")),
    Map.entry("ReadOnlyModelViewSet", List.of("list", "retrieve")),
    Map.entry("ListModelMixin", List.of("list")), Map.entry("CreateModelMixin", List.of("create")),
    Map.entry("RetrieveModelMixin", List.of("retrieve")), Map.entry("UpdateModelMixin", List.of("update", "partial_update")),
    Map.entry("DestroyModelMixin", List.of("destroy")),
    Map.entry("CreateView", List.of("GET", "POST")), Map.entry("UpdateView", List.of("GET", "POST")),
    Map.entry("DeleteView", List.of("GET", "POST")), Map.entry("FormView", List.of("GET", "POST")),
    Map.entry("ListView", List.of("GET")), Map.entry("DetailView", List.of("GET")), Map.entry("TemplateView", List.of("GET")),
    Map.entry("RedirectView", List.of("GET")),
    Map.entry("CreateAPIView", List.of("POST")), Map.entry("ListAPIView", List.of("GET")),
    Map.entry("RetrieveAPIView", List.of("GET")), Map.entry("DestroyAPIView", List.of("DELETE")),
    Map.entry("UpdateAPIView", List.of("PUT", "PATCH")), Map.entry("ListCreateAPIView", List.of("GET", "POST")),
    Map.entry("RetrieveUpdateAPIView", List.of("GET", "PUT", "PATCH")), Map.entry("RetrieveDestroyAPIView", List.of("GET", "DELETE")),
    Map.entry("RetrieveUpdateDestroyAPIView", List.of("GET", "PUT", "PATCH", "DELETE")));

  private static final Pattern METHOD_CHECK = Pattern.compile("request\\.method(?:==|!=| in| not in)[(\\[{]?((?:[\"'][A-Za-z]+[\"'],?)+)");

  private final WebModel model;
  private final List<Endpoint> out = new ArrayList<>();
  private Endpoint.Auth drfDefault = Endpoint.Auth.NONE;
  private boolean loginMiddleware;

  private DjangoRoutes(WebModel model) {
    this.model = model;
  }

  static List<Endpoint> find(WebModel model) {
    return new DjangoRoutes(model).run();
  }

  private List<Endpoint> run() {
    List<Module> django = model.modules().stream().filter(m -> !m.isTest()).toList();
    String root = null;
    Module rootFrom = null;
    for (Module m : django) {
      String conf = Exprs.string(m.assignment("ROOT_URLCONF"));
      if (conf != null && root == null) {
        root = conf;
        rootFrom = m;
      }
      List<Node> rest = m.assignment("REST_FRAMEWORK");
      if (rest != null) {
        drfDefault = drfDefault(rest);
      }
      List<Node> middleware = m.assignment("MIDDLEWARE");
      loginMiddleware |= middleware != null && Exprs.text(middleware).contains("LoginRequiredMiddleware");
    }
    List<Module> urlconfs = django.stream().filter(m -> m.assignments().containsKey("urlpatterns")).toList();
    List<Module> roots = new ArrayList<>();
    Module rootModule = root == null ? null : model.moduleNamed(rootFrom, root);
    if (rootModule != null && urlconfs.contains(rootModule)) {
      roots.add(rootModule);
    } else {
      Set<Module> included = new HashSet<>();
      for (Module m : urlconfs) {
        for (List<Node> v : m.assignments().get("urlpatterns")) {
          for (Chain c : Chains.in(new Node.Group(null, null, v))) {
            if (c.lastName().equals("include") && Exprs.firstCall(c) != null) {
              Module t = includedModule(m, Exprs.arg(Exprs.firstCall(c), 0, null));
              if (t != null && t != m) {
                included.add(t);
              }
            }
          }
        }
      }
      urlconfs.stream().filter(m -> !included.contains(m)).forEach(roots::add);
    }
    for (Module r : roots) {
      urlconf(r, "", null, new HashSet<>());
    }
    return out;
  }

  private void urlconf(Module m, String prefix, String wrapper, Set<Module> visiting) {
    if (!visiting.add(m) || visiting.size() > 20) {
      return;
    }
    for (List<Node> v : m.assignments().getOrDefault("urlpatterns", List.of())) {
      patterns(m, v, prefix, wrapper, visiting);
    }
    visiting.remove(m);
  }

  /** A urlpatterns value: a list, a sum of lists, {@code router.urls}, {@code format_suffix_patterns([...])}. */
  private void patterns(Module m, List<Node> value, String prefix, String wrapper, Set<Module> visiting) {
    for (List<Node> part : Nodes.split(value, "+")) {
      if (part.size() == 1 && part.get(0) instanceof Node.Group g && (g.is("[") || g.is("("))) {
        for (List<Node> item : g.items()) {
          entry(m, item, prefix, wrapper, visiting);
        }
        continue;
      }
      Chain c = Exprs.chain(part);
      if (c == null) {
        continue;
      }
      if (c.lastName().equals("urls") && !c.endsWithCall()) {
        router(m, Exprs.head(c), prefix, wrapper);
      } else if (Exprs.firstCall(c) != null && !Set.of("path", "re_path", "url").contains(c.lastName())) {
        for (List<Node> arg : Exprs.positional(Exprs.firstCall(c))) {
          patterns(m, arg, prefix, wrapper, visiting);
        }
      }
    }
  }

  /** One {@code path(route, view, ...)} item. */
  private void entry(Module m, List<Node> item, String prefix, String wrapper, Set<Module> visiting) {
    Chain c = Exprs.chain(item);
    Chain.Call call = c == null ? null : Exprs.firstCall(c);
    if (call == null || !Set.of("path", "re_path", "url").contains(c.lastName())) {
      if (c != null && c.lastName().equals("urls") && !c.endsWithCall()) {
        router(m, Exprs.head(c), prefix, wrapper);
      }
      return;
    }
    String route = Exprs.string(Exprs.arg(call, 0, "route"));
    List<Node> view = Exprs.arg(call, 1, "view");
    if (view != null) {
      view(m, view, prefix + clean(route == null ? "" : route), wrapper, visiting);
    }
  }

  private void view(Module m, List<Node> view, String path, String wrapper, Set<Module> visiting) {
    Chain v = Exprs.chain(view);
    if (v == null) {
      return;
    }
    String head = Exprs.head(v);
    List<Chain.Call> calls = v.calls();
    if (v.lastName().equals("include") && Exprs.firstCall(v) != null) {
      List<Node> arg = Exprs.arg(Exprs.firstCall(v), 0, null);
      Chain a = arg == null ? null : Exprs.chain(arg);
      if (arg != null && arg.size() == 1 && arg.get(0) instanceof Node.Group g && g.is("[")) {
        patterns(m, arg, path, wrapper, visiting);
      } else if (a != null && a.lastName().equals("urls") && !a.endsWithCall()) {
        router(m, Exprs.head(a), path, wrapper);
      } else {
        Module t = includedModule(m, arg);
        if (t != null) {
          urlconf(t, path, wrapper, visiting);
        }
      }
      return;
    }
    if (v.lastName().equals("as_view")) {
      PyClass cls = model.cls(m, head.endsWith(".as_view") ? head.substring(0, head.length() - ".as_view".length()) : head);
      if (cls != null) {
        classView(cls, path, wrapper, Exprs.firstCall(v));
      }
      return;
    }
    if (!calls.isEmpty() && v.endsWithCall()) {
      // login_required(views.f), csrf_exempt(View.as_view()), permission_required("x")(views.f)
      Chain.Call last = calls.get(calls.size() - 1);
      List<Node> inner = Exprs.arg(last, 0, null);
      if (inner != null) {
        String w = AuthHints.DECORATOR.matcher(head).find() ? head + " in " + m.path() : wrapper;
        view(m, inner, path, w, visiting);
      }
      return;
    }
    Function f = model.function(m, head);
    if (f != null) {
      functionView(f, path, wrapper);
    }
  }

  private Module includedModule(Module m, List<Node> arg) {
    if (arg == null) {
      return null;
    }
    if (arg.size() == 1 && arg.get(0) instanceof Node.Group g && g.is("(") && !g.items().isEmpty()) {
      arg = g.items().get(0);
    }
    String s = Exprs.string(arg);
    if (s != null) {
      return model.moduleNamed(m, s);
    }
    String dotted = Exprs.dotted(arg);
    WebModel.Ref r = dotted == null ? null : model.locate(m, dotted);
    return r != null && r.name().isEmpty() ? r.module() : null;
  }

  /** {@code include(router.urls)}: every {@code router.register(prefix, ViewSet)} of that router. */
  private void router(Module m, String routerName, String path, String wrapper) {
    WebModel.Ref r = model.locate(m, routerName.substring(0, routerName.length() - ".urls".length()));
    if (r == null) {
      return;
    }
    for (PyStatement s : r.module().py().walk()) {
      for (Chain c : Chains.direct(s.group())) {
        if (Exprs.head(c).equals(r.name() + ".register") && Exprs.firstCall(c) != null) {
          Chain.Call call = Exprs.firstCall(c);
          String prefix = Exprs.string(Exprs.arg(call, 0, "prefix"));
          List<Node> vs = Exprs.arg(call, 1, "viewset");
          String vsName = vs == null ? null : Exprs.dotted(vs);
          PyClass cls = vsName == null ? null : model.cls(r.module(), vsName);
          if (cls != null && prefix != null) {
            String base = path + clean(prefix);
            viewSet(cls, base.isEmpty() || base.endsWith("/") ? base : base + "/", wrapper);
          }
        }
      }
    }
  }

  private void viewSet(PyClass cls, String base, String wrapper) {
    Set<String> provided = provided(cls);
    for (Map.Entry<String, String[]> a : ACTIONS.entrySet()) {
      Function f = model.method(cls, a.getKey());
      if (f != null || provided.contains(a.getKey())) {
        add(cls, f, List.of(a.getValue()[0]), base + a.getValue()[1], a.getKey(), wrapper);
      }
    }
    for (PyClass k : model.hierarchy(cls)) {
      for (Function f : k.methods()) {
        for (Decorator d : f.decorators()) {
          if (d.last().equals("action")) {
            boolean detail = d.call() != null && "True".equals(Exprs.text(orEmpty(Exprs.arg(d.call(), -1, "detail"))));
            String urlPath = d.call() == null ? null : Exprs.string(Exprs.arg(d.call(), -1, "url_path"));
            List<String> methods = new ArrayList<>();
            if (d.call() != null) {
              Exprs.strings(Exprs.arg(d.call(), -1, "methods")).forEach(x -> methods.add(x.toUpperCase(Locale.ROOT)));
            }
            if (methods.isEmpty()) {
              methods.add("GET");
            }
            add(cls, f, methods, base + (detail ? "{pk}/" : "") + (urlPath == null ? f.name() : urlPath) + "/", f.name(), wrapper);
          }
        }
      }
    }
  }

  private void classView(PyClass cls, String path, String wrapper, Chain.Call asView) {
    List<Node> mapping = asView == null ? null : Exprs.arg(asView, 0, "actions");
    if (mapping != null && mapping.size() == 1 && mapping.get(0) instanceof Node.Group g && g.is("{")) {
      // ViewSet.as_view({"get": "list", "post": "create"})
      for (List<Node> item : g.items()) {
        List<List<Node>> kv = Nodes.split(item, ":");
        String method = kv.size() == 2 ? Exprs.string(kv.get(0)) : null;
        String action = kv.size() == 2 ? Exprs.string(kv.get(1)) : null;
        if (method != null && action != null) {
          add(cls, model.method(cls, action), List.of(method.toUpperCase(Locale.ROOT)), path, action, wrapper);
        }
      }
      return;
    }
    Set<String> inherited = new LinkedHashSet<>();
    provided(cls).stream().filter(x -> x.equals(x.toUpperCase(Locale.ROOT))).forEach(inherited::add);
    for (String h : HANDLERS) {
      Function f = model.method(cls, h);
      if (f != null) {
        add(cls, f, List.of(h.toUpperCase(Locale.ROOT)), path, h, wrapper);
        inherited.remove(h.toUpperCase(Locale.ROOT));
      }
    }
    if (!inherited.isEmpty()) {
      add(cls, null, List.copyOf(inherited), path, null, wrapper);
    }
  }

  private Set<String> provided(PyClass cls) {
    Set<String> out = new LinkedHashSet<>();
    for (String b : model.externalBases(cls)) {
      out.addAll(PROVIDED.getOrDefault(b.substring(b.lastIndexOf('.') + 1), List.of()));
    }
    return out;
  }

  private void add(PyClass cls, Function f, List<String> methods, String path, String action, String wrapper) {
    boolean drf = isDrf(cls);
    Endpoint.Auth auth = classAuth(cls, f, drf, wrapper);
    String label = cls.name() + (action == null ? "" : "." + action);
    out.add(new Endpoint(drf ? Framework.DRF : Framework.DJANGO, "/" + path, methods, cls.module(), f, cls,
      f != null ? f.token() : cls.token(), label, auth, f != null && f.isAsync(), AuthHints.writes(f)));
  }

  private void functionView(Function f, String path, String wrapper) {
    List<String> methods = new ArrayList<>();
    boolean drf = false;
    for (Decorator d : f.decorators()) {
      switch (d.last()) {
        case "require_POST" -> methods.add("POST");
        case "require_GET", "require_safe" -> methods.add("GET");
        case "require_http_methods" -> {
          if (d.call() != null) {
            Exprs.strings(Exprs.arg(d.call(), 0, "request_method_list")).forEach(x -> methods.add(x.toUpperCase(Locale.ROOT)));
          }
        }
        case "api_view" -> {
          drf = true;
          if (d.call() != null) {
            Exprs.strings(Exprs.arg(d.call(), 0, "http_method_names")).forEach(x -> methods.add(x.toUpperCase(Locale.ROOT)));
          }
          if (methods.isEmpty()) {
            methods.add("GET");
          }
        }
        default -> {
        }
      }
    }
    if (methods.isEmpty()) {
      Matcher mm = METHOD_CHECK.matcher(AuthHints.bodyText(f));
      Set<String> found = new LinkedHashSet<>();
      while (mm.find()) {
        for (String s : mm.group(1).split(",")) {
          if (s.length() > 2) {
            found.add(s.substring(1, s.length() - 1).toUpperCase(Locale.ROOT));
          }
        }
      }
      if (!found.isEmpty()) {
        methods.add("GET");
        found.stream().filter(x -> !x.equals("GET")).forEach(methods::add);
      } else {
        methods.add("ANY");
      }
    }
    Endpoint.Auth auth = functionAuth(f, drf, wrapper);
    out.add(new Endpoint(drf ? Framework.DRF : Framework.DJANGO, "/" + path, List.copyOf(methods), f.module(), f, null, f.token(),
      f.label(), auth, f.isAsync(), AuthHints.writes(f)));
  }

  private Endpoint.Auth functionAuth(Function f, boolean drf, String wrapper) {
    Endpoint.Auth open = null;
    for (Decorator d : f.decorators()) {
      if (d.last().equals("login_not_required")) {
        return Endpoint.Auth.NONE;
      }
      if (AuthHints.DECORATOR.matcher(d.name()).find()) {
        return Endpoint.Auth.by("@" + d.name());
      }
      if (d.last().equals("permission_classes") && d.call() != null) {
        Endpoint.Auth a = permissionClasses(d.call().args().children());
        if (a.present()) {
          return a;
        }
        open = a;
      }
    }
    if (wrapper != null) {
      return Endpoint.Auth.by(wrapper);
    }
    if (AuthHints.BODY.matcher(AuthHints.bodyText(f)).find()) {
      return Endpoint.Auth.by("checks request.user in the body");
    }
    if (open != null) {
      return open;
    }
    if (loginMiddleware) {
      return Endpoint.Auth.by("LoginRequiredMiddleware");
    }
    return drf ? drfDefault : Endpoint.Auth.NONE;
  }

  private Endpoint.Auth classAuth(PyClass cls, Function handler, boolean drf, String wrapper) {
    if (handler != null) {
      for (Decorator d : handler.decorators()) {
        if (AuthHints.DECORATOR.matcher(d.name()).find() || d.last().equals("method_decorator") && d.call() != null
          && AuthHints.DECORATOR.matcher(Exprs.text(orEmpty(Exprs.arg(d.call(), 0, null)))).find()) {
          return Endpoint.Auth.by("@" + Exprs.text(d.statement().nodes().subList(1, d.statement().nodes().size())));
        }
      }
      if (AuthHints.BODY.matcher(AuthHints.bodyText(handler)).find()) {
        return Endpoint.Auth.by("checks request.user in the body");
      }
    }
    if (wrapper != null) {
      return Endpoint.Auth.by(wrapper);
    }
    Endpoint.Auth open = null;
    for (PyClass k : model.hierarchy(cls)) {
      for (Decorator d : k.decorators()) {
        if (d.last().equals("method_decorator") && d.call() != null
          && AuthHints.DECORATOR.matcher(Exprs.text(orEmpty(Exprs.arg(d.call(), 0, null)))).find()) {
          return Endpoint.Auth.by("@" + Exprs.text(d.statement().nodes().subList(1, d.statement().nodes().size())));
        }
      }
      for (String b : k.bases()) {
        if (AuthHints.MIXIN.matcher(b).find()) {
          return Endpoint.Auth.by(b);
        }
      }
      List<Node> perms = k.attributes().get("permission_classes");
      if (perms != null && open == null) {
        Endpoint.Auth a = permissionClasses(perms);
        if (a.present()) {
          return a;
        }
        open = a;
      }
      for (String m : List.of("get_permissions", "dispatch", "initial", "check_permissions")) {
        Function f = k.method(m);
        if (f != null && (m.equals("get_permissions") || AuthHints.BODY.matcher(AuthHints.bodyText(f)).find()
          || f.decorators().stream().anyMatch(d -> AuthHints.DECORATOR.matcher(d.name()).find() || d.last().equals("method_decorator")
            && d.call() != null && AuthHints.DECORATOR.matcher(Exprs.text(orEmpty(Exprs.arg(d.call(), 0, null)))).find()))) {
          return Endpoint.Auth.by(k.name() + "." + m);
        }
      }
    }
    if (open != null) {
      return open;
    }
    if (loginMiddleware) {
      return Endpoint.Auth.by("LoginRequiredMiddleware");
    }
    return drf ? drfDefault : Endpoint.Auth.NONE;
  }

  /** {@code [IsAuthenticated]}: auth; {@code [AllowAny]} or {@code []}: explicitly open. */
  private static Endpoint.Auth permissionClasses(List<Node> nodes) {
    String text = Exprs.text(nodes);
    List<String> names = new ArrayList<>();
    for (String s : text.replaceAll("[\\[\\]()\\s]", "").split(",")) {
      if (!s.isEmpty()) {
        names.add(s.substring(s.lastIndexOf('.') + 1));
      }
    }
    if (names.isEmpty() || names.stream().allMatch(n -> n.equals("AllowAny"))) {
      return new Endpoint.Auth(false, "permission_classes = " + text);
    }
    return Endpoint.Auth.by("permission_classes = " + text);
  }

  /** REST_FRAMEWORK["DEFAULT_PERMISSION_CLASSES"] of the settings. */
  private static Endpoint.Auth drfDefault(List<Node> settings) {
    if (settings.size() != 1 || !(settings.get(0) instanceof Node.Group g) || !g.is("{")) {
      return Endpoint.Auth.NONE;
    }
    for (List<Node> item : g.items()) {
      List<List<Node>> kv = Nodes.split(item, ":");
      if (kv.size() == 2 && "DEFAULT_PERMISSION_CLASSES".equals(Exprs.string(kv.get(0)))) {
        List<String> names = Exprs.strings(kv.get(1)).stream().map(s -> s.substring(s.lastIndexOf('.') + 1)).toList();
        if (!names.isEmpty() && !names.stream().allMatch(n -> n.equals("AllowAny"))) {
          return Endpoint.Auth.by("DEFAULT_PERMISSION_CLASSES " + names);
        }
        return new Endpoint.Auth(false, "DEFAULT_PERMISSION_CLASSES " + names);
      }
    }
    return Endpoint.Auth.NONE;
  }

  private boolean isDrf(PyClass cls) {
    return model.externalBases(cls).stream().anyMatch(b -> b.startsWith("rest_framework") || b.endsWith("APIView")
      || b.endsWith("ViewSet"));
  }

  /** A route part for display: re_path anchors removed. */
  private static String clean(String route) {
    String r = route.startsWith("^") ? route.substring(1) : route;
    return r.endsWith("$") ? r.substring(0, r.length() - 1) : r;
  }

  private static List<Node> orEmpty(List<Node> nodes) {
    return nodes == null ? List.of() : nodes;
  }
}
