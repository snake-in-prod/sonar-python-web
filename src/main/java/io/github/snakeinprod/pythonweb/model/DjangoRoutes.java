package io.github.snakeinprod.pythonweb.model;

import io.github.snakeinprod.pythonweb.lang.python.PyStatement;
import io.github.snakeinprod.pythonweb.parse.Chain;
import io.github.snakeinprod.pythonweb.parse.Chains;
import io.github.snakeinprod.pythonweb.parse.Node;
import io.github.snakeinprod.pythonweb.parse.Nodes;
import java.util.ArrayList;
import java.util.HashMap;
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
 * {@code @action}. View classes a register decorator files in a registry, expanded by a URL helper reading it.
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

  private static final Pattern SUBSCRIPT = Pattern.compile("\\b([A-Za-z_]\\w*)\\[");
  private static final Pattern METHOD_CHECK = Pattern.compile("request\\.method(?:==|!=| in| not in)[(\\[{]?((?:[\"'][A-Za-z]+[\"'],?)+)");

  private final WebModel model;
  private final List<Endpoint> out = new ArrayList<>();
  /** The list variables being walked, against urls = urls + more loops. */
  private Endpoint.Auth drfDefault = Endpoint.Auth.NONE;
  private boolean loginMiddleware;
  private final Set<String> expanding = new HashSet<>();
  private final Set<Module> reached = new HashSet<>();
  private List<Registration> registrations;

  private DjangoRoutes(WebModel model) {
    this.model = model;
  }

  static List<Endpoint> find(WebModel model) {
    return new DjangoRoutes(model).run();
  }

  private List<Endpoint> run() {
    List<Module> django = model.modules().stream().filter(m -> !m.isTest()).toList();
    List<Module> urlconfs = django.stream().filter(m -> m.assignments().containsKey("urlpatterns")).toList();
    Set<Module> roots = new LinkedHashSet<>();
    for (Module m : django) {
      // every ROOT_URLCONF the settings set, also one set again under an if (the main and a secondary server)
      for (PyStatement s : m.assignments().containsKey("ROOT_URLCONF") ? m.py().walk() : List.<PyStatement>of()) {
        List<List<Node>> parts = Exprs.assignment(s.nodes());
        String conf = parts.size() == 2 && "ROOT_URLCONF".equals(Exprs.dotted(Exprs.unannotated(parts.get(0)))) ? Exprs.string(parts.get(1)) : null;
        Module rootModule = conf == null ? null : model.moduleNamed(m, conf);
        if (rootModule != null && urlconfs.contains(rootModule)) {
          roots.add(rootModule);
        }
      }
      List<Node> rest = m.assignment("REST_FRAMEWORK");
      if (rest != null) {
        drfDefault = drfDefault(rest);
      }
      List<Node> middleware = m.assignment("MIDDLEWARE");
      loginMiddleware |= middleware != null && Exprs.text(middleware).contains("LoginRequiredMiddleware");
    }
    if (roots.isEmpty()) {
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
    hookedUrlconfs(django);
    return out;
  }

  /**
   * {@code path("redirects/", include(urls))} inside a function (a hook returning extra URLs, registered at run time):
   * each urlconf so included that the roots did not reach, from that prefix.
   */
  private void hookedUrlconfs(List<Module> django) {
    for (Module m : django) {
      if (!m.py().imports().containsValue("django.urls.include") && !m.py().imports().containsValue("django.conf.urls.include")) {
        continue;
      }
      for (Function f : m.functions()) {
        for (PyStatement s : f.body()) {
          for (PyStatement x : s.walk()) {
            for (Chain c : Chains.in(x.group())) {
              hookedEntry(m, c);
            }
          }
        }
      }
    }
  }

  private void hookedEntry(Module m, Chain c) {
    Chain.Call call = Exprs.firstCall(c);
    if (call == null || !Set.of("path", "re_path").contains(c.lastName())) {
      return;
    }
    List<Node> view = Exprs.arg(call, 1, "view");
    Chain v = view == null ? null : Exprs.chain(view);
    if (v != null && v.lastName().equals("include") && Exprs.firstCall(v) != null) {
      Module t = includedModule(m, Exprs.arg(Exprs.firstCall(v), 0, null));
      String route = Exprs.string(Exprs.arg(call, 0, "route"));
      if (t != null && reached.add(t)) {
        urlconf(t, clean(route == null ? "" : route), null, new HashSet<>());
      }
    }
  }

  private void urlconf(Module m, String prefix, String wrapper, Set<Module> visiting) {
    if (!visiting.add(m) || visiting.size() > 20) {
      return;
    }
    reached.add(m);
    variable(m, "urlpatterns", prefix, wrapper, visiting);
    visiting.remove(m);
  }

  /**
   * A module-level list of patterns: its assignments and {@code +=}, then {@code name.append(path(...))} and
   * {@code name.extend([...])} anywhere in the module.
   */
  private void variable(Module m, String name, String prefix, String wrapper, Set<Module> visiting) {
    String key = m.path() + "#" + name;
    if (!expanding.add(key)) {
      return;
    }
    for (List<Node> v : m.assignments().getOrDefault(name, List.of())) {
      patterns(m, v, prefix, wrapper, visiting);
    }
    for (PyStatement s : m.py().walk()) {
      for (Chain c : Chains.direct(s.group())) {
        String h = Exprs.head(c);
        Chain.Call call = Exprs.firstCall(c);
        List<Node> arg = call == null ? null : Exprs.arg(call, 0, null);
        if (arg != null && h.equals(name + ".append")) {
          entry(m, arg, prefix, wrapper, visiting);
        } else if (arg != null && h.equals(name + ".extend")) {
          patterns(m, arg, prefix, wrapper, visiting);
        }
      }
    }
    expanding.remove(key);
  }

  /** A name standing for a list of patterns ({@code include(_patterns)}, {@code urls + extra}); false when it is not one. */
  private boolean named(Module m, List<Node> nodes, String prefix, String wrapper, Set<Module> visiting) {
    String dotted = Exprs.dotted(nodes);
    WebModel.Ref r = dotted == null ? null : model.locate(m, dotted);
    if (r == null || r.name().isEmpty() || r.name().contains(".") || !r.module().assignments().containsKey(r.name())) {
      return false;
    }
    variable(r.module(), r.name(), prefix, wrapper, visiting);
    return true;
  }

  /** A urlpatterns value: a list, a sum of lists, {@code router.urls}, {@code format_suffix_patterns([...])}. */
  private void patterns(Module m, List<Node> value, String prefix, String wrapper, Set<Module> visiting) {
    for (List<Node> part : Nodes.split(value, "+")) {
      if (part.size() > 1 && Nodes.isLeaf(part.get(0), "*")) {
        part = part.subList(1, part.size());
      }
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
      if (c.lastName().equals("urls") && c.names().size() > 1 && !c.endsWithCall()) {
        router(m, Exprs.head(c), prefix, wrapper);
      } else if (Exprs.firstCall(c) != null && !Set.of("path", "re_path", "url").contains(c.lastName())) {
        // format_suffix_patterns([...]), i18n_patterns(*urls), and Django 1.x patterns("", url(...), (r"^x/", include(...)))
        for (List<Node> arg : Exprs.firstCall(c).args().items()) {
          if (arg.size() > 1 && Nodes.isLeaf(arg.get(0), "*")) {
            patterns(m, arg.subList(1, arg.size()), prefix, wrapper, visiting);
          }
        }
        for (List<Node> arg : Exprs.positional(Exprs.firstCall(c))) {
          Chain a = Exprs.chain(arg);
          if (a != null && Set.of("path", "re_path", "url").contains(a.lastName()) || arg.size() == 1 && arg.get(0) instanceof Node.Group g && g.is("(")) {
            entry(m, arg, prefix, wrapper, visiting);
          } else {
            patterns(m, arg, prefix, wrapper, visiting);
          }
        }
      } else if (Exprs.firstCall(c) == null) {
        named(m, part, prefix, wrapper, visiting);
      }
    }
  }

  /** One {@code path(route, view, ...)} item. */
  private void entry(Module m, List<Node> item, String prefix, String wrapper, Set<Module> visiting) {
    if (item.size() == 1 && item.get(0) instanceof Node.Group g && g.is("(") && g.items().size() >= 2) {
      // Django 1.x tuple entry: (r"^users/", include("users.urls"))
      String route = Exprs.string(g.items().get(0));
      view(m, g.items().get(1), prefix + clean(route == null ? "" : route), wrapper, visiting);
      return;
    }
    Chain c = Exprs.chain(item);
    Chain.Call call = c == null ? null : Exprs.firstCall(c);
    if (call == null || !Set.of("path", "re_path", "url").contains(c.lastName())) {
      if (c != null && c.lastName().equals("urls") && c.names().size() > 1 && !c.endsWithCall()) {
        router(m, Exprs.head(c), prefix, wrapper);
      } else if (call != null) {
        dispatched(m, c, call, prefix, wrapper);
      }
      return;
    }
    String route = Exprs.string(Exprs.arg(call, 0, "route"));
    List<Node> view = Exprs.arg(call, 1, "view");
    if (view != null) {
      view(m, view, prefix + clean(route == null ? "" : route), wrapper, visiting);
    }
  }

  /**
   * {@code rest_path("users", GET=list_users, POST=create_user)}: a project helper returning
   * {@code path(route, dispatcher, handlers)}, one endpoint per HTTP method keyword. The dispatcher checking the user
   * counts as the handlers' auth.
   */
  private void dispatched(Module m, Chain c, Chain.Call call, String prefix, String wrapper) {
    Map<String, List<Node>> kwargs = Exprs.kwargs(call);
    if (kwargs.keySet().stream().noneMatch(DjangoRoutes::methodKeyword)) {
      return;
    }
    Function helper = model.function(m, Exprs.head(c));
    Function dispatcher = null;
    for (PyStatement s : helper == null ? List.<PyStatement>of() : helper.body()) {
      for (PyStatement x : s.walk()) {
        for (Chain pc : Chains.in(x.group())) {
          List<Node> v = Set.of("path", "re_path").contains(pc.lastName()) && Exprs.firstCall(pc) != null
            ? Exprs.arg(Exprs.firstCall(pc), 1, "view") : null;
          String d = v == null ? null : Exprs.dotted(v);
          dispatcher = d == null ? dispatcher : model.function(helper.module(), d);
        }
      }
    }
    if (dispatcher == null) {
      return;
    }
    String route = Exprs.string(Exprs.arg(call, 0, "route"));
    String w = wrapper != null ? wrapper
      : AuthHints.checkingDecorator(dispatcher) ? "dispatched by " + dispatcher.name() + " in " + dispatcher.module().path() : null;
    for (Map.Entry<String, List<Node>> kw : kwargs.entrySet()) {
      if (!methodKeyword(kw.getKey())) {
        continue;
      }
      List<Node> v = kw.getValue();
      if (v.size() == 1 && v.get(0) instanceof Node.Group g && g.is("(") && !g.items().isEmpty()) {
        v = g.items().get(0); // (handler, {"tag"})
      }
      String d = Exprs.dotted(v);
      Function f = d == null ? null : model.function(m, d);
      if (f != null) {
        functionView(f, prefix + clean(route == null ? "" : route), w, List.of(kw.getKey()));
      }
    }
  }

  private static boolean methodKeyword(String k) {
    return HANDLERS.contains(k.toLowerCase(Locale.ROOT)) && k.equals(k.toUpperCase(Locale.ROOT));
  }

  private void view(Module m, List<Node> view, String path, String wrapper, Set<Module> visiting) {
    String named = Exprs.string(view);
    if (named != null && named.contains(".")) {
      // Django 1.x string view: "web.views.index"
      Module vm = model.moduleNamed(m, named.substring(0, named.lastIndexOf('.')));
      Function f = vm == null ? null : vm.function(named.substring(named.lastIndexOf('.') + 1));
      if (f != null) {
        functionView(f, path, wrapper, null);
      }
      return;
    }
    Chain v = Exprs.chain(view);
    if (v == null) {
      return;
    }
    String head = Exprs.head(v);
    List<Chain.Call> calls = v.calls();
    if (v.lastName().equals("include") && Exprs.firstCall(v) != null) {
      List<Node> arg = Exprs.arg(Exprs.firstCall(v), 0, null);
      if (arg != null && arg.size() == 1 && arg.get(0) instanceof Node.Group t && t.is("(") && !t.items().isEmpty()) {
        // include((patterns, "app_name"))
        arg = t.items().get(0);
      }
      Chain a = arg == null ? null : Exprs.chain(arg);
      if (arg != null && arg.size() == 1 && arg.get(0) instanceof Node.Group g && g.is("[")) {
        patterns(m, arg, path, wrapper, visiting);
      } else if (a != null && a.endsWithCall() && registered(m, a, path, wrapper)) {
        return;
      } else if (a != null && Exprs.head(a).endsWith(".urls") && !a.endsWithCall()) {
        router(m, Exprs.head(a), path, wrapper);
      } else {
        Module t = includedModule(m, arg);
        if (t != null) {
          urlconf(t, path, wrapper, visiting);
        } else if (arg != null) {
          named(m, arg, path, wrapper, visiting);
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
      functionView(f, path, wrapper, null);
    }
  }

  /**
   * A view class a project decorator files in a registry: {@code @register_model_view(Site, "edit", path="x")}, with
   * the lower-case names of the project classes it passes and the directories of their modules.
   */
  private record Registration(Function decorator, PyClass view, Map<String, List<Node>> args, Set<String> names, Set<String> dirs) {
  }

  private List<Registration> registrations() {
    if (registrations == null) {
      registrations = new ArrayList<>();
      for (Module m : model.modules()) {
        for (PyClass cls : m.isTest() ? List.<PyClass>of() : m.classes()) {
          for (Decorator d : cls.decorators()) {
            Function f = d.call() != null && d.last().toLowerCase(Locale.ROOT).contains("register") ? model.function(m, d.name()) : null;
            if (f != null && model.externalBases(cls).stream().anyMatch(b -> b.startsWith("django.views") || b.startsWith("rest_framework"))) {
              registrations.add(registration(f, cls, bind(f, d.call())));
            }
          }
        }
      }
    }
    return registrations;
  }

  /**
   * {@code include(get_model_urls("dcim", "site", detail=False))}: a project function that reads the registry a
   * register decorator fills gives the views registered for that key. A registration matches when the arguments both
   * functions name alike are equal (defaults included) and each other string names the registered model (its class
   * name in lower case) or a directory of the model's module (the app). The route is the decorator's {@code path},
   * else its {@code name}. False when nothing matches.
   */
  private boolean registered(Module m, Chain c, String prefix, String wrapper) {
    Function helper = model.function(m, Exprs.head(c));
    if (helper == null || Exprs.firstCall(c) == null) {
      return false;
    }
    Map<String, List<Node>> given = bind(helper, Exprs.firstCall(c));
    boolean any = false;
    Map<Function, Boolean> shared = new HashMap<>();
    for (Registration r : registrations()) {
      String route = registeredRoute(r);
      if (route != null && shared.computeIfAbsent(r.decorator(), d -> sharesRegistry(d, helper)) && matches(r, given)) {
        classView(r.view(), prefix + (route.isEmpty() ? "" : route + "/"), wrapper, null);
        any = true;
      }
    }
    return any;
  }

  private static String registeredRoute(Registration r) {
    String path = Exprs.string(r.args().get("path"));
    return path != null ? path : Exprs.string(r.args().get("name"));
  }

  private Registration registration(Function decorator, PyClass view, Map<String, List<Node>> args) {
    Set<String> names = new HashSet<>();
    Set<String> dirs = new HashSet<>();
    for (List<Node> v : args.values()) {
      String d = Exprs.dotted(v);
      PyClass k = d == null ? null : model.cls(view.module(), d);
      if (k != null && k != view) {
        names.add(k.name().toLowerCase(Locale.ROOT));
        String p = k.module().path();
        dirs.addAll(List.of(p.substring(0, Math.max(0, p.lastIndexOf('/'))).split("/")));
      }
    }
    return new Registration(decorator, view, args, names, dirs);
  }

  private static boolean matches(Registration r, Map<String, List<Node>> given) {
    Set<String> names = r.names();
    Set<String> dirs = r.dirs();
    boolean named = false;
    for (Map.Entry<String, List<Node>> e : given.entrySet()) {
      List<Node> mine = r.args().get(e.getKey());
      String s = Exprs.string(e.getValue());
      if (mine != null) {
        if (!Exprs.text(mine).equals(Exprs.text(e.getValue()))) {
          return false;
        }
      } else if (s == null || !names.contains(s) && !dirs.contains(s)) {
        return false;
      } else {
        named |= names.contains(s);
      }
    }
    return named;
  }

  /** Both functions read or write the same module-level subscripted name ({@code registry["views"]}). */
  private static boolean sharesRegistry(Function decorator, Function helper) {
    String helperText = AuthHints.bodyText(helper);
    Matcher mm = SUBSCRIPT.matcher(AuthHints.bodyText(decorator));
    while (mm.find()) {
      String n = mm.group(1);
      String resolved = decorator.module().resolve(n);
      boolean global = !resolved.equals(n) || decorator.module() == helper.module() && decorator.module().assignments().containsKey(n);
      if (global && helperText.contains(n + "[") && resolved.equals(helper.module().resolve(n))) {
        return true;
      }
    }
    return false;
  }

  /** Parameter name to the argument a call passes, else the parameter's default. */
  private static Map<String, List<Node>> bind(Function f, Chain.Call call) {
    Map<String, List<Node>> out = new LinkedHashMap<>();
    List<List<Node>> positional = Exprs.positional(call);
    Map<String, List<Node>> kwargs = Exprs.kwargs(call);
    List<Function.Param> params = f.params().stream().filter(p -> p.stars() == 0).toList();
    for (int i = 0; i < params.size(); i++) {
      Function.Param p = params.get(i);
      List<Node> v = kwargs.containsKey(p.name()) ? kwargs.get(p.name()) : i < positional.size() ? positional.get(i) : p.defaultValue();
      if (!v.isEmpty()) {
        out.put(p.name(), v);
      }
    }
    return out;
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
          // @action(detail=...), and the list_route / detail_route of DRF before 3.8
          if (d.last().equals("action") || d.last().equals("list_route") || d.last().equals("detail_route")) {
            boolean detail = d.last().equals("detail_route")
              || d.call() != null && "True".equals(Exprs.text(orEmpty(Exprs.arg(d.call(), -1, "detail"))));
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
    boolean handled = false;
    for (String h : HANDLERS) {
      Function f = model.method(cls, h);
      if (f != null) {
        handled = true;
        add(cls, f, List.of(h.toUpperCase(Locale.ROOT)), path, h, wrapper);
        inherited.remove(h.toUpperCase(Locale.ROOT));
      }
    }
    if (!inherited.isEmpty()) {
      add(cls, null, List.copyOf(inherited), path, null, wrapper);
    } else if (!handled) {
      // a view that does everything in its own dispatch()
      Function dispatch = model.method(cls, "dispatch");
      if (dispatch != null) {
        add(cls, dispatch, List.of("ANY"), path, "dispatch", wrapper);
      }
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

  private void functionView(Function f, String path, String wrapper, List<String> given) {
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
    if (given != null) {
      methods.clear();
      methods.addAll(given);
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
      if (AuthHints.DECORATOR.matcher(d.name()).find() || AuthHints.checkingDecorator(model, f.module(), d)) {
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
    for (Decorator d : f.decorators()) {
      if (AuthHints.checkingDecorator(model.function(f.module(), d.name()))) {
        return Endpoint.Auth.by("@" + d.name());
      }
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
