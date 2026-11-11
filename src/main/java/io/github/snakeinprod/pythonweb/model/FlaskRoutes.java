package io.github.snakeinprod.pythonweb.model;

import io.github.snakeinprod.pythonweb.lang.python.PyStatement;
import io.github.snakeinprod.pythonweb.parse.Chain;
import io.github.snakeinprod.pythonweb.parse.Chains;
import io.github.snakeinprod.pythonweb.parse.Node;
import io.github.snakeinprod.pythonweb.parse.Token;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Flask endpoints: {@code @app.route(rule, methods=[...])}, {@code @bp.get/post/...(rule)} and {@code
 * add_url_rule(rule, view_func=...)} on {@code Flask(...)} apps and {@code Blueprint(..., url_prefix=...)}, with the
 * prefixes of {@code register_blueprint} (nested blueprints included); project helpers given a blueprint and a {@code
 * view_func}; Flask-RESTful {@code api.add_resource(Resource, urls...)}. Auth: a decorator whose name says so, a view
 * class's {@code decorators}, a check in the body, or a {@code before_request} guard (of the blueprint, or {@code
 * before_app_request} / the app's for all) whose body checks the user and can stop the request.
 */
final class FlaskRoutes {

  private static final Set<String> VERBS = Set.of("route", "get", "post", "put", "patch", "delete");
  private static final java.util.regex.Pattern GUARD = java.util.regex.Pattern.compile("current_user|login|session\\[|session\\.get"
    + "|abort\\((401|403)|jwt|token|verify|g\\.user|is_authenticated|Unauthorized|Forbidden|api_key|authorization|Authorization");

  private static final java.util.regex.Pattern STOPS = java.util.regex.Pattern.compile("\\babort\\(|redirect\\(|\\braise\\b|"
    + "\\breturn\\s+(?!None\\b)\\S");

  /** A Flask app or Blueprint. */
  record Holder(Module module, String var, boolean app, String prefix) {
  }

  private final WebModel model;
  private final Map<String, Holder> holders = new LinkedHashMap<>();
  private final Map<String, Holder> apis = new LinkedHashMap<>();
  private final List<Object[]> resources = new ArrayList<>();
  private final Map<Holder, Holder> parents = new HashMap<>();
  private final Map<Holder, String> registeredPrefix = new HashMap<>();
  private final Map<Holder, List<Function>> guards = new HashMap<>();
  private final List<Function> appGuards = new ArrayList<>();

  private FlaskRoutes(WebModel model) {
    this.model = model;
  }

  static List<Endpoint> find(WebModel model) {
    return new FlaskRoutes(model).run();
  }

  /** An app factory: a project function whose body builds a {@code Flask(...)} app. */
  private static boolean makesApp(Function f) {
    if (f == null) {
      return false;
    }
    for (PyStatement s : f.body()) {
      for (PyStatement x : s.walk()) {
        for (Chain c : Chains.in(x.group())) {
          if (Exprs.firstCall(c) != null && f.module().resolve(Exprs.head(c)).equals("flask.Flask")) {
            return true;
          }
        }
      }
    }
    return false;
  }

  private List<Endpoint> run() {
    List<Module> flask = model.modules().stream().filter(m -> !m.isTest() && m.frameworks().contains(Framework.FLASK)).toList();
    for (Module m : flask) {
      for (PyStatement s : m.py().walk()) {
        List<List<Node>> parts = Exprs.assignment(s.nodes());
        Chain c = parts.size() == 2 && s.body().isEmpty() ? Exprs.chain(parts.get(1)) : null;
        String var = parts.size() == 2 ? Exprs.dotted(Exprs.unannotated(parts.get(0))) : null;
        Chain.Call call = c == null ? null : Exprs.firstCall(c);
        if (call == null || var == null || Exprs.headSize(c) + 1 != c.segments().size()) {
          continue;
        }
        String callee = m.resolve(Exprs.head(c));
        if (callee.equals("flask.Flask") || callee.equals("flask.Blueprint") || callee.equals("flask.blueprints.Blueprint")) {
          String prefix = Exprs.string(Exprs.arg(call, -1, "url_prefix"));
          holders.put(m.path() + "#" + var, new Holder(m, var, callee.equals("flask.Flask"), prefix == null ? "" : prefix));
        } else if (restApi(m, Exprs.head(c), callee)) {
          String prefix = Exprs.string(Exprs.arg(call, -1, "prefix"));
          apis.put(m.path() + "#" + var, new Holder(m, var, false, prefix == null ? "" : prefix));
        } else if (makesApp(model.function(m, Exprs.head(c)))) {
          // application = create_app()
          holders.put(m.path() + "#" + var, new Holder(m, var, true, ""));
        }
      }
    }
    List<Object[]> rules = new ArrayList<>();
    for (Module m : flask) {
      for (PyStatement s : m.py().walk()) {
        for (Chain c : Chains.in(s.group())) {
          Chain.Call call = Exprs.firstCall(c);
          String head = Exprs.head(c);
          if (call == null) {
            continue;
          }
          List<List<Node>> pos = Exprs.positional(call);
          Holder wrapped = pos.isEmpty() || !Exprs.kwargs(call).containsKey("view_func") ? null : holder(m, Exprs.dotted(pos.get(0)));
          if (wrapped != null && !head.endsWith("add_url_rule")) {
            // a project helper registering a view on a blueprint: register_view(bp, routes=[...], view_func=V.as_view(...))
            List<Node> routes = pos.size() > 1 ? pos.get(1) : Exprs.kwargs(call).getOrDefault("routes", Exprs.kwargs(call).get("rule"));
            List<String> paths = routes == null ? List.of() : Exprs.string(routes) != null ? List.of(Exprs.string(routes)) : Exprs.strings(routes);
            for (String path : paths) {
              rules.add(new Object[] {m, wrapped, call, path});
            }
            continue;
          }
          if (!head.contains(".")) {
            continue;
          }
          Holder api = lookup(apis, m, head.substring(0, head.lastIndexOf('.')));
          PyClass resource = api == null || pos.isEmpty() ? null : model.cls(m, Exprs.dotted(pos.get(0)));
          if (resource != null) {
            // Flask-RESTful: api.add_resource(Resource, "/url", ...), or a project method of the Api subclass
            for (List<Node> url : pos.subList(1, pos.size())) {
              String path = rule(url);
              if (path != null) {
                resources.add(new Object[] {api, resource, path});
              }
            }
            continue;
          }
          Holder h = holder(m, head.substring(0, head.lastIndexOf('.')));
          String last = head.substring(head.lastIndexOf('.') + 1);
          if (h == null) {
            continue;
          }
          if (last.equals("register_blueprint")) {
            List<Node> child = Exprs.arg(call, 0, "blueprint");
            String name = child == null ? null : Exprs.dotted(child);
            Holder bp = name == null ? null : holder(m, name);
            if (bp != null && bp != h) {
              parents.putIfAbsent(bp, h);
              String prefix = Exprs.string(Exprs.arg(call, -1, "url_prefix"));
              if (prefix != null) {
                registeredPrefix.putIfAbsent(bp, prefix);
              }
            }
          } else if (last.equals("before_request") || last.equals("before_app_request")) {
            List<Node> arg = Exprs.arg(call, 0, "f");
            String name = arg == null ? null : Exprs.dotted(arg);
            Function f = name == null ? null : function(m, name);
            if (f != null) {
              guard(h, last, f);
            }
          } else if (last.equals("add_url_rule")) {
            rules.add(new Object[] {m, h, call, rule(Exprs.arg(call, 0, "rule"))});
          }
        }
      }
    }
    List<Endpoint> out = new ArrayList<>();
    for (Module m : flask) {
      for (Function f : m.functions()) {
        for (Decorator d : f.decorators()) {
          Holder h = d.receiver().isEmpty() ? null : holder(m, d.receiver());
          if (h != null && (d.last().equals("before_request") || d.last().equals("before_app_request")) && d.call() == null) {
            guard(h, d.last(), f);
          }
        }
      }
    }
    for (Module m : flask) {
      for (Function f : m.functions()) {
        for (Decorator d : f.decorators()) {
          Holder h = d.receiver().isEmpty() ? null : holder(m, d.receiver());
          if (h != null && d.call() != null && VERBS.contains(d.last())) {
            List<String> methods = d.last().equals("route") ? methods(d.call()) : List.of(d.last().toUpperCase(Locale.ROOT));
            String rule = rule(Exprs.arg(d.call(), 0, "rule"));
            out.add(endpoint(h, f, null, rule, methods, f.token()));
          }
        }
      }
    }
    for (Object[] r : resources) {
      PyClass cls = (PyClass) r[1];
      for (String verb : List.of("get", "post", "put", "patch", "delete")) {
        Function f = model.method(cls, verb);
        if (f != null) {
          out.add(endpoint((Holder) r[0], f, cls, (String) r[2], List.of(verb.toUpperCase(Locale.ROOT)), f.token()));
        }
      }
    }
    for (Object[] r : rules) {
      Module m = (Module) r[0];
      Chain.Call call = (Chain.Call) r[2];
      String rule = (String) r[3];
      List<Node> view = Exprs.arg(call, 2, "view_func");
      Chain v = view == null ? null : Exprs.chain(view);
      if (v == null) {
        continue;
      }
      String head = Exprs.head(v);
      if (head.endsWith(".as_view")) {
        PyClass cls = model.cls(m, head.substring(0, head.length() - ".as_view".length()));
        if (cls != null) {
          for (String verb : List.of("get", "post", "put", "patch", "delete")) {
            Function f = model.method(cls, verb);
            if (f != null) {
              out.add(endpoint((Holder) r[1], f, cls, rule, List.of(verb.toUpperCase(Locale.ROOT)), f.token()));
            }
          }
        }
      } else {
        Function f = function(m, head);
        if (f != null) {
          out.add(endpoint((Holder) r[1], f, null, rule, methods(call), f.token()));
        }
      }
    }
    return out;
  }

  /** A before_request function that checks the user and can stop the request (one that only loads g.user does not). */
  private static boolean guards(Function g) {
    String body = AuthHints.bodyText(g);
    return GUARD.matcher(body).find() && STOPS.matcher(body).find();
  }

  private void guard(Holder h, String kind, Function f) {
    if (h.app() || kind.equals("before_app_request")) {
      appGuards.add(f);
    } else {
      guards.computeIfAbsent(h, k -> new ArrayList<>()).add(f);
    }
  }

  private Function function(Module m, String name) {
    Function f = model.function(m, name);
    if (f == null) {
      f = m.functions().stream().filter(x -> x.name().equals(name)).findFirst().orElse(null);
    }
    return f;
  }

  /** A rule literal, or the literal a helper wraps: {@code org_scoped_rule("/login")}. */
  private static String rule(List<Node> nodes) {
    String s = nodes == null ? null : Exprs.string(nodes);
    Chain c = s == null && nodes != null ? Exprs.chain(nodes) : null;
    Chain.Call call = c == null ? null : Exprs.firstCall(c);
    return call == null || Exprs.positional(call).isEmpty() ? s : Exprs.string(Exprs.positional(call).get(0));
  }

  private static List<String> methods(Chain.Call call) {
    List<String> out = new ArrayList<>();
    Exprs.strings(Exprs.arg(call, -1, "methods")).forEach(x -> out.add(x.toUpperCase(Locale.ROOT)));
    return out.isEmpty() ? List.of("GET") : List.copyOf(out);
  }

  /** A Flask-RESTful / Flask-RESTX Api, or a project subclass of one. */
  private boolean restApi(Module m, String head, String callee) {
    if (callee.matches("flask_rest(ful|x|plus)\\.Api")) {
      return true;
    }
    PyClass cls = model.cls(m, head);
    return cls != null && model.externalBases(cls).stream().anyMatch(b -> b.matches("flask_rest(ful|x|plus)\\.Api"));
  }

  private Holder holder(Module m, String name) {
    return lookup(holders, m, name);
  }

  private Holder lookup(Map<String, Holder> holders, Module m, String name) {
    Holder local = holders.get(m.path() + "#" + name);
    if (local != null) {
      return local;
    }
    WebModel.Ref r = model.locate(m, name);
    return r == null ? null : holders.get(r.module().path() + "#" + r.name());
  }

  private Endpoint endpoint(Holder h, Function f, PyClass cls, String rule, List<String> methods, Token token) {
    String path = rule == null ? "" : rule;
    String auth = null;
    for (Decorator d : f.decorators()) {
      if (AuthHints.DECORATOR.matcher(d.name()).find() || AuthHints.checkingDecorator(model, f.module(), d)) {
        // every check, with its arguments: "@login_required @roles_required("Admin")"
        String args = d.call() == null ? "" : Exprs.text(d.call().args().children());
        String one = "@" + d.name() + (args.isEmpty() ? "" : "(" + args + ")");
        auth = auth == null ? one : auth + " " + one;
      }
    }
    if (auth == null && cls != null) {
      // MethodView / Resource: decorators = [login_required, ...] (method_decorators too) on the class or a project base
      for (PyClass k : model.hierarchy(cls)) {
        List<List<Node>> items = new ArrayList<>();
        for (String attr : List.of("decorators", "method_decorators")) {
          List<Node> value = k.attributes().get(attr);
          if (value != null) {
            items.addAll(Exprs.items(value));
          }
        }
        for (List<Node> item : items) {
          Chain d = Exprs.chain(item);
          String name = d == null ? "" : Exprs.head(d);
          if (auth == null && AuthHints.DECORATOR.matcher(name).find()) {
            auth = "decorators = [" + name + "] on " + k.name();
          }
        }
      }
    }
    if (auth == null && AuthHints.BODY.matcher(AuthHints.bodyText(f)).find()) {
      auth = "checks the user in the body";
    }
    Set<Holder> seen = new HashSet<>();
    for (Holder cur = h; cur != null && seen.add(cur); cur = parents.get(cur)) {
      path = registeredPrefix.getOrDefault(cur, cur.prefix()) + path;
      for (Function g : guards.getOrDefault(cur, List.of())) {
        if (auth == null && guards(g)) {
          auth = "before_request " + g.name();
        }
      }
    }
    for (Function g : appGuards) {
      if (auth == null && guards(g)) {
        auth = "before_request " + g.name();
      }
    }
    return new Endpoint(Framework.FLASK, path.isEmpty() ? "/" : path, methods, f.module(), f, cls, token,
      f.label(), auth == null ? Endpoint.Auth.NONE : Endpoint.Auth.by(auth), f.isAsync(),
      AuthHints.writes(f));
  }
}
