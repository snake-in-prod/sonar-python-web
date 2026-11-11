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
 * prefixes of {@code register_blueprint} (nested blueprints included). Auth: a decorator whose name says so, a check in
 * the body, or a {@code before_request} guard (of the blueprint, or {@code before_app_request} / the app's for all)
 * whose body checks the user.
 */
final class FlaskRoutes {

  private static final Set<String> VERBS = Set.of("route", "get", "post", "put", "patch", "delete");
  private static final java.util.regex.Pattern GUARD = java.util.regex.Pattern.compile("current_user|login|session\\[|session\\.get"
    + "|abort\\((401|403)|jwt|token|verify|g\\.user|is_authenticated|Unauthorized|Forbidden|api_key|authorization|Authorization");

  /** A Flask app or Blueprint. */
  record Holder(Module module, String var, boolean app, String prefix) {
  }

  private final WebModel model;
  private final Map<String, Holder> holders = new LinkedHashMap<>();
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
        }
      }
    }
    List<Object[]> rules = new ArrayList<>();
    for (Module m : flask) {
      for (PyStatement s : m.py().walk()) {
        for (Chain c : Chains.in(s.group())) {
          Chain.Call call = Exprs.firstCall(c);
          String head = Exprs.head(c);
          if (call == null || !head.contains(".")) {
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
            rules.add(new Object[] {m, h, call});
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
            String rule = Exprs.string(Exprs.arg(d.call(), 0, "rule"));
            out.add(endpoint(h, f, null, rule, methods, f.token()));
          }
        }
      }
    }
    for (Object[] r : rules) {
      Module m = (Module) r[0];
      Chain.Call call = (Chain.Call) r[2];
      String rule = Exprs.string(Exprs.arg(call, 0, "rule"));
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

  private static List<String> methods(Chain.Call call) {
    List<String> out = new ArrayList<>();
    Exprs.strings(Exprs.arg(call, -1, "methods")).forEach(x -> out.add(x.toUpperCase(Locale.ROOT)));
    return out.isEmpty() ? List.of("GET") : List.copyOf(out);
  }

  private Holder holder(Module m, String name) {
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
      if (auth == null && AuthHints.DECORATOR.matcher(d.name()).find()) {
        auth = "@" + d.name();
      }
    }
    if (auth == null && AuthHints.BODY.matcher(AuthHints.bodyText(f)).find()) {
      auth = "checks the user in the body";
    }
    Set<Holder> seen = new HashSet<>();
    for (Holder cur = h; cur != null && seen.add(cur); cur = parents.get(cur)) {
      path = registeredPrefix.getOrDefault(cur, cur.prefix()) + path;
      for (Function g : guards.getOrDefault(cur, List.of())) {
        if (auth == null && GUARD.matcher(AuthHints.bodyText(g)).find()) {
          auth = "before_request " + g.name();
        }
      }
    }
    for (Function g : appGuards) {
      if (auth == null && GUARD.matcher(AuthHints.bodyText(g)).find()) {
        auth = "before_request " + g.name();
      }
    }
    return new Endpoint(Framework.FLASK, path.isEmpty() ? "/" : path, methods, f.module(), f, cls, token,
      f.label(), auth == null ? Endpoint.Auth.NONE : Endpoint.Auth.by(auth), f.isAsync(),
      AuthHints.writes(f));
  }
}
