package io.github.snakeinprod.pythonweb.model;

import io.github.snakeinprod.pythonweb.lang.python.PyStatement;
import io.github.snakeinprod.pythonweb.parse.Chain;
import io.github.snakeinprod.pythonweb.parse.Chains;
import io.github.snakeinprod.pythonweb.parse.Node;
import io.github.snakeinprod.pythonweb.parse.Nodes;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Which aiohttp object a name denotes: the {@code web.Application()} or {@code web.RouteTableDef()} call that made it,
 * as a key ("app.py:12:10"). Followed through local and module assignments, {@code for} loops, imports, factory
 * functions that return it and parameters (to the arguments of every call of the function; for a method, calls on
 * an instance of its class). {@code app.router} is {@code app}; {@code self.app} is not followed. The prefixes of an
 * app come from {@code parent.add_subapp(prefix, child)}, nested ones joined.
 */
final class AiohttpApps {

  static final Pattern MADE = Pattern.compile("aiohttp\\.web(_app|_routedef)?\\.(Application|RouteTableDef)");
  private static final int DEPTH = 8;

  private final WebModel model;
  /** Child app to its parents and the prefix it is mounted at. */
  private final Map<String, List<String[]>> parents = new HashMap<>();
  /** Calls by the last name of their head, for following parameters; built on first use. */
  private Map<String, List<Site>> calls;

  /** A call: the dotted receiver before the name ("" for none, null for a made object) or the class it is made from. */
  private record Site(Module module, Function scope, String receiver, PyClass made, Chain.Call call) {
  }

  AiohttpApps(WebModel model, List<Module> mods) {
    this.model = model;
    for (Module m : mods) {
      for (PyStatement s : m.py().walk()) {
        for (Chain c : Chains.in(s.group())) {
          Chain.Call call = Exprs.firstCall(c);
          String head = Exprs.head(c);
          String prefix = call != null && head.endsWith(".add_subapp") ? AiohttpRoutes.path(Exprs.arg(call, 0, "prefix")) : null;
          List<Node> child = prefix == null ? null : Exprs.arg(call, 1, "subapp");
          if (child != null) {
            Function at = m.functionAt(c.line());
            // aiohttp drops the trailing slash of a prefix
            String p = prefix.replaceAll("/+$", "");
            for (String parent : of(m, at, head.substring(0, head.lastIndexOf('.')))) {
              for (String k : of(m, at, child, 0)) {
                parents.computeIfAbsent(k, x -> new ArrayList<>()).add(new String[] {parent, p});
              }
            }
          }
        }
      }
    }
  }

  static String key(Module m, Chain made) {
    return m.path() + ":" + made.first().line() + ":" + made.first().column();
  }

  /** An app (null: unknown) and one URL prefix it is mounted at ("" for a root). */
  record Mount(String app, String prefix) {
    static final Mount UNKNOWN = new Mount(null, "");
  }

  /** The apps a receiver denotes ({@code app}, {@code app.router}) with their prefixes; {@link Mount#UNKNOWN} when none. */
  Set<Mount> mounts(Module m, Function scope, String receiver) {
    Set<Mount> out = new LinkedHashSet<>();
    for (String k : of(m, scope, receiver)) {
      for (String p : prefixes(k, 0)) {
        out.add(new Mount(k, p));
      }
    }
    return out.isEmpty() ? Set.of(Mount.UNKNOWN) : out;
  }

  /** The app and every app it is mounted in, up through nested sub-apps: whose middlewares run for its routes. */
  Set<String> lineage(String app) {
    Set<String> out = new LinkedHashSet<>();
    List<String> todo = new ArrayList<>(List.of(app));
    while (!todo.isEmpty()) {
      String a = todo.remove(todo.size() - 1);
      if (out.add(a)) {
        parents.getOrDefault(a, List.of()).forEach(e -> todo.add(e[0]));
      }
    }
    return out;
  }

  private Set<String> prefixes(String app, int depth) {
    List<String[]> up = parents.get(app);
    if (up == null || depth > DEPTH) {
      return Set.of("");
    }
    Set<String> out = new LinkedHashSet<>();
    for (String[] e : up) {
      for (String p : prefixes(e[0], depth + 1)) {
        out.add(p + e[1]);
      }
    }
    return out;
  }

  /** The objects a name denotes in a function (null: module level). */
  Set<String> of(Module m, Function scope, String name) {
    return of(m, scope, name, 0);
  }

  /** The objects an expression denotes: a constructor call, a factory call, a name ({@code await} dropped). */
  Set<String> of(Module m, Function scope, List<Node> expr, int depth) {
    if (expr == null || expr.isEmpty() || depth > DEPTH) {
      return Set.of();
    }
    if (Nodes.isLeaf(expr.get(0), "await")) {
      expr = expr.subList(1, expr.size());
    }
    Chain c = Exprs.chain(expr);
    if (c == null) {
      return Set.of();
    }
    String head = Exprs.head(c);
    int n = Exprs.headSize(c);
    if (n == c.segments().size()) {
      return of(m, scope, head, depth + 1);
    }
    if (Exprs.firstCall(c) == null || n + 1 != c.segments().size()) {
      return Set.of();
    }
    if (MADE.matcher(m.resolve(head)).matches()) {
      return Set.of(key(m, c));
    }
    Function f = head.startsWith("self.") ? null : model.function(m, head);
    Set<String> out = new LinkedHashSet<>();
    if (f != null) {
      for (PyStatement s : own(f)) {
        if (s.keyword().equals("return")) {
          out.addAll(of(f.module(), f, s.nodes().subList(1, s.nodes().size()), depth + 1));
        }
      }
    }
    return out;
  }

  private Set<String> of(Module m, Function scope, String name, int depth) {
    if (name.endsWith(".router")) {
      name = name.substring(0, name.length() - ".router".length());
    }
    if (depth > DEPTH || name.isEmpty() || name.startsWith("self.") || name.startsWith("cls.")) {
      return Set.of();
    }
    for (Function f = scope; f != null; f = f.parent()) {
      List<List<Node>> values = values(f, name);
      if (!values.isEmpty()) {
        Set<String> out = new LinkedHashSet<>();
        for (List<Node> v : values) {
          out.addAll(of(m, f, v, depth + 1));
        }
        return out;
      }
      Function.Param p = f.param(name);
      if (p != null) {
        return p.stars() > 0 ? Set.of() : callers(f, f.params().indexOf(p), name, depth + 1);
      }
    }
    List<List<Node>> values = m.assignments().get(name);
    if (values != null) {
      Set<String> out = new LinkedHashSet<>();
      for (List<Node> v : values) {
        out.addAll(of(m, null, v, depth + 1));
      }
      return out;
    }
    WebModel.Ref r = model.locate(m, name);
    return r == null || r.module() == m && r.name().equals(name) || r.name().isEmpty() ? Set.of() : of(r.module(), null, r.name(), depth + 1);
  }

  /** What a function's own statements assign to a name: {@code name = v}, and the items of {@code for name in [a, b]}. */
  private static List<List<Node>> values(Function f, String name) {
    List<List<Node>> out = new ArrayList<>();
    for (PyStatement s : own(f)) {
      List<Node> nodes = s.nodes();
      if (s.keyword().equals("for")) {
        int in = 1;
        while (in < nodes.size() && !Nodes.isLeaf(nodes.get(in), "in")) {
          in++;
        }
        int end = Nodes.isLeaf(nodes.get(nodes.size() - 1), ":") ? nodes.size() - 1 : nodes.size();
        if (in < end && name.equals(Exprs.dotted(nodes.subList(1, in)))) {
          out.addAll(Exprs.items(nodes.subList(in + 1, end)));
        }
      } else if (s.body().isEmpty()) {
        List<List<Node>> parts = Exprs.assignment(nodes);
        for (List<Node> t : parts.subList(0, parts.size() - 1)) {
          if (name.equals(Exprs.dotted(Exprs.unannotated(t)))) {
            out.add(parts.get(parts.size() - 1));
          }
        }
      }
    }
    return out;
  }

  /** The statements of a function, those of nested defs excluded. */
  private static List<PyStatement> own(Function f) {
    List<PyStatement> out = new ArrayList<>();
    for (PyStatement s : f.body()) {
      for (PyStatement x : s.walk()) {
        if (f.module().functionAt(x.first().line()) == f) {
          out.add(x);
        }
      }
    }
    return out;
  }

  /**
   * What the callers of {@code f} pass for its parameter at {@code index}: {@code setup_routes(app)}, {@code
   * handler.register(app)} with {@code handler = Handler(...)}. Calls on an instance of unknown type count only
   * when no typed call does.
   */
  private Set<String> callers(Function f, int index, String name, int depth) {
    Set<String> typed = new LinkedHashSet<>();
    Set<String> untyped = new LinkedHashSet<>();
    int pos = f.takesSelf() ? index - 1 : index;
    for (Site site : calls().getOrDefault(f.name(), List.of())) {
      Boolean match = matches(site, f);
      List<Node> arg = match == null ? null : Exprs.arg(site.call(), pos, name);
      if (arg != null) {
        (match ? typed : untyped).addAll(of(site.module(), site.scope(), arg, depth));
      }
    }
    return typed.isEmpty() ? untyped : typed;
  }

  /** The call is of {@code f}: true; may be (a method called on a value of unknown type): false; is not: null. */
  private Boolean matches(Site site, Function f) {
    String receiver = site.receiver();
    if (f.owner() == null) {
      return receiver != null && model.function(site.module(), receiver.isEmpty() ? f.name() : receiver + "." + f.name()) == f ? true : null;
    }
    PyClass type = site.made();
    if (receiver == null && type == null || "".equals(receiver)) {
      return null;
    }
    if ("self".equals(receiver) && site.scope() != null) {
      Function outer = site.scope();
      while (outer.owner() == null && outer.parent() != null) {
        outer = outer.parent();
      }
      type = outer.owner();
    } else if (receiver != null) {
      List<List<Node>> values = new ArrayList<>();
      for (Function s = site.scope(); s != null && values.isEmpty(); s = s.parent()) {
        values.addAll(values(s, receiver));
      }
      if (values.isEmpty() && site.module().assignments().containsKey(receiver)) {
        values.addAll(site.module().assignments().get(receiver));
      }
      for (List<Node> v : values) {
        Chain c = Exprs.chain(Nodes.isLeaf(v.get(0), "await") ? v.subList(1, v.size()) : v);
        PyClass k = c != null && Exprs.firstCall(c) != null ? model.cls(site.module(), Exprs.head(c)) : null;
        type = k != null ? k : type;
      }
    }
    if (type == null) {
      return false;
    }
    return model.method(type, f.name()) == f ? true : null;
  }

  /**
   * Every call in the project by its name: {@code a.b.f(x)} (receiver "a.b"), {@code f(x)} (receiver ""), {@code
   * Handler().register(app)} (the class made, receiver null).
   */
  private Map<String, List<Site>> calls() {
    if (calls == null) {
      calls = new HashMap<>();
      for (Module m : model.modules()) {
        if (m.isTest()) {
          continue;
        }
        for (PyStatement s : m.py().walk()) {
          for (Chain c : Chains.in(s.group())) {
            List<Chain.Segment> seg = c.segments();
            Function scope = m.functionAt(c.line());
            int n = Exprs.headSize(c);
            if (n < seg.size() && seg.get(n) instanceof Chain.Call call) {
              String head = Exprs.head(c);
              int dot = head.lastIndexOf('.');
              calls.computeIfAbsent(head.substring(dot + 1), k -> new ArrayList<>())
                .add(new Site(m, scope, dot < 0 ? "" : head.substring(0, dot), null, call));
              // Handler(...).register(app)
              PyClass made = n + 2 < seg.size() ? model.cls(m, head) : null;
              if (made != null && seg.get(n + 1) instanceof Chain.Name name && seg.get(n + 2) instanceof Chain.Call second) {
                calls.computeIfAbsent(name.token().text(), k -> new ArrayList<>()).add(new Site(m, scope, null, made, second));
              }
            }
          }
        }
      }
    }
    return calls;
  }
}
