package io.github.snakeinprod.pythonweb.model;

import io.github.snakeinprod.pythonweb.lang.python.PyStatement;
import io.github.snakeinprod.pythonweb.parse.Chain;
import io.github.snakeinprod.pythonweb.parse.Chains;
import io.github.snakeinprod.pythonweb.parse.Node;
import io.github.snakeinprod.pythonweb.parse.Token;
import io.github.snakeinprod.pythonweb.parse.TokenKind;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * FastAPI endpoints: {@code @app.get(...)} / {@code @router.post(...)} / {@code @router.api_route(..., methods=[...])}
 * on {@code FastAPI()} and {@code APIRouter(prefix=..., dependencies=[...])} objects, prefixes and dependencies of
 * {@code include_router} calls followed up to the app; a router only tests include gives no endpoint. Auth: a dependency whose name says so ({@code
 * Depends(get_current_user)}, {@code Security(...)}, an {@code OAuth2PasswordBearer} scheme, an {@code Annotated} alias of
 * one, or a project dependency function that itself depends on one) on the route, a parameter, a router, an include or
 * the app.
 */
final class FastApiRoutes {

  private static final Set<String> VERBS = Set.of("get", "post", "put", "patch", "delete", "options", "head", "trace", "api_route");

  /** A FastAPI app or APIRouter object: module-level or inside a factory function ({@code at}, else null). */
  record Router(Module module, String var, String prefix, List<Node> deps, boolean app, Function at) {
  }

  record Include(Router parent, String prefix, List<Node> deps) {
  }

  private final WebModel model;
  private final Map<String, Router> routers = new LinkedHashMap<>();
  private final Map<Router, Include> parents = new HashMap<>();
  /** Every router an include_router outside tests adds to a known router. */
  private final Map<Router, Set<Router>> includedIn = new HashMap<>();
  /** Routers an include_router outside tests adds to a receiver that cannot be followed ({@code self.app}). */
  private final Set<Router> looseIncludes = new HashSet<>();
  /** Some include_router outside tests adds a router that cannot be followed: every router counts as mounted. */
  private boolean unknownInclude;
  private Map<String, Integer> names;

  private FastApiRoutes(WebModel model) {
    this.model = model;
  }

  static List<Endpoint> find(WebModel model) {
    return new FastApiRoutes(model).run();
  }

  private List<Endpoint> run() {
    // every module: a route module may import only the project's own router class
    List<Module> fastapi = model.modules().stream().filter(m -> !m.isTest()).toList();
    for (Module m : fastapi) {
      for (PyStatement s : m.py().walk()) {
        List<List<Node>> parts = Exprs.assignment(s.nodes());
        Chain c = parts.size() == 2 && s.body().isEmpty() ? Exprs.chain(parts.get(1)) : null;
        String var = parts.size() == 2 ? Exprs.dotted(Exprs.unannotated(parts.get(0))) : null;
        Chain.Call call = c == null ? null : Exprs.firstCall(c);
        if (call == null || var == null || Exprs.headSize(c) + 1 != c.segments().size()) {
          continue;
        }
        if (routerFactory(m, Exprs.head(c))) {
          String prefix = Exprs.string(Exprs.arg(call, -1, "prefix"));
          List<Node> deps = Exprs.arg(call, -1, "dependencies");
          routers.put(m.path() + "#" + var, new Router(m, var, prefix == null ? "" : prefix, deps == null ? List.of() : deps,
            isApp(m, Exprs.head(c)), m.functionAt(s.first().line())));
        }
      }
    }
    for (Module m : fastapi) {
      for (PyStatement s : m.py().walk()) {
        for (Chain c : Chains.in(s.group())) {
          if (c.names().size() >= 2 && c.lastName().equals("include_router") && Exprs.firstCall(c) != null) {
            Chain.Call call = Exprs.firstCall(c);
            String head = Exprs.head(c);
            Router parent = router(m, head.substring(0, head.lastIndexOf('.')));
            List<Node> childNodes = Exprs.arg(call, 0, "router");
            String childName = childNodes == null ? null : Exprs.dotted(childNodes);
            Router child = childName == null ? null : router(m, childName);
            if (parent != null && child != null && child != parent) {
              String prefix = Exprs.string(Exprs.arg(call, -1, "prefix"));
              List<Node> deps = Exprs.arg(call, -1, "dependencies");
              parents.putIfAbsent(child, new Include(parent, prefix == null ? "" : prefix, deps == null ? List.of() : deps));
            }
            Set<Router> children = childNodes == null ? Set.of() : children(m, childNodes);
            if (children == null) {
              unknownInclude = true;
            } else if (parent != null) {
              children.forEach(k -> includedIn.computeIfAbsent(k, x -> new HashSet<>()).add(parent));
            } else if (reached(m.functionAt(c.line()), head)) {
              looseIncludes.addAll(children);
            }
          }
        }
      }
    }
    List<Endpoint> out = new ArrayList<>();
    for (Module m : fastapi) {
      for (Function f : m.functions()) {
        for (Decorator d : f.decorators()) {
          if (d.call() != null && VERBS.contains(d.last()) && !d.receiver().isEmpty()
            && d.chain().segments().size() == Exprs.headSize(d.chain()) + 1) {
            Router r = router(m, d.receiver());
            if (r != null && mounted(r, new HashSet<>())) {
              out.add(endpoint(f, d, r));
            }
          }
        }
      }
    }
    return out;
  }

  /**
   * A call that makes an app or router: fastapi's FastAPI / APIRouter, a project alias named so ({@code
   * BackofficeRouter = make_router_class(...)}), or a project subclass of one.
   */
  private boolean routerFactory(Module m, String head) {
    String callee = m.resolve(head);
    String last = callee.substring(callee.lastIndexOf('.') + 1);
    if (callee.startsWith("fastapi.") && (last.equals("FastAPI") || last.equals("APIRouter"))) {
      return true;
    }
    WebModel.Ref r = model.locate(m, head);
    if (r == null) {
      return false;
    }
    if (last.equals("FastAPI") || last.endsWith("APIRouter") || last.endsWith("Router") && model.cls(m, head) == null) {
      return true;
    }
    PyClass cls = model.cls(m, head);
    return cls != null && model.externalBases(cls).stream()
      .anyMatch(b -> b.startsWith("fastapi.") && (b.endsWith(".FastAPI") || b.endsWith(".APIRouter")));
  }

  /** A FastAPI app ({@code FastAPI()} or a project subclass), not a router. */
  private boolean isApp(Module m, String head) {
    String callee = m.resolve(head);
    if (callee.equals("fastapi.FastAPI") || callee.endsWith(".FastAPI") || callee.equals("FastAPI")) {
      return true;
    }
    PyClass cls = model.cls(m, head);
    return cls != null && model.externalBases(cls).stream().anyMatch(b -> b.endsWith(".FastAPI"));
  }

  /**
   * The router is served: an app, or added by an include_router outside tests to a router that is, or to a receiver
   * that cannot be followed. A router only tests include gives no endpoint.
   */
  private boolean mounted(Router r, Set<Router> seen) {
    if (r.app() || unknownInclude || looseIncludes.contains(r)) {
      return true;
    }
    if (!seen.add(r)) {
      return false;
    }
    return includedIn.getOrDefault(r, Set.of()).stream().anyMatch(p -> mounted(p, seen));
  }

  /**
   * The routers an include_router argument denotes: a router name, the routers a project function builds
   * ({@code build_router()}), none for a third-party router ({@code fastapi_users.get_auth_router(...)}); null when
   * it cannot be followed ({@code for r in routers: app.include_router(r)}) and no router has that name.
   */
  private Set<Router> children(Module m, List<Node> arg) {
    String name = Exprs.dotted(arg);
    if (name != null) {
      Router r = router(m, name);
      if (r != null) {
        return Set.of(r);
      }
      if (model.locate(m, name) == null && !m.resolve(name).equals(name)) {
        return Set.of();
      }
      String last = name.substring(name.lastIndexOf('.') + 1);
      Set<Router> named = new HashSet<>();
      routers.values().stream().filter(x -> x.var().equals(last)).forEach(named::add);
      return named.isEmpty() ? null : named;
    }
    Chain c = Exprs.chain(arg);
    if (c == null || Exprs.firstCall(c) == null) {
      return null;
    }
    Function f = model.function(m, Exprs.head(c));
    if (f == null) {
      return Set.of();
    }
    Set<Router> built = new HashSet<>();
    routers.values().stream().filter(x -> x.at() == f).forEach(built::add);
    return built.isEmpty() ? null : built;
  }

  /**
   * An include_router whose receiver cannot be followed runs outside tests: unless the receiver is a parameter of a
   * function ({@code def init(app): app.include_router(...)}) that no code outside tests names.
   */
  private boolean reached(Function at, String head) {
    String receiver = head.substring(0, head.indexOf('.'));
    if (at == null || at.param(receiver) == null) {
      return true;
    }
    if (names == null) {
      names = new HashMap<>();
      model.modules().stream().filter(x -> !x.isTest()).flatMap(x -> x.file().tokens().stream())
        .filter(t -> t.kind() == TokenKind.IDENT).forEach(t -> names.merge(t.text(), 1, Integer::sum));
    }
    return names.getOrDefault(at.name(), 0) > 1;
  }

  /** The router a name denotes in a module: one assigned in that module (anywhere), or one it imports. */
  private Router router(Module m, String name) {
    Router local = routers.get(m.path() + "#" + name);
    if (local != null) {
      return local;
    }
    WebModel.Ref r = model.locate(m, name);
    return r == null ? null : routers.get(r.module().path() + "#" + r.name());
  }

  private Endpoint endpoint(Function f, Decorator d, Router r) {
    String route = Exprs.string(Exprs.arg(d.call(), 0, "path"));
    List<String> methods = new ArrayList<>();
    if (d.last().equals("api_route")) {
      Exprs.strings(Exprs.arg(d.call(), -1, "methods")).forEach(x -> methods.add(x.toUpperCase(Locale.ROOT)));
      if (methods.isEmpty()) {
        methods.add("GET");
      }
    } else {
      methods.add(d.last().toUpperCase(Locale.ROOT));
    }
    String path = r.prefix() + (route == null ? "" : route);
    String auth = null;
    List<Node> routeDeps = Exprs.arg(d.call(), -1, "dependencies");
    if (routeDeps != null && authDependency(f.module(), routeDeps, 0) != null) {
      auth = authDependency(f.module(), routeDeps, 0) + " on the route";
    }
    for (Function.Param p : f.params()) {
      String a = auth == null ? paramAuth(f.module(), p, 0) : null;
      if (a != null) {
        auth = a + " on parameter " + p.name();
      }
    }
    Router cur = r;
    Set<Router> seen = new HashSet<>();
    while (cur != null && seen.add(cur)) {
      String a = authDependency(cur.module(), cur.deps(), 0);
      if (auth == null && a != null) {
        auth = a + " on " + cur.var();
      }
      Include inc = parents.get(cur);
      if (inc == null) {
        break;
      }
      a = authDependency(inc.parent().module(), inc.deps(), 0);
      if (auth == null && a != null) {
        auth = a + " on include_router";
      }
      path = inc.parent().prefix() + inc.prefix() + path;
      cur = inc.parent();
    }
    Endpoint.Auth evidence = auth == null ? Endpoint.Auth.NONE : Endpoint.Auth.by(auth);
    Token token = f.token();
    return new Endpoint(Framework.FASTAPI, path.isEmpty() ? "/" : path, List.copyOf(methods), f.module(), f, null, token, f.label(),
      evidence, f.isAsync(), AuthHints.writes(f));
  }

  /** An auth dependency in a parameter's default or annotation (an Annotated alias followed), or null. */
  private String paramAuth(Module m, Function.Param p, int depth) {
    String a = authDependency(m, p.defaultValue(), depth);
    if (a == null) {
      a = authDependency(m, p.annotation(), depth);
    }
    String alias = a == null ? Exprs.dotted(p.annotation()) : null;
    List<Node> value = alias == null ? null : model.value(m, alias);
    if (value != null) {
      WebModel.Ref r = model.locate(m, alias);
      a = authDependency(r.module(), value, depth);
    }
    return a;
  }

  /** The first Depends(...) / Security(...) in the nodes that is about auth, as text, or null. */
  String authDependency(Module m, List<Node> nodes, int depth) {
    if (nodes == null || nodes.isEmpty() || depth > 3) {
      return null;
    }
    for (Chain c : Chains.in(new Node.Group(null, null, nodes))) {
      String head = Exprs.head(c);
      String resolved = m.resolve(head);
      Chain.Call call = Exprs.firstCall(c);
      if (call == null) {
        continue;
      }
      boolean security = resolved.equals("fastapi.Security") || head.equals("Security");
      if (!security && !resolved.equals("fastapi.Depends") && !resolved.equals("fastapi.params.Depends") && !head.equals("Depends")) {
        continue;
      }
      String text = "Depends(" + Exprs.text(call.args().children()) + ")";
      if (security) {
        return "Security(" + Exprs.text(call.args().children()) + ")";
      }
      List<Node> arg = Exprs.arg(call, 0, "dependency");
      if (arg != null && authLike(m, arg, depth)) {
        return text;
      }
    }
    return null;
  }

  /** A dependency callable that is about auth: by its name, its security scheme class, or what it depends on itself. */
  private boolean authLike(Module m, List<Node> arg, int depth) {
    if (AuthHints.DEPENDENCY.matcher(Exprs.text(arg)).find()) {
      return true;
    }
    Chain c = Exprs.chain(arg);
    if (c == null) {
      return false;
    }
    String head = Exprs.head(c);
    if (m.resolve(head).startsWith("fastapi.security")) {
      return true;
    }
    List<Node> value = model.value(m, head);
    if (value != null) {
      Chain v = Exprs.chain(value);
      WebModel.Ref r = model.locate(m, head);
      if (v != null && (r.module().resolve(Exprs.head(v)).startsWith("fastapi.security")
        || Exprs.firstCall(v) != null && AuthHints.DEPENDENCY.matcher(Exprs.head(v)).find()
        || AuthHints.AUTH_MODULE.matcher(r.module().path()).find())) {
        return true;
      }
    }
    Function f = model.function(m, head);
    if (f != null) {
      if (AuthHints.AUTH_MODULE.matcher(f.module().path()).find()) {
        return true;
      }
      for (Function.Param p : f.params()) {
        String reads = Exprs.text(p.defaultValue()) + Exprs.text(p.annotation());
        if (paramAuth(f.module(), p, depth + 1) != null
          || (reads.contains("Cookie(") || reads.contains("Header(")) && AuthHints.CREDENTIAL_PARAM.matcher(p.name()).find()) {
          return true;
        }
      }
    }
    return false;
  }
}
