package io.github.snakeinprod.pythonweb.model;

import io.github.snakeinprod.pythonweb.lang.python.PyStatement;
import io.github.snakeinprod.pythonweb.model.AiohttpApps.Mount;
import io.github.snakeinprod.pythonweb.parse.Chain;
import io.github.snakeinprod.pythonweb.parse.Chains;
import io.github.snakeinprod.pythonweb.parse.Node;
import io.github.snakeinprod.pythonweb.parse.Nodes;
import io.github.snakeinprod.pythonweb.parse.Token;
import io.github.snakeinprod.pythonweb.parse.TokenKind;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * aiohttp endpoints: {@code @routes.get/post/.../view(path)} of a {@code web.RouteTableDef()} some {@code
 * app.add_routes(routes)} adds, {@code
 * x.router.add_get/add_post/.../add_route/add_view(path, handler)}, {@code web.get/post/.../route/view(path, handler)}
 * (in {@code app.add_routes([...])} or anywhere); a class handler (a {@code web.View}) gives one endpoint per verb
 * method. Paths take the prefixes of the sub-app they are added to ({@link AiohttpApps}). Auth: an auth decorator, aiohttp_security calls ({@code check_authorized}, {@code check_permission}, {@code
 * authorized_userid}) or an aiohttp_session login check in the handler or a helper it calls, or an auth middleware
 * registered on the route's app or an app it is mounted in ({@code web.Application(middlewares=[...])}, {@code
 * app.middlewares.append(...)}).
 */
final class AiohttpRoutes {

  private static final List<String> VERBS = List.of("get", "post", "put", "patch", "delete");
  private static final Pattern ADD = Pattern.compile("add_(get|post|put|patch|delete|head|route|view)");
  private static final Pattern WEB_DEF = Pattern.compile("aiohttp\\.web\\.(get|post|put|patch|delete|head|route|view)");

  /** aiohttp_security calls that refuse an unknown caller themselves. */
  static final Pattern SECURITY = Pattern.compile("\\b(check_authorized|check_permissions?|permits)\\(");
  /** An aiohttp_session login check: the session is read and the request refused or sent to a login page. */
  private static final Pattern SESSION_READ = Pattern.compile("session\\[|session\\.get\\(|\\bin session\\b");
  private static final Pattern SESSION_REFUSAL = Pattern.compile("HTTPUnauthorized|HTTP(Found|SeeOther)\\([^)]*login");

  private final WebModel model;
  /** Route tables: the {@code web.RouteTableDef()} call (see {@link AiohttpApps#key}) to its variable name. */
  private final Map<String, String> tables = new HashMap<>();
  /** Tables added to an app ({@code app.add_routes(routes)}), with the apps and their prefixes. */
  private final Map<String, Set<Mount>> registered = new HashMap<>();
  /** The {@code add_routes} calls outside tests. */
  private final List<AddRoutes> adds = new ArrayList<>();
  private AiohttpApps apps;
  /** Auth middlewares by the app they are registered on; the key null for an app that cannot be followed. */
  private final Map<String, String> middlewares = new LinkedHashMap<>();

  private record AddRoutes(Module module, List<Node> arg, Set<Mount> mounts) {
  }

  private AiohttpRoutes(WebModel model) {
    this.model = model;
  }

  static List<Endpoint> find(WebModel model) {
    return new AiohttpRoutes(model).run();
  }

  private List<Endpoint> run() {
    List<Module> mods = model.modules().stream().filter(m -> !m.isTest() && m.frameworks().contains(Framework.AIOHTTP)).toList();
    for (Module m : mods) {
      for (PyStatement s : m.py().walk()) {
        List<List<Node>> parts = Exprs.assignment(s.nodes());
        Chain c = parts.size() == 2 && s.body().isEmpty() ? Exprs.chain(parts.get(1)) : null;
        String var = parts.size() == 2 ? Exprs.dotted(Exprs.unannotated(parts.get(0))) : null;
        if (c != null && var != null && Exprs.firstCall(c) != null
          && m.resolve(Exprs.head(c)).matches("aiohttp\\.web(_routedef)?\\.RouteTableDef")) {
          tables.put(AiohttpApps.key(m, c), var.substring(var.lastIndexOf('.') + 1));
        }
      }
    }
    apps = new AiohttpApps(model, model.modules().stream().filter(m -> !m.isTest()).toList());
    for (Module m : mods) {
      for (PyStatement s : m.py().walk()) {
        for (Chain ch : Chains.in(s.group())) {
          middlewares(m, ch);
        }
      }
    }
    registrations();
    List<Endpoint> out = new ArrayList<>();
    for (Module m : mods) {
      for (PyStatement s : m.py().walk()) {
        for (Chain c : Chains.in(s.group())) {
          Chain.Call call = Exprs.firstCall(c);
          String head = Exprs.head(c);
          if (call == null || !head.contains(".")) {
            continue;
          }
          String last = head.substring(head.lastIndexOf('.') + 1);
          String receiver = head.substring(0, head.lastIndexOf('.'));
          Matcher web = WEB_DEF.matcher(m.resolve(head));
          Matcher add = ADD.matcher(last);
          String kind = web.matches() ? web.group(1) : add.matches() && receiver.toLowerCase(Locale.ROOT).endsWith("router")
            ? add.group(1) : null;
          if (kind == null) {
            continue;
          }
          boolean route = kind.equals("route");
          List<Node> method = route ? Exprs.arg(call, 0, "method") : null;
          String path = path(Exprs.arg(call, route ? 1 : 0, "path"));
          List<Node> handler = Exprs.arg(call, route ? 2 : 1, "handler");
          String verb = route ? Exprs.string(method) : kind;
          if (path != null && handler != null && verb != null) {
            Function at = m.functionAt(s.first().line());
            for (Mount mt : web.matches() ? listed(m, at, s) : apps.mounts(m, at, receiver)) {
              add(out, m, at, Exprs.dotted(handler), mt.prefix() + path, verb.toUpperCase(Locale.ROOT), mt.app());
            }
          }
        }
      }
      for (Function f : m.functions()) {
        for (Decorator d : f.decorators()) {
          Set<Mount> mounts = registered.getOrDefault(table(m, f.owner(), f.parent(), d), Set.of());
          String path = mounts.isEmpty() ? null : path(Exprs.arg(d.call(), 0, "path"));
          List<String> methods = List.of();
          if (path != null && (VERBS.contains(d.last()) || d.last().equals("head"))) {
            methods = List.of(d.last().toUpperCase(Locale.ROOT));
          } else if (path != null && d.last().equals("route")) {
            String verb = Exprs.string(Exprs.arg(d.call(), 0, "method"));
            path = path(Exprs.arg(d.call(), 1, "path"));
            methods = verb == null || path == null ? List.of() : List.of(verb.equals("*") ? "ANY" : verb.toUpperCase(Locale.ROOT));
          }
          for (Mount mt : methods.isEmpty() ? Set.<Mount>of() : mounts) {
            out.add(endpoint(f, null, mt.prefix() + path, methods, mt.app()));
          }
        }
      }
      for (PyClass k : m.classes()) {
        for (Decorator d : k.decorators()) {
          Set<Mount> mounts = d.last().equals("view")
            ? registered.getOrDefault(table(m, null, m.functionAt(k.firstLine()), d), Set.of()) : Set.of();
          String path = mounts.isEmpty() ? null : path(Exprs.arg(d.call(), 0, "path"));
          for (Mount mt : path == null ? Set.<Mount>of() : mounts) {
            view(out, k, mt.prefix() + path, "VIEW", mt.app());
          }
        }
      }
    }
    return merged(out);
  }

  /**
   * The {@code add_routes} calls: which tables they add, to apps with which prefixes. A table added only in tests
   * still counts (with no prefix); a table never added to an app gives no endpoint.
   */
  private void registrations() {
    List<Module> all = new ArrayList<>(model.modules());
    all.sort((a, b) -> Boolean.compare(a.isTest(), b.isTest()));
    for (Module m : all) {
      for (PyStatement s : m.py().walk()) {
        for (Chain c : Chains.in(s.group())) {
          Chain.Call call = Exprs.firstCall(c);
          String head = Exprs.head(c);
          List<Node> arg = call != null && head.endsWith(".add_routes") ? Exprs.arg(call, 0, "routes") : null;
          if (arg == null) {
            continue;
          }
          Function at = m.functionAt(c.line());
          Set<Mount> mounts = m.isTest() ? Set.of(Mount.UNKNOWN) : apps.mounts(m, at, head.substring(0, head.lastIndexOf('.')));
          if (!m.isTest()) {
            adds.add(new AddRoutes(m, arg, mounts));
          }
          for (String t : tablesIn(m, at, arg)) {
            if (!m.isTest() || !registered.containsKey(t)) {
              registered.computeIfAbsent(t, k -> new LinkedHashSet<>()).addAll(mounts);
            }
          }
        }
      }
    }
  }

  /**
   * The tables an {@code add_routes} argument denotes. One that cannot be followed ({@code webapp.add_routes(m.routes)}
   * over a registry, a list of tables) stands for every table of that name.
   */
  private Set<String> tablesIn(Module m, Function at, List<Node> arg) {
    String name = Exprs.dotted(arg);
    Set<String> out = new LinkedHashSet<>();
    if (name != null) {
      apps.of(m, at, name).stream().filter(tables::containsKey).forEach(out::add);
    }
    if (out.isEmpty()) {
      Set<String> words = name != null ? Set.of(name.substring(name.lastIndexOf('.') + 1))
        : Nodes.tokens(arg).stream().filter(t -> t.kind() == TokenKind.IDENT).map(Token::text).collect(Collectors.toSet());
      tables.forEach((k, v) -> {
        if (words.contains(v)) {
          out.add(k);
        }
      });
    }
    return out;
  }

  /**
   * The apps a {@code web.get(...)} of statement {@code s} goes to: the {@code add_routes([...])} it is
   * in, or the one that adds the list it is assigned or appended to ({@code routes = [...]}, {@code routes.append(...)}).
   */
  private Set<Mount> listed(Module m, Function at, PyStatement s) {
    for (Chain c : Chains.in(s.group())) {
      String head = Exprs.head(c);
      if (Exprs.firstCall(c) != null && head.endsWith(".add_routes")) {
        return apps.mounts(m, at, head.substring(0, head.lastIndexOf('.')));
      }
    }
    List<List<Node>> parts = Exprs.assignment(s.nodes());
    String var = parts.size() > 1 ? Exprs.dotted(Exprs.unannotated(parts.get(0))) : null;
    Chain first = var == null && !s.nodes().isEmpty() ? Chains.direct(s.group()).stream().findFirst().orElse(null) : null;
    if (first != null && Exprs.firstCall(first) != null && Exprs.head(first).matches("[\\w.]+\\.(append|extend|insert)")) {
      var = Exprs.head(first).substring(0, Exprs.head(first).lastIndexOf('.'));
    } else if (var == null && s.nodes().size() > 1 && Nodes.isLeaf(s.nodes().get(1), "+=")) {
      var = Exprs.dotted(s.nodes().subList(0, 1));
    }
    Set<Mount> out = new LinkedHashSet<>();
    for (AddRoutes a : var == null ? List.<AddRoutes>of() : adds) {
      String name = Exprs.dotted(a.arg());
      WebModel.Ref r = name == null ? null : a.module() == m ? new WebModel.Ref(m, name) : model.locate(a.module(), name);
      if (r != null && r.module() == m && r.name().equals(var)) {
        out.addAll(a.mounts());
      }
    }
    return out.isEmpty() ? Set.of(Mount.UNKNOWN) : out;
  }

  /** One endpoint per handler and path: {@code add_get("/", index)} and {@code add_post("/", index)} give GET|POST /. */
  private static List<Endpoint> merged(List<Endpoint> all) {
    Map<String, Endpoint> out = new LinkedHashMap<>();
    for (Endpoint e : all) {
      String key = e.module().path() + ":" + e.function().firstLine() + " " + e.path();
      Endpoint prev = out.get(key);
      if (prev == null) {
        out.put(key, e);
      } else if (!prev.methods().containsAll(e.methods())) {
        List<String> methods = new ArrayList<>(prev.methods());
        methods.addAll(e.methods());
        out.put(key, new Endpoint(prev.framework(), prev.path(), List.copyOf(methods), prev.module(), prev.function(),
          prev.viewClass(), prev.token(), prev.label(), prev.auth(), prev.async(), prev.writes()));
      }
    }
    return new ArrayList<>(out.values());
  }

  /**
   * The table a decorator is of ({@code @routes.get("/x")}): a class attribute of {@code owner}, else a name seen
   * from {@code scope}; or null.
   */
  private String table(Module m, PyClass owner, Function scope, Decorator d) {
    if (d.call() == null || d.receiver().isEmpty()) {
      return null;
    }
    List<Node> attr = owner == null ? null : owner.attributes().get(d.receiver());
    Set<String> keys = attr != null ? apps.of(m, null, attr, 0) : apps.of(m, scope, d.receiver());
    return keys.stream().filter(tables::containsKey).findFirst().orElse(null);
  }

  /** The endpoints of one registered handler: a function, a method ({@code self.handle_post}) or a view class. */
  private void add(List<Endpoint> out, Module m, Function at, String name, String path, String verb, String app) {
    if (name == null) {
      return;
    }
    if (name.startsWith("self.") && at != null) {
      Function owner = at;
      while (owner.owner() == null && owner.parent() != null) {
        owner = owner.parent();
      }
      Function f = owner.owner() == null ? null : model.method(owner.owner(), name.substring(5));
      if (f != null) {
        out.add(endpoint(f, null, path, List.of(verb), app));
      }
      return;
    }
    PyClass k = model.cls(m, name);
    if (k != null) {
      view(out, k, path, verb, app);
      return;
    }
    Function f = model.function(m, name);
    if (f == null && !name.contains(".")) {
      // a handler defined inside the factory that registers it (that factory's own first, when several define one)
      f = m.functions().stream().filter(x -> x.name().equals(name) && x.owner() == null)
        .min((a, b) -> Boolean.compare(a.parent() != at, b.parent() != at)).orElse(null);
    }
    if (f != null) {
      out.add(endpoint(f, null, path, List.of(verb.equals("*") || verb.equals("VIEW") ? "ANY" : verb), app));
    }
  }

  /** A class-based view: one endpoint per verb method it (or a project base) defines, all of them for "*" or a view. */
  private void view(List<Endpoint> out, PyClass k, String path, String verb, String app) {
    for (String v : VERBS) {
      Function f = model.method(k, v);
      if (f != null && (verb.equals("*") || verb.equals("VIEW") || verb.equalsIgnoreCase(v))) {
        out.add(endpoint(f, k, path, List.of(v.toUpperCase(Locale.ROOT)), app));
      }
    }
  }

  /**
   * The middlewares registered on an app: {@code web.Application(middlewares=[...])}, {@code
   * app.middlewares.append(m)} / {@code extend([...])}. Per app, the first one whose code checks the caller is the
   * evidence; one on an app that cannot be followed ({@code self.app.middlewares}) is kept under null.
   */
  private void middlewares(Module m, Chain c) {
    Chain.Call call = Exprs.firstCall(c);
    String head = Exprs.head(c);
    if (call == null) {
      return;
    }
    List<Node> list = null;
    Set<String> on = Set.of();
    if (m.resolve(head).equals("aiohttp.web.Application")) {
      list = Exprs.kwargs(call).get("middlewares");
      on = Set.of(AiohttpApps.key(m, c));
    } else if (head.endsWith(".middlewares.append") || head.endsWith(".middlewares.extend") || head.endsWith(".middlewares.insert")) {
      List<List<Node>> pos = Exprs.positional(call);
      list = pos.isEmpty() ? null : pos.get(pos.size() - 1);
      on = apps.of(m, m.functionAt(c.line()), head.substring(0, head.lastIndexOf(".middlewares.")));
    }
    if (list == null) {
      return;
    }
    for (List<Node> item : Exprs.items(list)) {
      Chain ch = Exprs.chain(item);
      String name = ch == null ? null : Exprs.head(ch);
      Function f = name == null ? null : model.function(m, name);
      if (f != null && (SECURITY.matcher(AuthHints.bodyText(f)).find() || AuthHints.checkingDecorator(f))) {
        if (on.isEmpty()) {
          middlewares.putIfAbsent(null, "middleware " + name);
        }
        on.forEach(app -> middlewares.putIfAbsent(app, "middleware " + name));
        return;
      }
    }
  }

  /**
   * The auth middleware that runs for a route of {@code app}: one registered on it or on an app it is mounted in
   * (aiohttp runs a parent's middlewares for its sub-apps' routes), or on an app that cannot be followed. For a route
   * whose app cannot be followed, any auth middleware.
   */
  private String middleware(String app) {
    if (middlewares.containsKey(null) || app == null) {
      return middlewares.isEmpty() ? null : middlewares.values().iterator().next();
    }
    // ponytail: a sub-app mounted in two parents counts as guarded when either parent is; split per prefix if that matters
    return apps.lineage(app).stream().map(middlewares::get).filter(Objects::nonNull).findFirst().orElse(null);
  }

  /** A path literal, or an f-string's literal parts ({@code f"{base}/api/rooms/{{name}}"} gives "/api/rooms/{name}"). */
  static String path(List<Node> nodes) {
    String s = Exprs.string(nodes);
    if (s != null || nodes == null || nodes.size() != 1) {
      return s;
    }
    Token t = Nodes.leaf(nodes.get(0));
    if (t == null || t.kind() != TokenKind.STRING) {
      return null;
    }
    String text = t.text();
    int q = 0;
    while (q < text.length() && text.charAt(q) != '\'' && text.charAt(q) != '"') {
      q++;
    }
    String body = text.substring(q);
    int quote = body.startsWith("\"\"\"") || body.startsWith("'''") ? 3 : 1;
    if (body.length() < 2 * quote) {
      return null;
    }
    body = body.substring(quote, body.length() - quote);
    // drop the {fields}, keep {{escaped}} braces as one brace
    String out = body.replace("{{", "\u0001").replace("}}", "\u0002").replaceAll("\\{[^{}]*}", "")
      .replace('\u0001', '{').replace('\u0002', '}').replaceAll("/{2,}", "/");
    return out.isEmpty() ? "/" : out;
  }

  private Endpoint endpoint(Function f, PyClass cls, String path, List<String> methods, String app) {
    String auth = null;
    for (Decorator d : f.decorators()) {
      if (auth == null && (AuthHints.DECORATOR.matcher(d.name()).find() || AuthHints.checkingDecorator(model, f.module(), d))) {
        auth = "@" + d.name();
      }
    }
    if (auth == null) {
      auth = checks(f, "in the body");
    }
    if (auth == null) {
      Function h = checkingHelper(f, 2);
      auth = h == null ? null : h.name() + "() checks the caller";
    }
    if (auth == null) {
      auth = middleware(app);
    }
    return new Endpoint(Framework.AIOHTTP, path.isEmpty() ? "/" : path, methods, f.module(), f, cls, f.token(), f.label(),
      auth == null ? Endpoint.Auth.NONE : Endpoint.Auth.by(auth), f.isAsync(), AuthHints.writes(f));
  }

  /** A project function {@code f} calls, directly or through {@code depth - 1} more calls, that checks the caller; or null. */
  private Function checkingHelper(Function f, int depth) {
    for (PyStatement s : f.body()) {
      for (PyStatement x : s.walk()) {
        for (Chain c : Chains.in(x.group())) {
          Function callee = Exprs.firstCall(c) != null ? helper(f, Exprs.head(c)) : null;
          if (callee != null && callee != f && (checks(callee, "") != null || depth > 1 && checkingHelper(callee, depth - 1) != null)) {
            return callee;
          }
        }
      }
    }
    return null;
  }

  /** A project function a handler calls: {@code get_authorized_user(request)}, {@code self._check_permissions()}. */
  private Function helper(Function f, String head) {
    if (head.startsWith("self.") && f.owner() != null) {
      return model.method(f.owner(), head.substring(5));
    }
    return model.function(f.module(), head);
  }

  /** What in a function's body checks the caller: an aiohttp_security call, a session login check, a user or credential test; or null. */
  private static String checks(Function f, String where) {
    String body = AuthHints.bodyText(f);
    Matcher sec = SECURITY.matcher(body);
    String suffix = where.isEmpty() ? "" : " " + where;
    if (sec.find()) {
      return sec.group(1) + suffix;
    }
    if (body.contains("authorized_userid(") && SESSION_REFUSAL.matcher(body).find()) {
      // the identity is read and an unknown caller refused (not a login page sending a known one away)
      return "authorized_userid" + suffix;
    }
    if (body.contains("get_session(") && SESSION_READ.matcher(body).find() && SESSION_REFUSAL.matcher(body).find()) {
      return "session check" + suffix;
    }
    if (AuthHints.BODY.matcher(body).find()) {
      return "checks the user" + suffix;
    }
    // a helper reading a credential (Authorization header, session cookie, token) and refusing with 401 / 403; not a
    // handler, whose login form also reads the session and refuses
    return where.isEmpty() && AuthHints.checkingDecorator(f) ? "checks the caller" : null;
  }
}
