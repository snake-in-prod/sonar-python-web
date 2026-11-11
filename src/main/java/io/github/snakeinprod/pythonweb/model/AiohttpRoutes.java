package io.github.snakeinprod.pythonweb.model;

import io.github.snakeinprod.pythonweb.lang.python.PyStatement;
import io.github.snakeinprod.pythonweb.parse.Chain;
import io.github.snakeinprod.pythonweb.parse.Chains;
import io.github.snakeinprod.pythonweb.parse.Node;
import io.github.snakeinprod.pythonweb.parse.Nodes;
import io.github.snakeinprod.pythonweb.parse.Token;
import io.github.snakeinprod.pythonweb.parse.TokenKind;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * aiohttp endpoints: {@code @routes.get/post/.../view(path)} of a {@code web.RouteTableDef()}, {@code
 * x.router.add_get/add_post/.../add_route/add_view(path, handler)}, {@code web.get/post/.../route/view(path, handler)}
 * (in {@code app.add_routes([...])} or anywhere); a class handler (a {@code web.View}) gives one endpoint per verb
 * method. Auth: an auth decorator, aiohttp_security calls ({@code check_authorized}, {@code check_permission}, {@code
 * authorized_userid}) or an aiohttp_session login check in the handler or a helper it calls, or an auth middleware
 * registered on an app ({@code web.Application(middlewares=[...])}, {@code app.middlewares.append(...)}).
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
  private final Set<String> tables = new HashSet<>();
  private String middleware;

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
          tables.add(m.path() + "#" + var);
        }
        for (Chain ch : Chains.in(s.group())) {
          middlewares(m, ch);
        }
      }
    }
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
            add(out, m, at, Exprs.dotted(handler), path, verb.toUpperCase(Locale.ROOT));
          }
        }
      }
      for (Function f : m.functions()) {
        for (Decorator d : f.decorators()) {
          String path = table(m, d) ? path(Exprs.arg(d.call(), 0, "path")) : null;
          if (path != null && (VERBS.contains(d.last()) || d.last().equals("head"))) {
            out.add(endpoint(f, null, path, List.of(d.last().toUpperCase(Locale.ROOT))));
          } else if (path != null && d.last().equals("route")) {
            String verb = Exprs.string(Exprs.arg(d.call(), 0, "method"));
            path = path(Exprs.arg(d.call(), 1, "path"));
            if (verb != null && path != null) {
              out.add(endpoint(f, null, path, List.of(verb.equals("*") ? "ANY" : verb.toUpperCase(Locale.ROOT))));
            }
          }
        }
      }
      for (PyClass k : m.classes()) {
        for (Decorator d : k.decorators()) {
          String path = table(m, d) && d.last().equals("view") ? path(Exprs.arg(d.call(), 0, "path")) : null;
          if (path != null) {
            view(out, k, path, "VIEW");
          }
        }
      }
    }
    return merged(out);
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

  /** A decorator of a RouteTableDef: {@code @routes.get("/x")}. */
  private boolean table(Module m, Decorator d) {
    if (d.call() == null || d.receiver().isEmpty()) {
      return false;
    }
    if (tables.contains(m.path() + "#" + d.receiver())) {
      return true;
    }
    WebModel.Ref r = model.locate(m, d.receiver());
    return r != null && tables.contains(r.module().path() + "#" + r.name());
  }

  /** The endpoints of one registered handler: a function, a method ({@code self.handle_post}) or a view class. */
  private void add(List<Endpoint> out, Module m, Function at, String name, String path, String verb) {
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
        out.add(endpoint(f, null, path, List.of(verb)));
      }
      return;
    }
    PyClass k = model.cls(m, name);
    if (k != null) {
      view(out, k, path, verb);
      return;
    }
    Function f = model.function(m, name);
    if (f == null && !name.contains(".")) {
      // a handler defined inside the factory that registers it
      f = m.functions().stream().filter(x -> x.name().equals(name) && x.owner() == null).findFirst().orElse(null);
    }
    if (f != null) {
      out.add(endpoint(f, null, path, List.of(verb.equals("*") || verb.equals("VIEW") ? "ANY" : verb)));
    }
  }

  /** A class-based view: one endpoint per verb method it (or a project base) defines, all of them for "*" or a view. */
  private void view(List<Endpoint> out, PyClass k, String path, String verb) {
    for (String v : VERBS) {
      Function f = model.method(k, v);
      if (f != null && (verb.equals("*") || verb.equals("VIEW") || verb.equalsIgnoreCase(v))) {
        out.add(endpoint(f, k, path, List.of(v.toUpperCase(Locale.ROOT))));
      }
    }
  }

  /**
   * The middlewares registered on an app: {@code web.Application(middlewares=[...])}, {@code
   * app.middlewares.append(m)} / {@code extend([...])}. The first one whose code checks the caller is the evidence.
   */
  private void middlewares(Module m, Chain c) {
    Chain.Call call = Exprs.firstCall(c);
    String head = Exprs.head(c);
    if (call == null || middleware != null) {
      return;
    }
    List<Node> list = null;
    if (m.resolve(head).equals("aiohttp.web.Application")) {
      list = Exprs.kwargs(call).get("middlewares");
    } else if (head.endsWith(".middlewares.append") || head.endsWith(".middlewares.extend") || head.endsWith(".middlewares.insert")) {
      List<List<Node>> pos = Exprs.positional(call);
      list = pos.isEmpty() ? null : pos.get(pos.size() - 1);
    }
    if (list == null) {
      return;
    }
    for (List<Node> item : Exprs.items(list)) {
      Chain ch = Exprs.chain(item);
      String name = ch == null ? null : Exprs.head(ch);
      Function f = name == null ? null : model.function(m, name);
      if (f != null && (SECURITY.matcher(AuthHints.bodyText(f)).find() || AuthHints.checkingDecorator(f))) {
        middleware = "middleware " + name;
        return;
      }
    }
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

  private Endpoint endpoint(Function f, PyClass cls, String path, List<String> methods) {
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
    if (auth == null && middleware != null) {
      // ponytail: an auth middleware counts for every aiohttp endpoint; tie it to its app when repositories mix apps
      auth = middleware;
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
