package io.github.snakeinprod.pythonweb.rules;

import io.github.snakeinprod.pythonweb.lang.python.PyStatement;
import io.github.snakeinprod.pythonweb.model.Endpoint;
import io.github.snakeinprod.pythonweb.model.Exprs;
import io.github.snakeinprod.pythonweb.model.Framework;
import io.github.snakeinprod.pythonweb.model.Function;
import io.github.snakeinprod.pythonweb.model.Module;
import io.github.snakeinprod.pythonweb.model.WebModel;
import io.github.snakeinprod.pythonweb.parse.Chain;
import io.github.snakeinprod.pythonweb.parse.Chains;
import io.github.snakeinprod.pythonweb.parse.Node;
import io.github.snakeinprod.pythonweb.parse.Nodes;
import io.github.snakeinprod.pythonweb.parse.Token;
import io.github.snakeinprod.pythonweb.taint.Step;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Blocking calls in the async code of FastAPI and Django endpoints: in an async endpoint, in the async project
 * functions it calls, and in the sync project functions those call directly (reported at the call). Flask runs each
 * async view in its own event loop, so its views are left out. Calls that are awaited, passed to a thread wrapper
 * (asyncio.to_thread, sync_to_async, run_in_threadpool...) or inside a lambda are not blocking here.
 */
public class BlockingCallInAsync implements PwRule {

  private static final Set<String> HTTP = Set.of("requests.get", "requests.post", "requests.put", "requests.patch",
    "requests.delete", "requests.head", "requests.options", "requests.request", "httpx.get", "httpx.post", "httpx.put",
    "httpx.patch", "httpx.delete", "httpx.head", "httpx.options", "httpx.request", "httpx.stream",
    "urllib.request.urlopen", "urllib3.request");
  private static final Set<String> CLIENTS = Set.of("requests.Session", "requests.session", "httpx.Client");
  private static final Set<String> CLIENT_METHODS = Set.of("get", "post", "put", "patch", "delete", "head", "options",
    "request", "send", "stream");
  private static final Set<String> DRIVERS = Set.of("psycopg2.connect", "psycopg.connect", "sqlite3.connect", "pymysql.connect",
    "MySQLdb.connect", "mysql.connector.connect");
  private static final Set<String> PROCESSES = Set.of("subprocess.run", "subprocess.call", "subprocess.check_call",
    "subprocess.check_output", "os.system");
  private static final Set<String> PATH_IO = Set.of("read_text", "write_text", "read_bytes", "write_bytes", "open");
  private static final Set<String> SESSIONS = Set.of("sqlalchemy.orm.Session", "sqlalchemy.orm.session.Session", "sqlmodel.Session");
  private static final Set<String> SESSION_IO = Set.of("execute", "query", "commit", "get", "scalars", "scalar", "exec",
    "refresh", "flush", "merge");
  /** QuerySet and manager methods that run the query (their async twins start with "a"). */
  private static final Set<String> ORM_IO = Set.of("get", "create", "get_or_create", "update_or_create", "count", "exists",
    "first", "last", "update", "delete", "bulk_create", "bulk_update", "aggregate", "in_bulk", "earliest", "latest");
  /** Calls whose arguments run in a worker thread: asyncio.to_thread, sync_to_async, run_in_threadpool, loop.run_in_executor... */
  private static final Set<String> WRAPPERS = Set.of("to_thread", "sync_to_async", "database_sync_to_async",
    "run_in_threadpool", "run_sync", "run_in_executor");
  private static final Set<String> PLAIN_DECORATORS = Set.of("staticmethod", "classmethod");
  private static final int DEPTH = 3;
  private static final String FILE_IO = "use aiofiles or run the file IO with asyncio.to_thread";

  /** A blocking call: where, what ("requests.get()") and what to do instead. */
  record Blocking(Token from, Token to, String name, String advice) {
  }

  private Map<Function, Endpoint> reach;

  @Override
  public void check(RuleContext ctx) {
    WebModel model = ctx.model();
    for (Map.Entry<Function, Endpoint> e : reach(model).entrySet()) {
      Function fn = e.getKey();
      if (fn.module() != ctx.module()) {
        continue;
      }
      String where = "async " + String.join("|", e.getValue().methods()) + " " + e.getValue().path();
      for (Blocking b : direct(model, fn)) {
        ctx.report(b.from(), b.to(), b.name() + " blocks the event loop of " + where + "; " + b.advice() + ".", List.of());
      }
      for (Chain c : calls(fn)) {
        Function callee = callee(model, fn, Exprs.head(c));
        if (callee == null || callee.isAsync() || !plain(callee) || Exprs.firstCall(c) == null) {
          continue;
        }
        List<Step> path = new ArrayList<>();
        Blocking b = transitive(model, callee, path, new HashSet<>(), 0);
        if (b != null) {
          ctx.report(c.first(), c.last(), callee.name() + "() makes a blocking call (" + b.name() + ") in " + where
            + "; make it async or run it with asyncio.to_thread.", path);
        }
      }
    }
  }

  /** Async functions run on the event loop of an async FastAPI or Django endpoint, with the first such endpoint. */
  private Map<Function, Endpoint> reach(WebModel model) {
    if (reach != null) {
      return reach;
    }
    reach = new LinkedHashMap<>();
    List<Function> queue = new ArrayList<>();
    for (Endpoint e : model.endpoints()) {
      Function f = e.function();
      if (f != null && f.isAsync() && e.framework() != Framework.FLASK && !f.module().isTest() && !reach.containsKey(f)) {
        reach.put(f, e);
        queue.add(f);
      }
    }
    for (int i = 0; i < queue.size(); i++) {
      Function f = queue.get(i);
      for (Chain c : allCalls(f)) {
        Function g = callee(model, f, Exprs.head(c));
        if (g != null && g.isAsync() && plain(g) && !reach.containsKey(g)) {
          reach.put(g, reach.get(f));
          queue.add(g);
        }
      }
    }
    return reach;
  }

  /** The first blocking call in a sync function or the sync project functions it calls, the way there in {@code path}. */
  private static Blocking transitive(WebModel model, Function fn, List<Step> path, Set<Function> seen, int depth) {
    if (depth >= DEPTH || !seen.add(fn)) {
      return null;
    }
    // ponytail: local file IO only counts in the async function itself; a helper's small read is rarely what stalls the loop
    List<Blocking> own = direct(model, fn).stream().filter(b -> !b.advice().equals(FILE_IO)).toList();
    if (!own.isEmpty()) {
      Blocking b = own.get(0);
      path.add(new Step(fn.module(), b.from(), b.name() + " blocks here"));
      return b;
    }
    for (Chain c : calls(fn)) {
      Function g = callee(model, fn, Exprs.head(c));
      if (g != null && !g.isAsync() && plain(g) && Exprs.firstCall(c) != null) {
        path.add(new Step(fn.module(), c.first(), "calls " + g.name() + "()"));
        Blocking b = transitive(model, g, path, seen, depth + 1);
        if (b != null) {
          return b;
        }
        path.remove(path.size() - 1);
      }
    }
    return null;
  }

  /** The blocking calls written in the function itself, in order. */
  static List<Blocking> direct(WebModel model, Function fn) {
    Module m = fn.module();
    boolean django = model.frameworks().contains(Framework.DJANGO);
    Map<String, String> types = types(model, fn);
    List<Blocking> out = new ArrayList<>();
    for (PyStatement s : statements(fn.body())) {
      if (s.keyword().equals("for") && !s.isAsync() && django) {
        int in = indexOf(s.nodes(), "in");
        Chain c = in < 0 ? null : Exprs.chain(s.nodes().subList(in + 1, s.nodes().size() - 1));
        if (c != null && isManager(c)) {
          out.add(new Blocking(c.first(), c.last(), "Iterating " + Exprs.head(c) + "()",
            "iterate with async for, or wrap the query in sync_to_async"));
        }
      }
      for (Chain c : usable(s)) {
        Blocking b = blocking(m, fn, c, types, django);
        if (b != null) {
          out.add(b);
        }
      }
    }
    return out;
  }

  private static Blocking blocking(Module m, Function fn, Chain c, Map<String, String> types, boolean django) {
    Chain.Call call = Exprs.firstCall(c);
    if (call == null) {
      return null;
    }
    String head = Exprs.head(c);
    List<String> names = c.names();
    String first = names.get(0);
    String type = types.get(first);
    String name = head + "()";
    if (type != null && Exprs.headSize(c) == 2) {
      if (CLIENTS.contains(type) && CLIENT_METHODS.contains(names.get(1))) {
        return new Blocking(c.first(), call.args().last(), name, "use an async HTTP client such as httpx.AsyncClient");
      }
      if (SESSIONS.contains(type) && SESSION_IO.contains(names.get(1))) {
        return new Blocking(c.first(), call.args().last(), name, "use an AsyncSession or a sync def endpoint");
      }
      return null;
    }
    if (fn.param(first) != null) {
      return null;
    }
    if (django && isManager(c) && ORM_IO.contains(c.lastName()) && c.endsWithCall()) {
      return new Blocking(c.first(), c.last(), first + ".objects" + (names.size() > 3 ? "..." : ".") + c.lastName() + "()",
        "use a" + c.lastName() + "() or sync_to_async");
    }
    if (head.equals("open") && !m.py().imports().containsKey("open") && m.function("open") == null) {
      return new Blocking(c.first(), call.args().last(), name, FILE_IO);
    }
    String resolved = imported(m, head);
    if (resolved == null) {
      return null;
    }
    if (HTTP.contains(resolved)) {
      return new Blocking(c.first(), call.args().last(), name, "use an async HTTP client such as httpx.AsyncClient");
    }
    List<Node> secs = Exprs.arg(call, 0, "secs");
    if (resolved.equals("time.sleep") && (secs == null || !Exprs.text(secs).equals("0"))) {
      return new Blocking(c.first(), call.args().last(), name, "use await asyncio.sleep()");
    }
    if (DRIVERS.contains(resolved)) {
      return new Blocking(c.first(), call.args().last(), name, "use an async driver or run the query with asyncio.to_thread");
    }
    if (PROCESSES.contains(resolved)) {
      return new Blocking(c.first(), call.args().last(), name, "use asyncio.create_subprocess_exec");
    }
    if (resolved.equals("pathlib.Path") && PATH_IO.contains(c.lastName()) && names.size() == 2 && c.endsWithCall()) {
      return new Blocking(c.first(), c.last(), head + "(...)." + c.lastName() + "()", FILE_IO);
    }
    return null;
  }

  /** {@code Item.objects...}: a Django manager of a class (capitalised name). */
  private static boolean isManager(Chain c) {
    List<Chain.Segment> s = c.segments();
    return s.size() > 2 && s.get(1) instanceof Chain.Name n && n.token().text().equals("objects")
      && Character.isUpperCase(c.firstName().charAt(0));
  }

  /** Local names bound to an HTTP client or a sync database session: parameters by annotation, assignments, with items. */
  private static Map<String, String> types(WebModel model, Function fn) {
    Module m = fn.module();
    Map<String, String> out = new HashMap<>();
    for (Function.Param p : fn.params()) {
      String t = annotationType(model, m, p.annotation());
      if (t != null && SESSIONS.contains(t)) {
        out.put(p.name(), t);
      }
    }
    for (PyStatement s : statements(fn.body())) {
      List<Node> nodes = s.nodes();
      if (s.keyword().equals("with") && !s.isAsync()) {
        for (List<Node> item : Nodes.split(nodes.subList(1, nodes.size() - 1), ",")) {
          int as = indexOf(item, "as");
          if (as > 0 && as == item.size() - 2) {
            client(m, item.subList(0, as), Nodes.leaf(item.get(as + 1)), out);
          }
        }
      } else if (s.body().isEmpty()) {
        List<List<Node>> parts = Exprs.assignment(nodes);
        if (parts.size() == 2 && parts.get(0).size() == 1) {
          client(m, parts.get(1), Nodes.leaf(parts.get(0).get(0)), out);
          // session = make_session(...) where the project function is declared -> Session
          Chain c = Exprs.chain(parts.get(1));
          Function maker = c != null && c.segments().size() == Exprs.headSize(c) + 1 && Exprs.firstCall(c) != null
            ? model.function(m, Exprs.head(c)) : null;
          String t = maker == null || maker.isAsync() ? null : annotationType(model, maker.module(), maker.returns());
          Token name = Nodes.leaf(parts.get(0).get(0));
          if (t != null && SESSIONS.contains(t) && name != null) {
            out.put(name.text(), t);
          }
        }
      }
    }
    return out;
  }

  private static void client(Module m, List<Node> value, Token name, Map<String, String> out) {
    Chain c = Exprs.chain(value);
    if (name != null && c != null && c.segments().size() == Exprs.headSize(c) + 1 && Exprs.firstCall(c) != null) {
      String t = imported(m, Exprs.head(c));
      if (t != null && CLIENTS.contains(t)) {
        out.put(name.text(), t);
      }
    }
  }

  /** The type an annotation names, through {@code Annotated[T, ...]} and a module-level alias of it. */
  private static String annotationType(WebModel model, Module m, List<Node> annotation) {
    for (int hop = 0; hop < 2 && !annotation.isEmpty(); hop++) {
      if (annotation.size() == 2 && Nodes.isIdent(annotation.get(0), "Annotated") && annotation.get(1) instanceof Node.Group g
        && !g.items().isEmpty()) {
        annotation = g.items().get(0);
      }
      String dotted = Exprs.dotted(annotation);
      if (dotted == null) {
        return null;
      }
      List<Node> alias = model.value(m, dotted);
      String t = imported(m, dotted);
      if (t != null && alias == null) {
        return t;
      }
      WebModel.Ref r = model.locate(m, dotted);
      if (alias == null || r == null) {
        return null;
      }
      m = r.module();
      annotation = alias;
    }
    return null;
  }

  /** A name through the imports of the module, or null when its first part is not imported. */
  static String imported(Module m, String dotted) {
    String first = dotted.contains(".") ? dotted.substring(0, dotted.indexOf('.')) : dotted;
    return m.py().imports().containsKey(first) && m.function(first) == null ? m.resolve(dotted) : null;
  }

  /** The project function a called name denotes from {@code fn}: self/cls methods, nested defs, module and imported functions. */
  static Function callee(WebModel model, Function fn, String head) {
    if (head.isEmpty() || fn.param(head.contains(".") ? head.substring(0, head.indexOf('.')) : head) != null
      && !head.startsWith("self.") && !head.startsWith("cls.")) {
      return null;
    }
    int dot = head.indexOf('.');
    if (dot > 0 && (head.startsWith("self.") || head.startsWith("cls."))) {
      return fn.owner() != null && head.indexOf('.', dot + 1) < 0 ? model.method(fn.owner(), head.substring(dot + 1)) : null;
    }
    if (dot < 0) {
      for (Function f : fn.module().functions()) {
        if (f.parent() != null && (f.parent() == fn || f.parent() == fn.parent()) && f.name().equals(head)) {
          return f;
        }
      }
    }
    return model.function(fn.module(), head);
  }

  /** No decorator that could change what calling the function does. */
  static boolean plain(Function f) {
    return f.decorators().stream().allMatch(d -> PLAIN_DECORATORS.contains(d.name()));
  }

  /** The statements of a body and their nested blocks, without nested defs and classes. */
  static List<PyStatement> statements(List<PyStatement> body) {
    List<PyStatement> out = new ArrayList<>();
    for (PyStatement s : body) {
      if (!s.keyword().equals("def") && !s.keyword().equals("class")) {
        out.add(s);
        out.addAll(statements(s.body()));
      }
    }
    return out;
  }

  /** The call chains of the function body that run in it, see {@link #usable}. */
  private static List<Chain> calls(Function fn) {
    List<Chain> out = new ArrayList<>();
    for (PyStatement s : statements(fn.body())) {
      out.addAll(usable(s));
    }
    return out;
  }

  /** Every call chain of the body, nested defs excepted. */
  private static List<Chain> allCalls(Function fn) {
    List<Chain> out = new ArrayList<>();
    for (PyStatement s : statements(fn.body())) {
      Chains.in(s.group()).stream().filter(c -> Exprs.firstCall(c) != null).forEach(out::add);
    }
    return out;
  }

  /**
   * The chains of one line that run synchronously there: not awaited, not inside a lambda, not in the arguments of a
   * thread wrapper or of run_in_executor.
   */
  private static List<Chain> usable(PyStatement s) {
    List<Token[]> spans = new ArrayList<>();
    Map<Node.Group, Boolean> seen = new IdentityHashMap<>();
    List<Chain> all = Chains.in(s.group());
    Nodes.groups(s.group(), g -> {
      List<Node> kids = g.children();
      for (int i = 0; i < kids.size(); i++) {
        if (Nodes.isIdent(kids.get(i), "lambda")) {
          int end = i;
          while (end + 1 < kids.size() && !Nodes.isLeaf(kids.get(end + 1), ",")) {
            end++;
          }
          spans.add(new Token[] {kids.get(i).first(), kids.get(end).last()});
        }
      }
    });
    for (Chain c : all) {
      Chain.Call call = Exprs.firstCall(c);
      if (call != null && seen.put(call.args(), true) == null && wrapper(c)) {
        spans.add(new Token[] {call.args().first(), call.args().last()});
      }
    }
    List<Chain> out = new ArrayList<>();
    for (Chain c : all) {
      if (Exprs.firstCall(c) != null && !c.precededBy("await") && spans.stream().noneMatch(sp -> inside(c.first(), sp))) {
        out.add(c);
      }
    }
    return out;
  }

  private static boolean wrapper(Chain c) {
    String head = Exprs.head(c);
    return WRAPPERS.contains(head.substring(head.lastIndexOf('.') + 1));
  }

  private static boolean inside(Token t, Token[] span) {
    return after(t, span[0]) && after(span[1], t);
  }

  /** {@code a} at or after {@code b}. */
  private static boolean after(Token a, Token b) {
    return a.line() > b.line() || a.line() == b.line() && a.column() >= b.column();
  }

  private static int indexOf(List<Node> nodes, String ident) {
    for (int i = 0; i < nodes.size(); i++) {
      if (Nodes.isIdent(nodes.get(i), ident)) {
        return i;
      }
    }
    return -1;
  }
}
