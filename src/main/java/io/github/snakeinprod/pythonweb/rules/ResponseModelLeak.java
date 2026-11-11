package io.github.snakeinprod.pythonweb.rules;

import io.github.snakeinprod.pythonweb.lang.python.PyStatement;
import io.github.snakeinprod.pythonweb.model.Decorator;
import io.github.snakeinprod.pythonweb.model.Endpoint;
import io.github.snakeinprod.pythonweb.model.Exprs;
import io.github.snakeinprod.pythonweb.model.Framework;
import io.github.snakeinprod.pythonweb.model.Function;
import io.github.snakeinprod.pythonweb.model.Module;
import io.github.snakeinprod.pythonweb.model.PyClass;
import io.github.snakeinprod.pythonweb.model.WebModel;
import io.github.snakeinprod.pythonweb.parse.Chain;
import io.github.snakeinprod.pythonweb.parse.Chains;
import io.github.snakeinprod.pythonweb.parse.Node;
import io.github.snakeinprod.pythonweb.parse.Nodes;
import io.github.snakeinprod.pythonweb.parse.Token;
import io.github.snakeinprod.pythonweb.parse.TokenKind;
import io.github.snakeinprod.pythonweb.taint.Step;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * A FastAPI endpoint whose response carries a password or secret field: its response_model (or return annotation) is
 * a project class with such a field, or it has none and returns an object of such a class (loaded with
 * {@code db.get(User, id)}, {@code db.query(User)...}, {@code select(User)}, {@code User.objects...}, built with
 * {@code User(...)}, a dependency parameter typed User, a project function returning one) or a dict whose password
 * key is read from an object. Silent on anything it cannot follow.
 */
public class ResponseModelLeak implements PwRule {

  /** A class field that must not reach a client. */
  private static final Pattern SECRET_FIELD = Pattern.compile("(?i)password|passwd|secret|private_key|^hashed_|_hash$");
  private static final Pattern NOT_SECRET = Pattern.compile("(?i)^(has|is|must|requires?|needs?|show|use)_|"
    + "_(at|on|date|changed|updated|expires|expiry|expiration|set|required|length|policy|hint|sent|count|enabled)$|^(content|file|commit)_hash$");
  /** A dict key that is a stored password. */
  private static final Pattern SECRET_KEY = Pattern.compile("(?i)password|passwd|hashed_pw|pwd_hash|password_digest");
  private static final Set<String> VERBS = Set.of("get", "post", "put", "patch", "delete", "api_route");
  private static final Set<String> LOADERS = Set.of("get", "query", "select", "get_or_404", "first_or_404", "one_or_404", "get_one");
  private static final Set<String> NARROWING = Set.of("count", "exists", "delete", "update", "values", "values_list", "only", "defer",
    "with_entities", "load_only", "aggregate", "scalar_subquery", "columns");
  private static final Set<String> DUMPS = Set.of("dict", "model_dump", "__dict__");

  /** What leaks: the returned class (or null for a dict) and the secret field or key. */
  private record Leak(String what, String field, Step at) {
  }

  @Override
  public void check(RuleContext ctx) {
    WebModel model = ctx.model();
    Set<Function> seen = new LinkedHashSet<>();
    for (Endpoint e : model.endpoints()) {
      Function f = e.function();
      if (e.framework() != Framework.FASTAPI || e.module() != ctx.module() || f == null || !seen.add(f)) {
        continue;
      }
      Decorator route = f.decorators().stream().filter(d -> d.call() != null && VERBS.contains(d.last())).findFirst().orElse(null);
      Map<String, List<Node>> kw = route == null ? Map.of() : Exprs.kwargs(route.call());
      if (route == null || kw.containsKey("response_model_exclude") || kw.containsKey("response_model_include")
        || kw.containsKey("response_class")) {
        continue;
      }
      String where = String.join("|", e.methods()) + " " + e.path();
      List<Node> declared = kw.get("response_model");
      if (declared == null || !"None".equals(Exprs.text(declared))) {
        List<Node> annotation = declared != null ? declared : returnAnnotation(f);
        if (annotation != null) {
          List<PyClass> classes = classes(model, f.module(), annotation);
          Leak leak = classes.stream().map(c -> secret(model, c)).filter(l -> l != null).findFirst().orElse(null);
          if (leak != null) {
            ctx.report(annotation.get(0).first(), annotation.get(annotation.size() - 1).last(), where + " responds with " + leak.what()
              + ", which has the field " + leak.field() + ": use a response model without it.", List.of(leak.at()));
          }
          if (leak != null || !classes.isEmpty() || !Exprs.text(annotation).matches("(typing\\.)?(dict|Dict|Any|Mapping)\\b.*")) {
            continue;
          }
        }
      }
      for (PyStatement r : returns(f.body(), new ArrayList<>())) {
        Leak leak = classify(model, f, value(r), 0);
        if (leak != null) {
          String text = leak.what() == null ? " returns the key " + leak.field()
            : " returns " + leak.what() + " with its field " + leak.field();
          ctx.report(r.first(), r.last(), where + text + " and has no response_model: declare one without it.", List.of(leak.at()));
        }
      }
    }
  }

  /** The return statements of a body, nested defs and classes left out. */
  private static List<PyStatement> returns(List<PyStatement> body, List<PyStatement> out) {
    for (PyStatement s : body) {
      String kw = s.keyword();
      if (kw.equals("return") && s.nodes().size() > 1) {
        out.add(s);
      } else if (!kw.equals("def") && !kw.equals("class")) {
        returns(s.body(), out);
      }
    }
    return out;
  }

  /** The returned expression without "return" and "await". */
  private static List<Node> value(PyStatement r) {
    List<Node> v = r.nodes().subList(1, r.nodes().size());
    return !v.isEmpty() && Nodes.isIdent(v.get(0), "await") ? v.subList(1, v.size()) : v;
  }

  private static List<Node> returnAnnotation(Function f) {
    List<Node> nodes = f.def().nodes();
    for (int i = 0; i < nodes.size(); i++) {
      if (Nodes.isLeaf(nodes.get(i), "->")) {
        int end = Nodes.isLeaf(nodes.get(nodes.size() - 1), ":") ? nodes.size() - 1 : nodes.size();
        return end > i + 1 ? nodes.subList(i + 1, end) : null;
      }
    }
    return null;
  }

  /** The project classes named in a type expression: {@code User}, {@code list[schemas.User]}, {@code Optional[User]}. */
  private static List<PyClass> classes(WebModel model, Module m, List<Node> type) {
    List<PyClass> out = new ArrayList<>();
    for (Chain c : Chains.in(new Node.Group(null, null, type))) {
      PyClass k = model.cls(m, Exprs.head(c));
      if (k != null && !out.contains(k)) {
        out.add(k);
      }
    }
    return out;
  }

  /** What the returned expression leaks, or null when it leaks nothing or cannot be followed. */
  private Leak classify(WebModel model, Function f, List<Node> expr, int depth) {
    if (depth > 3 || expr.isEmpty()) {
      return null;
    }
    Module m = f.module();
    if (expr.size() == 1 && expr.get(0) instanceof Node.Group g && g.is("{")) {
      for (List<Node> item : g.items()) {
        List<List<Node>> kv = Nodes.split(item, ":");
        String key = kv.size() == 2 ? Exprs.string(kv.get(0)) : null;
        String v = kv.size() == 2 ? Exprs.text(kv.get(1)) : "";
        if (key != null && SECRET_KEY.matcher(key).find() && (v.contains(".") || v.contains("["))) {
          return new Leak(null, "\"" + key + "\"", new Step(m, kv.get(0).get(0).first(), "the password read here"));
        }
      }
      return null;
    }
    Chain c = Exprs.chain(expr);
    if (c == null) {
      return null;
    }
    String head = Exprs.head(c);
    String first = c.firstName();
    Chain.Call call = Exprs.firstCall(c);
    // jsonable_encoder(user), vars(user), dict(user)
    if (call != null && Set.of("jsonable_encoder", "vars", "dict").contains(head) && c.segments().size() == 2) {
      List<Node> arg = Exprs.arg(call, 0, null);
      return arg == null ? null : classify(model, f, arg, depth + 1);
    }
    boolean whole = c.segments().size() == 1 || c.segments().size() <= 3 && c.names().size() == 2 && DUMPS.contains(c.names().get(1))
      && (c.segments().size() == 2 || c.endsWithCall());
    Function.Param p = whole ? f.param(first) : null;
    if (p != null) {
      for (PyClass k : classes(model, m, p.annotation())) {
        Leak l = secret(model, k);
        if (l != null) {
          return l;
        }
      }
      return null;
    }
    List<List<Node>> assigned = whole ? assignments(f, first) : List.of();
    if (!assigned.isEmpty()) {
      if (assigned.size() != 1) {
        return null;
      }
      List<Node> v = assigned.get(0);
      return classify(model, f, !v.isEmpty() && Nodes.isIdent(v.get(0), "await") ? v.subList(1, v.size()) : v, depth + 1);
    }
    if (c.names().stream().anyMatch(NARROWING::contains) || !c.endsWithCall()) {
      return null;
    }
    PyClass k = model.cls(m, head.contains(".") && model.cls(m, head) == null ? first : head);
    if (k != null && !c.calls().isEmpty()) {
      return secret(model, k);
    }
    Leak loaded = loaded(model, m, c);
    if (loaded != null) {
      return loaded;
    }
    Function callee = call != null && c.segments().size() == Exprs.headSize(c) + 1 ? model.function(m, head) : null;
    if (callee != null && callee != f) {
      for (PyStatement r : returns(callee.body(), new ArrayList<>())) {
        Leak l = classify(model, callee, value(r), depth + 1);
        if (l != null) {
          return l;
        }
      }
    }
    return null;
  }

  /** {@code db.get(User, id)}, {@code db.query(User).first()}, {@code session.exec(select(User)).first()}. */
  private static Leak loaded(WebModel model, Module m, Chain c) {
    List<Chain.Segment> segs = c.segments();
    for (int i = 1; i < segs.size(); i++) {
      if (!(segs.get(i) instanceof Chain.Call call) || !(segs.get(i - 1) instanceof Chain.Name n)) {
        continue;
      }
      List<Node> arg = Exprs.arg(call, 0, null);
      if (arg == null) {
        continue;
      }
      String dotted = Exprs.dotted(arg);
      if (dotted != null && LOADERS.contains(n.token().text())) {
        PyClass k = model.cls(m, dotted);
        return k == null ? null : secret(model, k);
      }
      Chain inner = Exprs.chain(arg);
      if (inner != null && inner.names().stream().noneMatch(NARROWING::contains)) {
        Leak l = loaded(model, m, inner);
        if (l != null) {
          return l;
        }
      }
    }
    return null;
  }

  /** The values assigned to a plain local name in the function (nested defs left out). */
  private static List<List<Node>> assignments(Function f, String name) {
    List<List<Node>> out = new ArrayList<>();
    collect(f.body(), name, out);
    return out;
  }

  private static void collect(List<PyStatement> body, String name, List<List<Node>> out) {
    for (PyStatement s : body) {
      String kw = s.keyword();
      if (kw.equals("def") || kw.equals("class")) {
        continue;
      }
      if (s.body().isEmpty()) {
        List<List<Node>> parts = Exprs.assignment(s.nodes());
        for (int i = 0; i + 1 < parts.size(); i++) {
          List<Node> target = Exprs.unannotated(parts.get(i));
          if (name.equals(Exprs.dotted(target))) {
            out.add(parts.get(parts.size() - 1));
          } else if (Exprs.text(target).matches("(.*,)?" + Pattern.quote(name) + "(,.*)?")) {
            out.add(List.of());
          }
        }
      } else if (Exprs.text(s.nodes()).matches("(?s)(for|with|async)\\b.*\\b" + Pattern.quote(name) + "\\b.*")) {
        out.add(List.of());
      }
      collect(s.body(), name, out);
    }
  }

  /** The first secret field of a class or its project bases, or null; SecretStr, excluded and deferred fields do not count. */
  private static Leak secret(WebModel model, PyClass c) {
    List<PyClass> hierarchy = model.hierarchy(c);
    if (hierarchy.stream().anyMatch(k -> k.method("dict") != null || k.method("model_dump") != null || k.method("__iter__") != null)) {
      return null;
    }
    for (PyClass k : hierarchy) {
      for (PyStatement s : k.statement().body()) {
        List<Node> nodes = s.nodes();
        Token name = nodes.size() > 1 ? Nodes.leaf(nodes.get(0)) : null;
        if (!s.body().isEmpty() || name == null || name.kind() != TokenKind.IDENT
          || !Nodes.isLeaf(nodes.get(1), ":") && !Nodes.isLeaf(nodes.get(1), "=")) {
          continue;
        }
        String rest = Exprs.text(nodes.subList(2, nodes.size()));
        if (SECRET_FIELD.matcher(name.text()).find() && !NOT_SECRET.matcher(name.text()).find()
          && !rest.matches("(?s).*(Secret(Str|Bytes)|exclude=True|deferred\\(|deferred=True).*")) {
          return new Leak(c.name(), name.text(), new Step(k.module(), name, name.text() + " is a field of " + k.name()));
        }
      }
    }
    return null;
  }
}
