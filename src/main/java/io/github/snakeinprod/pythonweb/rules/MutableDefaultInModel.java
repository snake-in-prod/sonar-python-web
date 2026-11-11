package io.github.snakeinprod.pythonweb.rules;

import io.github.snakeinprod.pythonweb.lang.python.PyStatement;
import io.github.snakeinprod.pythonweb.model.Decorator;
import io.github.snakeinprod.pythonweb.model.Endpoint;
import io.github.snakeinprod.pythonweb.model.Exprs;
import io.github.snakeinprod.pythonweb.model.Framework;
import io.github.snakeinprod.pythonweb.model.Function;
import io.github.snakeinprod.pythonweb.model.Module;
import io.github.snakeinprod.pythonweb.model.PyClass;
import io.github.snakeinprod.pythonweb.parse.Chain;
import io.github.snakeinprod.pythonweb.parse.Chains;
import io.github.snakeinprod.pythonweb.parse.Node;
import io.github.snakeinprod.pythonweb.parse.Nodes;
import io.github.snakeinprod.pythonweb.parse.Token;
import io.github.snakeinprod.pythonweb.parse.TokenKind;
import io.github.snakeinprod.pythonweb.taint.Step;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * A [] or {} default that is one object for every instance or request: a Django or Flask endpoint parameter that the
 * body changes, an attrs field, a Django JSONField / ArrayField / HStoreField default (in any model: AbstractUser and
 * third-party bases too), or a stdlib dataclass field
 * (which fails at import). Pydantic models and FastAPI parameters copy their defaults, so they are left alone.
 */
public class MutableDefaultInModel implements PwRule {

  private static final Set<String> MUTATORS = Set.of("append", "extend", "insert", "remove", "pop", "clear", "sort", "reverse",
    "update", "setdefault", "popitem", "add", "discard", "difference_update", "intersection_update", "symmetric_difference_update");
  private static final Set<String> AUGMENTED = Set.of("+=", "|=", "-=", "&=", "^=", "*=");
  private static final Set<String> MUTABLE_CALLS = Set.of("list", "dict", "set", "bytearray", "collections.defaultdict",
    "collections.OrderedDict", "collections.Counter", "collections.deque");
  /** attrs decorators that infer auto_attribs (annotated attributes are fields). */
  private static final Set<String> ATTRS_AUTO = Set.of("attr.define", "attr.mutable", "attr.frozen", "attr.dataclass",
    "attrs.define", "attrs.mutable", "attrs.frozen");
  private static final Set<String> ATTRS_CLASSIC = Set.of("attr.s", "attr.attrs", "attrs.attrs");
  private static final Set<String> ATTRS_FIELD = Set.of("attr.ib", "attr.attrib", "attr.field", "attrs.field");
  private static final Set<String> DJANGO_CONTAINER_FIELDS = Set.of("JSONField", "ArrayField", "HStoreField");
  private static final Pattern NOT_A_FIELD = Pattern.compile("^(\\w+\\.)*(ClassVar|InitVar)\\b.*");

  private enum Kind { NONE, DATACLASS, ATTRS, ATTRS_AUTO, DJANGO }

  @Override
  public void check(RuleContext ctx) {
    for (Function f : ctx.module().functions()) {
      endpointDefaults(ctx, f);
    }
    for (PyClass c : ctx.module().classes()) {
      fieldDefaults(ctx, c);
    }
  }

  private static void endpointDefaults(RuleContext ctx, Function f) {
    // FastAPI deep-copies the defaults of the parameters it fills; Django and Flask call the view with the default itself
    Endpoint e = ctx.model().endpointsOf(f).stream().filter(x -> x.framework() != Framework.FASTAPI).findFirst().orElse(null);
    if (e == null) {
      return;
    }
    for (Function.Param p : f.params()) {
      String kind = p.stars() == 0 ? mutable(p.defaultValue(), f.module()) : null;
      Token changed = kind == null ? null : mutation(f, p.name());
      if (changed != null) {
        ctx.report(p.token(), p.token(), "Default " + kind + " of parameter " + p.name() + " of " + String.join("|", e.methods()) + " " + e.path()
            + " is one object shared by every request; default to None and create it in the body.",
          List.of(new Step(f.module(), changed, "changed here, for every later request")));
      }
    }
  }

  private static void fieldDefaults(RuleContext ctx, PyClass c) {
    Module m = c.module();
    Kind kind = kind(ctx, c);
    if (kind == Kind.NONE) {
      return;
    }
    if (kind == Kind.ATTRS_AUTO && unannotatedAttrsField(c)) {
      // attrs then takes only attr.ib() / field() assignments as fields: annotated values are class variables
      kind = Kind.ATTRS;
    }
    for (PyStatement s : c.statement().body()) {
      List<List<Node>> parts = Exprs.assignment(s.nodes());
      if (!s.body().isEmpty() || parts.size() != 2) {
        continue;
      }
      List<Node> target = parts.get(0);
      List<Node> bare = Exprs.unannotated(target);
      String name = Exprs.dotted(bare);
      if (name == null || name.contains(".")) {
        continue;
      }
      boolean annotated = bare.size() < target.size();
      if (annotated && NOT_A_FIELD.matcher(Exprs.text(target.subList(bare.size() + 1, target.size()))).matches()) {
        continue;
      }
      List<Node> value = parts.get(1);
      String literal = mutable(value, m);
      if (literal != null && annotated && kind == Kind.DATACLASS) {
        reportImport(ctx, value, literal, c);
      } else if (literal != null && annotated && kind == Kind.ATTRS_AUTO) {
        reportShared(ctx, value, literal, c, "attrs.field(factory=" + factory(value, literal) + ")");
      } else if (literal == null) {
        fieldCall(ctx, c, kind, annotated, value);
      }
    }
  }

  /** {@code field(default=[])}, {@code attr.ib([])}, {@code models.JSONField(default={})}. */
  private static void fieldCall(RuleContext ctx, PyClass c, Kind kind, boolean annotated, List<Node> value) {
    Chain chain = Exprs.chain(value);
    Chain.Call call = chain == null ? null : Exprs.firstCall(chain);
    if (call == null || Exprs.headSize(chain) + 1 != chain.segments().size()) {
      return;
    }
    String callee = c.module().resolve(Exprs.head(chain));
    String last = callee.substring(callee.lastIndexOf('.') + 1);
    List<Node> dflt = callee.startsWith("attr.") && !callee.equals("attr.field") ? Exprs.arg(call, 0, "default") : Exprs.kwargs(call).get("default");
    String literal = dflt == null ? null : mutable(dflt, c.module());
    if (literal == null) {
      return;
    }
    if (kind == Kind.DATACLASS && annotated && callee.equals("dataclasses.field")) {
      reportImport(ctx, dflt, literal, c);
    } else if ((kind == Kind.ATTRS || kind == Kind.ATTRS_AUTO) && ATTRS_FIELD.contains(callee)) {
      reportShared(ctx, dflt, literal, c, "factory=" + factory(dflt, literal));
    } else if (kind == Kind.DJANGO && callee.startsWith("django.") && DJANGO_CONTAINER_FIELDS.contains(last)) {
      reportShared(ctx, dflt, literal, c, "default=" + factory(dflt, literal));
    }
  }

  private static void reportImport(RuleContext ctx, List<Node> value, String literal, PyClass c) {
    ctx.report(value.get(0).first(), "This " + literal + " default makes the dataclass " + c.name()
      + " raise ValueError at import; use field(default_factory=" + factory(value, literal) + ").");
  }

  private static void reportShared(RuleContext ctx, List<Node> value, String literal, PyClass c, String fix) {
    ctx.report(value.get(0).first(), "This " + literal + " default is one object shared by every " + c.name() + "; use " + fix + ".");
  }

  /** The type name for an empty literal ({@code list}), else a hint to write a function. */
  private static String factory(List<Node> value, String literal) {
    boolean empty = value.size() == 1 && value.get(0) instanceof Node.Group g ? g.children().isEmpty()
      : value.size() == 2 && value.get(1) instanceof Node.Group g2 && g2.children().isEmpty();
    return empty ? literal : "a function building it";
  }

  private static Kind kind(RuleContext ctx, PyClass c) {
    for (Decorator d : c.decorators()) {
      if (d.resolved().equals("dataclasses.dataclass")) {
        return Kind.DATACLASS;
      }
      if (ATTRS_AUTO.contains(d.resolved())) {
        return Kind.ATTRS_AUTO;
      }
      if (ATTRS_CLASSIC.contains(d.resolved())) {
        List<Node> auto = d.call() == null ? null : Exprs.kwargs(d.call()).get("auto_attribs");
        return auto != null && Exprs.text(auto).equals("True") ? Kind.ATTRS_AUTO : Kind.ATTRS;
      }
    }
    // any class with a base may be a model (AbstractUser, a third-party or project base): only Django's container
    // fields are checked there
    return c.bases().isEmpty() ? Kind.NONE : Kind.DJANGO;
  }

  private static boolean unannotatedAttrsField(PyClass c) {
    for (Map.Entry<String, List<Node>> a : c.attributes().entrySet()) {
      Chain chain = Exprs.chain(a.getValue());
      if (chain != null && ATTRS_FIELD.contains(c.module().resolve(Exprs.head(chain)))) {
        for (PyStatement s : c.statement().body()) {
          List<Node> target = Exprs.assignment(s.nodes()).get(0);
          if (a.getKey().equals(Exprs.dotted(target))) {
            return true;
          }
        }
      }
    }
    return false;
  }

  /** "list", "dict", "set" or the factory called, for a value that is a new mutable object; null otherwise. */
  static String mutable(List<Node> value, Module m) {
    if (value.size() == 1 && value.get(0) instanceof Node.Group g) {
      if (g.is("[")) {
        return "list";
      }
      if (g.is("{")) {
        return g.children().isEmpty() || g.children().stream().anyMatch(n -> Nodes.isLeaf(n, ":") || Nodes.isLeaf(n, "**")) ? "dict" : "set";
      }
      return null;
    }
    Chain chain = Exprs.chain(value);
    if (chain == null || Exprs.firstCall(chain) == null || Exprs.headSize(chain) + 1 != chain.segments().size()) {
      return null;
    }
    String head = Exprs.head(chain);
    String resolved = m.resolve(head);
    return MUTABLE_CALLS.contains(resolved) && (head.contains(".") || !resolved.equals(head) || m.function(head) == null && m.cls(head) == null)
      ? head.substring(head.lastIndexOf('.') + 1) : null;
  }

  /**
   * Where the body changes the parameter in place ({@code p.append(x)}, {@code p[k] = v}, {@code p += x}, {@code del p[k]}),
   * or null; null also when the body rebinds the name anywhere, since the change may then be on a new object.
   */
  private static Token mutation(Function f, String name) {
    Token found = null;
    for (PyStatement top : f.body()) {
      for (PyStatement s : top.walk()) {
        if (rebinds(s, name)) {
          return null;
        }
        if (found == null) {
          found = change(s, name);
        }
      }
    }
    return found;
  }

  private static Token change(PyStatement s, String name) {
    Node.Group line = s.group();
    for (Chain c : Chains.in(line)) {
      List<Chain.Segment> segs = c.segments();
      if (!c.firstName().equals(name)) {
        continue;
      }
      if (segs.size() >= 3 && segs.get(1) instanceof Chain.Name n && MUTATORS.contains(n.token().text()) && segs.get(2) instanceof Chain.Call) {
        return n.token();
      }
      Node after = c.after();
      boolean assigned = after instanceof Node.Leaf l && l.token().kind() == TokenKind.OP && (l.token().is("=") || AUGMENTED.contains(l.token().text()));
      if (segs.size() == 2 && segs.get(1) instanceof Chain.Index && (assigned || c.precededBy("del"))) {
        return c.first();
      }
      if (segs.size() == 1 && c.container() == line &&c.from() == 0 && after instanceof Node.Leaf l2 && AUGMENTED.contains(l2.token().text())) {
        return c.first();
      }
    }
    return null;
  }

  /** {@code p = ...}, {@code a, p = ...}, {@code for p in}, {@code with ... as p}, {@code global p}, {@code del p}. */
  static boolean rebinds(PyStatement s, String name) {
    List<Node> nodes = s.nodes();
    String kw = s.keyword();
    int i = s.isAsync() ? 1 : 0;
    if (kw.equals("for")) {
      for (int k = i + 1; k < nodes.size() && !Nodes.isIdent(nodes.get(k), "in"); k++) {
        if (Nodes.tokens(nodes.get(k)).stream().anyMatch(t -> t.isIdent(name))) {
          return true;
        }
      }
      return false;
    }
    if (kw.equals("with") || kw.equals("except")) {
      for (int k = 0; k + 1 < nodes.size(); k++) {
        if (Nodes.isIdent(nodes.get(k), "as") && Nodes.isIdent(nodes.get(k + 1), name)) {
          return true;
        }
      }
      return false;
    }
    if (kw.equals("global") || kw.equals("nonlocal")) {
      return nodes.stream().anyMatch(n -> Nodes.isIdent(n, name));
    }
    if (kw.equals("del")) {
      return nodes.size() == 2 && Nodes.isIdent(nodes.get(1), name);
    }
    List<List<Node>> parts = Exprs.assignment(nodes);
    for (List<Node> target : parts.subList(0, parts.size() - 1)) {
      List<Node> bare = Exprs.unannotated(target);
      if (name.equals(Exprs.dotted(bare))) {
        return true;
      }
      for (List<Node> item : Nodes.split(bare, ",")) {
        if (item.size() == 1 && Nodes.isIdent(item.get(0), name)) {
          return true;
        }
      }
    }
    for (int k = 0; k + 1 < nodes.size(); k++) {
      if (Nodes.isIdent(nodes.get(k), name) && Nodes.isLeaf(nodes.get(k + 1), ":=")) {
        return true;
      }
    }
    return false;
  }
}
