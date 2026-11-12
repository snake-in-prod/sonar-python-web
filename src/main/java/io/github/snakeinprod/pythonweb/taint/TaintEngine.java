package io.github.snakeinprod.pythonweb.taint;

import io.github.snakeinprod.pythonweb.lang.python.PyStatement;
import io.github.snakeinprod.pythonweb.lang.python.PythonLexer;
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
import io.github.snakeinprod.pythonweb.parse.TreeBuilder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Inter-procedural taint analysis from request inputs to sinks. Each project function gets a {@link Summary}
 * (parameters to return value, parameters to sinks, inputs it returns), computed over all functions until no summary
 * changes or {@link #MAX_ROUNDS} rounds; a last pass then records the findings. Within a function: statements in order,
 * {@code if} / {@code try} branches analysed apart and joined, loop bodies twice; assignments, f-strings, %, +, join
 * and format, containers, attribute and subscript reads, mutating calls ({@code parts.append(x)}) and returns carry
 * taint; a call of an unknown function does not, unless the models list it as a propagator.
 * <p>ponytail: every round re-analyses every function; a worklist of the callers of changed summaries if this shows
 * in profiles. Guards clear a variable for the rest of the function, whichever branch they guard.
 */
public final class TaintEngine {

  public static final int MAX_ROUNDS = 8;

  private static final Set<String> COMPARISONS = Set.of("==", "!=", "<", ">", "<=", ">=");
  private static final Set<String> AUGMENTED = Set.of("+=", "-=", "*=", "/=", "%=", "|=", "&=", "^=", "//=", "@=");
  private static final Set<String> SKIPPED = Set.of("pass", "break", "continue", "global", "nonlocal", "import", "from", "del");
  private static final Set<String> SCALARS = Set.of("int", "float", "bool", "Decimal", "UUID", "UUID1", "UUID3", "UUID4",
    "UUID5", "date", "datetime", "time", "timedelta", "conint", "confloat", "condecimal", "PositiveInt", "NegativeInt",
    "NonNegativeInt", "NonPositiveInt", "PositiveFloat", "NegativeFloat", "NonNegativeFloat", "NonPositiveFloat", "StrictInt",
    "StrictFloat", "StrictBool");
  private static final Pattern PATH_PARAM = Pattern.compile("<(?:(\\w+)(?:\\([^>]*\\))?:)?(\\w+)>|\\{(\\w+)(?::\\w+)?}");
  /** A literal start that fixes where a URL goes: "https://host/", "/items/", "?q=", "&page=", "items/". */
  private static final Pattern FIXED_TARGET = Pattern.compile("^(?:[A-Za-z][A-Za-z0-9+.-]*://[^/?#\\\\@\\s]+[/?#]|/[^/\\\\]|[?#&]|[\\w.-]+/)");
  private static final Set<String> URL_KINDS = Set.of("ssrf", "redirect");
  /** The name of a value or call giving a URL's fixed start: BASE_URL, get_public_root_url, api_host, self.endpoint. */
  private static final Pattern URL_BASE = Pattern.compile("(?i)(url|uri|root|base|host|domain|origin|endpoint)$");
  /** A Django regex route's group, named or positional, and a group body matching digits only. */
  private static final Pattern REGEX_GROUP = Pattern.compile("\\((?!\\?[:=!<])(?:\\?P<(\\w+)>)?((?:[^()\\\\]|\\\\.)*)\\)");
  private static final Pattern DIGITS = Pattern.compile("(\\\\d|\\[0-9]|\\[\\\\d])(\\+|\\*|\\{\\d+(,\\d*)?})?");
  /** A project helper named for making a path safe: clean_path(p), safe_filename(n). */
  private static final Pattern PATH_CLEANER = Pattern.compile("(?i)^_?(clean|safe|sanitize|secure)_?(path|file_?name|filename|dir)");
  /** A validation helper: validate_jobid(x), is_valid_name(x), is_safe_path(x), sanitize(x), assert_local_path(x). */
  private static final Pattern VALIDATOR = Pattern.compile("^_?(validate|is_valid|valid_|is_safe|sanitize|verify_|assert_|ensure_)");

  private final WebModel model;
  private final TaintModels models;
  private final Map<Function, Summary> summaries = new IdentityHashMap<>();
  private final Map<Function, Set<Function>> callers = new IdentityHashMap<>();
  private final Map<String, Finding> findings = new LinkedHashMap<>();
  /** Request data a method stores on {@code self}, by class and attribute: what the other methods of the class read. */
  private final Map<PyClass, Map<String, Taint>> attributes = new IdentityHashMap<>();
  /**
   * What {@code __init__} stores on {@code self} from its parameters, by class and attribute: parameter origins (indexes
   * count self). Dataclass and attrs classes get one from their fields.
   */
  private final Map<PyClass, Map<String, Taint>> ctorAttributes = new IdentityHashMap<>();
  /** The generated {@code __init__}'s parameter names (self excluded) of a dataclass or attrs class. */
  private final Map<PyClass, List<String>> fieldParams = new IdentityHashMap<>();
  /** Attribute names to ids: {@code self.url} in a method is the pseudo parameter {@code ATTR + id} of its summary. */
  private final Map<String, Integer> attrIds = new HashMap<>();
  private final Map<PyClass, List<PyClass>> subclasses = new IdentityHashMap<>();
  private final Map<PyClass, Set<PyClass>> related = new IdentityHashMap<>();
  private final Map<Module, Map<String, java.util.Optional<PyClass>>> classes = new IdentityHashMap<>();
  /** Parameter indexes from here on are attributes of the receiver, not arguments. */
  static final int ATTR = 10_000;
  private static final Set<String> DATACLASSES = Set.of("dataclasses.dataclass", "pydantic.dataclasses.dataclass", "attr.s",
    "attr.attrs", "attr.define", "attr.frozen", "attr.mutable", "attr.dataclass", "attrs.define", "attrs.frozen", "attrs.mutable");
  private static final Pattern ATTRS_FIELD = Pattern.compile("(attr\\.ib|attr\\.attrib|attrib|attrs\\.field|attr\\.field|field)\\(.*");

  private TaintEngine(WebModel model, TaintModels models) {
    this.model = model;
    this.models = models;
  }

  public static TaintResult run(WebModel model, TaintModels models) {
    return new TaintEngine(model, models).run();
  }

  private TaintResult run() {
    List<Function> functions = new ArrayList<>();
    model.modules().stream().filter(m -> !m.isTest()).forEach(m -> functions.addAll(m.functions()));
    for (Module m : model.modules()) {
      for (PyClass c : m.isTest() ? List.<PyClass>of() : m.classes()) {
        for (PyClass b : model.hierarchy(c)) {
          if (b != c) {
            subclasses.computeIfAbsent(b, x -> new ArrayList<>()).add(c);
          }
        }
        fields(c);
      }
    }
    for (int round = 0; round < MAX_ROUNDS; round++) {
      String attrs = attributeSignature();
      boolean changed = false;
      for (Function f : functions) {
        Summary s = new Analysis(f, false).run();
        Summary old = summaries.put(f, s);
        changed |= old == null ? !s.signature().equals(Summary.EMPTY.signature()) : !old.signature().equals(s.signature());
      }
      if (!changed && attrs.equals(attributeSignature())) {
        break;
      }
    }
    for (Function f : functions) {
      new Analysis(f, true).run();
    }
    List<Finding> out = new ArrayList<>();
    for (Finding f : findings.values()) {
      out.add(new Finding(f.kind(), f.sinkName(), f.label(), f.source(), f.sink(), f.path(), f.function(), endpoint(f.function())));
    }
    return new TaintResult(List.copyOf(out), Map.copyOf(summaries));
  }

  /** The stored attributes without the paths: like {@link Summary#signature()}, for the fixpoint. */
  private String attributeSignature() {
    Set<String> out = new java.util.TreeSet<>();
    attributes.forEach((c, as) -> as.forEach((a, t) -> t.flows().forEach((o, f) ->
      out.add(c.module().path() + c.name() + "." + a + o.label() + o.source() + new java.util.TreeSet<>(f.cleared())))));
    ctorAttributes.forEach((c, as) -> as.forEach((a, t) -> t.flows().forEach((o, f) ->
      out.add("i" + c.module().path() + c.name() + "." + a + o.param() + new java.util.TreeSet<>(f.cleared())))));
    return out.toString();
  }

  /** The class, its project base classes and its subclasses: whose methods may run on the same instance. */
  private Set<PyClass> related(PyClass c) {
    return related.computeIfAbsent(c, k -> {
      Set<PyClass> out = java.util.Collections.newSetFromMap(new IdentityHashMap<>());
      out.addAll(model.hierarchy(k));
      out.addAll(subclasses.getOrDefault(k, List.of()));
      return out;
    });
  }

  private int attrId(String attr) {
    return attrIds.computeIfAbsent(attr, a -> attrIds.size());
  }

  /**
   * A {@code @dataclass} or attrs class without its own {@code __init__}: its fields (annotated class attributes,
   * {@code attr.ib()}), project base classes' first, are the generated {@code __init__}'s parameters and attributes.
   */
  private void fields(PyClass c) {
    if (c.method("__init__") != null || c.decorators().stream().noneMatch(d -> DATACLASSES.contains(d.resolved()))) {
      return;
    }
    List<String> attrs = new ArrayList<>();
    List<String> params = new ArrayList<>();
    List<PyClass> line = new ArrayList<>(model.hierarchy(c));
    java.util.Collections.reverse(line);
    for (PyClass k : line) {
      boolean data = k.decorators().stream().anyMatch(d -> DATACLASSES.contains(d.resolved()));
      for (PyStatement s : data ? k.statement().body() : List.<PyStatement>of()) {
        List<Node> n = s.nodes();
        Token name = n.size() > 2 ? Nodes.leaf(n.get(0)) : null;
        Token op = n.size() > 2 ? Nodes.leaf(n.get(1)) : null;
        if (!s.body().isEmpty() || name == null || name.kind() != TokenKind.IDENT || op == null || name.text().equals("_")
          || attrs.contains(name.text())) {
          continue;
        }
        String value = Exprs.text(n.subList(2, n.size()));
        boolean field = op.is(":") && !value.startsWith("ClassVar") && !value.startsWith("typing.ClassVar")
          && !value.startsWith("KW_ONLY") || op.is("=") && ATTRS_FIELD.matcher(value).matches();
        if (field && !value.replace(" ", "").contains("init=False")) {
          attrs.add(name.text());
          // attrs drops the leading underscore of a private attribute's parameter
          params.add(k.decorators().stream().anyMatch(d -> d.resolved().startsWith("attr")) ? name.text().replaceFirst("^_+", "") : name.text());
        }
      }
    }
    Map<String, Taint> out = new HashMap<>();
    for (int i = 0; i < attrs.size(); i++) {
      attrId(attrs.get(i));
      out.put(attrs.get(i), Taint.param(i + 1, params.get(i)));
    }
    if (!out.isEmpty()) {
      ctorAttributes.put(c, out);
      fieldParams.put(c, params);
    }
  }

  /** The endpoint of the function, else of the nearest caller that is one. */
  private Endpoint endpoint(Function f) {
    List<Function> queue = new ArrayList<>(List.of(f));
    Set<Function> seen = new HashSet<>();
    for (int i = 0; i < queue.size() && i < 200; i++) {
      Function g = queue.get(i);
      if (!seen.add(g)) {
        continue;
      }
      List<Endpoint> es = model.endpointsOf(g);
      if (!es.isEmpty()) {
        return es.get(0);
      }
      queue.addAll(callers.getOrDefault(g, Set.of()));
    }
    // setup(), dispatch(), get_queryset(): a method the framework calls, of a view class
    for (Endpoint e : f.owner() == null ? List.<Endpoint>of() : model.endpoints()) {
      if (e.viewClass() != null && model.hierarchy(e.viewClass()).contains(f.owner())) {
        return e;
      }
    }
    return null;
  }

  /** Variables in scope: their taint, the class they were built from, and which ones are request objects. */
  private static final class Env {
    final Map<String, Taint> vars = new HashMap<>();
    final Map<String, String> types = new HashMap<>();
    final Set<String> requests = new HashSet<>();
    /** Variables holding an instance of a project class built here: {@code client = Client(url)}. */
    final Map<String, PyClass> classes = new HashMap<>();

    Env copy() {
      Env e = new Env();
      e.vars.putAll(vars);
      e.types.putAll(types);
      e.requests.addAll(requests);
      e.classes.putAll(classes);
      return e;
    }

    void add(Env o) {
      o.vars.forEach((k, v) -> vars.merge(k, v, Taint::union));
      types.putAll(o.types);
      requests.addAll(o.requests);
      classes.putAll(o.classes);
    }

    void set(List<Env> all) {
      vars.clear();
      types.clear();
      requests.clear();
      classes.clear();
      all.forEach(this::add);
    }
  }

  /** One pass over one function. */
  private final class Analysis {
    private final Function fn;
    private final Module m;
    private final boolean collect;
    private final Summary summary = new Summary();
    private final Set<String> sinkKeys = new HashSet<>();
    private Taint returned = Taint.EMPTY;
    /** {@code port = PROXIES.get(host)}: the variable holding a lookup in a fixed map, and the key it looked up. */
    private final Map<String, List<Node>> lookups = new HashMap<>();

    Analysis(Function fn, boolean collect) {
      this.fn = fn;
      this.m = fn.module();
      this.collect = collect;
    }

    Summary run() {
      Env env = new Env();
      Set<String> inputs = inputs();
      List<Function.Param> ps = fn.params();
      for (int i = 0; i < ps.size(); i++) {
        Function.Param p = ps.get(i);
        if (i == 0 && fn.takesSelf()) {
          continue;
        }
        if (isRequest(p)) {
          env.requests.add(p.name());
        } else if (inputs.contains(p.name())) {
          String label = "parameter " + p.name();
          env.vars.put(p.name(), Taint.source(label, new Step(m, p.token(), "request input " + p.name()), fn));
        } else {
          env.vars.put(p.name(), Taint.param(i, p.name()));
        }
      }
      if (fn.owner() != null) {
        env.requests.add("self.request");
        if (fn.takesSelf()) {
          // self.url = request.GET["url"] in another method of the class, a base class or a subclass (a base class's
          // method runs on the subclass's instances): the value it may hold here
          // self.url = url in __init__: the attribute is a pseudo parameter, given by the caller's instance
          for (PyClass c : related(fn.owner())) {
            attributes.getOrDefault(c, Map.of()).forEach((a, t) -> env.vars.merge("self." + a, t, Taint::union));
            for (String a : ctorAttributes.getOrDefault(c, Map.of()).keySet()) {
              env.vars.merge("self." + a, Taint.param(ATTR + attrId(a), "self." + a), Taint::union);
            }
          }
        }
      }
      block(fn.body(), env);
      summary.returnSources = returned.filter(Taint.Origin::isSource);
      returned.flows().forEach((o, f) -> {
        if (!o.isSource()) {
          summary.returns.put(o.param(), f);
        }
      });
      return summary;
    }

    /** Parameters that are request inputs: FastAPI query/path/body parameters, Django and Flask URL parameters. */
    private Set<String> inputs() {
      Set<String> out = new HashSet<>();
      for (Endpoint e : model.endpointsOf(fn)) {
        List<Function.Param> ps = fn.params();
        if (e.framework() == Framework.FASTAPI) {
          for (Function.Param p : ps) {
            String text = p.annotationText() + "=" + Exprs.text(p.defaultValue());
            String alias = Exprs.dotted(p.annotation());
            List<Node> aliased = alias == null ? null : model.value(m, alias);
            if (p.stars() == 0 && !isRequest(p) && !text.contains("Depends(") && !text.contains("Security(")
              && !models.notInputs.contains(lastName(p.annotationText())) && !validated(p.annotationText())
              && (aliased == null || !Exprs.text(aliased).contains("Depends("))) {
              out.add(p.name());
            }
          }
          continue;
        }
        if (e.framework() == Framework.AIOHTTP) {
          // aiohttp handlers take the request only; URL parameters come from request.match_info
          continue;
        }
        Map<String, String> declared = new HashMap<>();
        Matcher pm = PATH_PARAM.matcher(e.path());
        while (pm.find()) {
          declared.put(pm.group(2) != null ? pm.group(2) : pm.group(3), pm.group(1) == null ? "str" : pm.group(1));
        }
        // Django regex routes: (?P<id>\d+) and positional (\d+) groups match digits only
        List<Boolean> positional = new ArrayList<>();
        Matcher gm = REGEX_GROUP.matcher(e.path());
        while (gm.find()) {
          boolean digits = DIGITS.matcher(gm.group(2)).matches();
          if (gm.group(1) == null) {
            positional.add(digits);
          } else if (digits) {
            declared.put(gm.group(1), "int");
          }
        }
        int first = fn.takesSelf() ? 1 : 0;
        for (int i = first; i < ps.size(); i++) {
          Function.Param p = ps.get(i);
          String conv = declared.get(p.name());
          int g = i - first - 1;
          boolean typed = conv != null && Set.of("int", "float", "uuid", "slug").contains(conv)
            || conv == null && e.framework() != Framework.FLASK && g >= 0 && g < positional.size() && positional.get(g);
          boolean url = e.framework() == Framework.FLASK ? conv != null : i > first;
          if (p.stars() == 0 && !isRequest(p) && url && !typed) {
            out.add(p.name());
          }
        }
      }
      return out;
    }

    /**
     * A FastAPI parameter type that FastAPI validates into a value that cannot carry text: int, float, bool, UUID, dates,
     * constrained numbers, a Literal or an Enum ({@code Annotated[...]}, {@code Optional[...]} and {@code | None} looked
     * through).
     */
    private boolean validated(String annotation) {
      String a = annotation;
      for (String wrapper : List.of("Annotated[", "Optional[")) {
        if (a.startsWith(wrapper) && a.endsWith("]")) {
          a = topLevel(a.substring(wrapper.length(), a.length() - 1), ',').get(0);
        }
      }
      List<String> parts = new ArrayList<>(topLevel(a, '|'));
      parts.remove("None");
      if (a.isEmpty() || parts.isEmpty()) {
        return false;
      }
      for (String part : parts) {
        String name = lastName(part);
        PyClass c = part.contains("[") || part.contains("(") ? null : model.cls(m, part);
        boolean isEnum = c != null && model.externalBases(c).stream().anyMatch(b -> b.startsWith("enum."));
        if (!part.startsWith("Literal[") && !part.startsWith("typing.Literal[") && !SCALARS.contains(name) && !isEnum) {
          return false;
        }
      }
      return true;
    }

    private boolean isRequest(Function.Param p) {
      String type = lastName(p.annotationText());
      return models.requestTypes.contains(type) || (p.name().equals("request") || p.name().equals("req")) && p.annotation().isEmpty();
    }

    // ---- statements

    private void block(List<PyStatement> stmts, Env env) {
      for (int i = 0; i < stmts.size(); i++) {
        PyStatement s = stmts.get(i);
        switch (s.keyword()) {
          case "def", "class" -> {
          }
          case "if" -> i = branches(stmts, i, env);
          case "try" -> i = tryBlock(stmts, i, env);
          case "for", "while" -> {
            header(s, env);
            Env e = env.copy();
            block(s.body(), e);
            header(s, e);
            block(s.body(), e);
            env.add(e);
          }
          case "return" -> {
            List<Node> rest = s.nodes().subList(1, s.nodes().size());
            sinks(rest, env);
            returned = returned.union(eval(rest, env).step(step(s.first(), "returned")));
          }
          default -> {
            if (s.body().isEmpty()) {
              simple(s.nodes(), env);
            } else {
              header(s, env);
              block(s.body(), env);
            }
          }
        }
      }
    }

    private int branches(List<PyStatement> stmts, int i, Env env) {
      int j = i + 1;
      while (j < stmts.size() && Set.of("elif", "else").contains(stmts.get(j).keyword())) {
        j++;
      }
      List<Env> outs = new ArrayList<>();
      boolean otherwise = false;
      for (int k = i; k < j; k++) {
        PyStatement b = stmts.get(k);
        if (b.keyword().equals("else")) {
          otherwise = true;
        } else {
          header(b, env);
        }
        Env e = env.copy();
        block(b.body(), e);
        if (!exits(b.body())) {
          // a branch ending in return or raise does not reach the code after the if
          outs.add(e);
        }
      }
      if (!otherwise || outs.isEmpty()) {
        outs.add(env.copy());
      }
      env.set(outs);
      return j - 1;
    }

    private static boolean exits(List<PyStatement> body) {
      return !body.isEmpty() && Set.of("return", "raise").contains(body.get(body.size() - 1).keyword());
    }

    private int tryBlock(List<PyStatement> stmts, int i, Env env) {
      int j = i + 1;
      while (j < stmts.size() && Set.of("except", "else", "finally").contains(stmts.get(j).keyword())) {
        j++;
      }
      Env t = env.copy();
      block(stmts.get(i).body(), t);
      List<Env> outs = new ArrayList<>(List.of(t));
      PyStatement fin = null;
      for (int k = i + 1; k < j; k++) {
        PyStatement b = stmts.get(k);
        switch (b.keyword()) {
          case "except" -> {
            Env e = env.copy();
            e.add(t);
            header(b, e);
            block(b.body(), e);
            outs.add(e);
          }
          case "else" -> block(b.body(), t);
          default -> fin = b;
        }
      }
      env.set(outs);
      if (fin != null) {
        block(fin.body(), env);
      }
      return j - 1;
    }

    /** The header of a compound statement: guards in conditions, sinks, loop and with targets. */
    private void header(PyStatement s, Env env) {
      List<Node> n = s.nodes();
      int from = s.isAsync() ? 2 : 1;
      int to = n.size() > from && Nodes.isLeaf(n.get(n.size() - 1), ":") ? n.size() - 1 : n.size();
      List<Node> h = from <= to ? n.subList(from, to) : List.of();
      switch (s.keyword()) {
        case "if", "elif", "while" -> {
          guards(h, env);
          sinks(h, env);
        }
        case "for" -> {
          int in = indexOfIdent(h, "in");
          if (in > 0) {
            List<Node> iter = h.subList(in + 1, h.size());
            sinks(iter, env);
            bind(h.subList(0, in), eval(iter, env), iter, env);
          }
        }
        case "with" -> {
          for (List<Node> item : Nodes.split(h, ",")) {
            int as = indexOfIdent(item, "as");
            List<Node> expr = as < 0 ? item : item.subList(0, as);
            sinks(expr, env);
            if (as > 0) {
              bind(item.subList(as + 1, item.size()), eval(expr, env), expr, env);
            }
          }
        }
        case "except" -> {
          int as = indexOfIdent(h, "as");
          if (as > 0) {
            bind(h.subList(as + 1, h.size()), Taint.EMPTY, List.of(), env);
          }
        }
        default -> sinks(h, env);
      }
    }

    private void simple(List<Node> nodes, Env env) {
      for (List<Node> part : Nodes.split(nodes, ";")) {
        Token first = Nodes.leaf(part.get(0));
        String kw = first != null && first.kind() == TokenKind.IDENT ? first.text() : "";
        if (SKIPPED.contains(kw)) {
          continue;
        }
        List<Node> rest = part.subList(1, part.size());
        if (kw.equals("raise")) {
          sinks(rest, env);
          continue;
        }
        if (kw.equals("assert")) {
          guards(rest, env);
          sinks(rest, env);
          continue;
        }
        if (kw.equals("yield")) {
          sinks(rest, env);
          returned = returned.union(eval(rest, env).step(step(first, "yielded")));
          continue;
        }
        sinks(part, env);
        validatorCalls(part, env);
        int aug = -1;
        for (int i = 1; i < part.size() && aug < 0; i++) {
          Token t = Nodes.leaf(part.get(i));
          if (t != null && t.kind() == TokenKind.OP && AUGMENTED.contains(t.text())) {
            aug = i;
          }
        }
        if (aug > 0) {
          String key = Exprs.dotted(part.subList(0, aug));
          Taint t = eval(part.subList(aug + 1, part.size()), env);
          if (key != null && !t.isEmpty()) {
            env.vars.merge(key, t.step(step(part.get(0).first(), "added to " + key)), Taint::union);
            store(key, env);
          }
          continue;
        }
        List<List<Node>> parts = Exprs.assignment(part);
        if (parts.size() >= 2) {
          List<Node> value = parts.get(parts.size() - 1);
          lookup(parts.get(0), value);
          Taint t = eval(value, env);
          for (List<Node> target : parts.subList(0, parts.size() - 1)) {
            bind(target, t, value, env);
          }
          continue;
        }
        Chain c = Exprs.chain(kw.equals("await") ? rest : part);
        if (c != null && c.endsWithCall() && c.lastName().equals("__init__") && fn.name().equals("__init__") && fn.takesSelf()
          && fn.owner() != null) {
          superInit(c, env);
          continue;
        }
        int k = c == null ? 0 : Exprs.headSize(c);
        if (c != null && k >= 2 && c.segments().size() == k + 1 && c.endsWithCall() && models.mutators.contains(c.lastName())) {
          String receiver = Exprs.head(c);
          receiver = receiver.substring(0, receiver.lastIndexOf('.'));
          Taint t = args(((Chain.Call) c.segments().get(k)).args(), env);
          if (c.lastName().equals("write")) {
            // what is written fills a buffer's content, not a file's name or a path
            t = t.clear(Set.of("path"));
          }
          if (!t.isEmpty()) {
            env.vars.merge(receiver, t.step(step(c.first(), "added to " + receiver)), Taint::union);
            store(receiver, env);
          }
        }
      }
    }

    private void bind(List<Node> target, Taint t, List<Node> value, Env env) {
      target = Exprs.unannotated(target);
      List<List<Node>> items = Nodes.split(target, ",");
      if (target.size() == 1 && target.get(0) instanceof Node.Group g && (g.is("(") || g.is("["))) {
        items = g.items();
      }
      for (List<Node> item : items) {
        if (Nodes.isLeaf(item.get(0), "*") && item.size() > 1) {
          item = item.subList(1, item.size());
        }
        String key = Exprs.dotted(item);
        if (key != null) {
          env.vars.keySet().removeIf(k -> k.startsWith(key + "."));
          env.classes.remove(key);
          if (t.isEmpty()) {
            env.vars.remove(key);
          } else {
            env.vars.put(key, t.step(step(item.get(0).first(), "assigned to " + key)));
            store(key, env);
          }
          if (items.size() == 1) {
            String vd = Exprs.dotted(value);
            Chain vc = Exprs.chain(value);
            Chain.Call call = vc == null ? null : Exprs.firstCall(vc);
            String type = call != null && Exprs.headSize(vc) + 1 == vc.segments().size() ? qualify(Exprs.head(vc), env) : null;
            if (type != null && Character.isUpperCase(lastName(type).isEmpty() ? 'x' : lastName(type).charAt(0))) {
              env.types.put(key, type);
            } else {
              env.types.remove(key);
            }
            if (vd != null && isRequestObject(vd, env)) {
              env.requests.add(key);
            } else {
              env.requests.remove(key);
            }
            // client = Client(request.GET["url"]): the attributes its __init__ stores from those arguments
            PyClass cls = type == null ? null : projectClass(Exprs.head(vc));
            if (cls != null) {
              env.classes.put(key, cls);
              Step at = step(item.get(0).first(), "assigned to " + key);
              constructed(cls, 1, vc.last(), call.args(), env).forEach((a, v) -> env.vars.put(key + "." + a, v.step(at)));
            }
          }
        } else if (!t.isEmpty()) {
          Chain c = Exprs.chain(item);
          if (c != null && c.segments().get(c.segments().size() - 1) instanceof Chain.Index) {
            String base = Exprs.head(c);
            env.vars.merge(base, t.step(step(c.first(), "stored in " + base)), Taint::union);
            store(base, env);
          }
        }
      }
    }

    /**
     * {@code self.url = ...} with request data: kept for the other methods of the class (parameters are not, they are
     * this call's); in {@code __init__}, the parameters it stores are kept apart, for the callers building instances.
     */
    private void store(String key, Env env) {
      if (fn.owner() == null || !fn.takesSelf() || !key.startsWith("self.") || key.indexOf('.', 5) >= 0) {
        return;
      }
      Taint t = env.vars.get(key).filter(Taint.Origin::isSource);
      if (!t.isEmpty()) {
        attributes.computeIfAbsent(fn.owner(), c -> new HashMap<>()).merge(key.substring(5), t, Taint::union);
      }
      Taint p = fn.name().equals("__init__") ? env.vars.get(key).filter(o -> !o.isSource() && o.param() < ATTR) : Taint.EMPTY;
      if (!p.isEmpty()) {
        attrId(key.substring(5));
        ctorAttributes.computeIfAbsent(fn.owner(), c -> new HashMap<>()).merge(key.substring(5), p, Taint::union);
      }
    }

    /** {@code super().__init__(url)} or {@code Base.__init__(self, url)} in {@code __init__}: what the base stores, stored here. */
    private void superInit(Chain c, Env env) {
      List<Chain.Segment> segs = c.segments();
      Chain.Call args = (Chain.Call) segs.get(segs.size() - 1);
      PyClass base;
      int offset;
      if (c.firstName().equals("super") && segs.size() == 4) {
        List<PyClass> h = model.hierarchy(fn.owner());
        base = h.size() > 1 ? h.get(1) : null;
        offset = 1;
      } else {
        base = Exprs.headSize(c) + 1 == segs.size() && segs.size() > 2 ? model.cls(m, Exprs.head(c).replaceFirst("\\.__init__$", "")) : null;
        offset = 0;
      }
      if (base == null) {
        return;
      }
      constructed(base, offset, c.last(), args.args(), env).forEach((a, v) -> {
        env.vars.put("self." + a, v);
        store("self." + a, env);
      });
    }

    /**
     * The attributes an instance of the class gets from its constructor's arguments ({@code Client(url)} with
     * {@code self.url = url} in {@code __init__}): those holding tainted values. {@code offset} is the parameter index of
     * the first positional argument (1, or 0 for {@code Base.__init__(self, x)}).
     */
    private Map<String, Taint> constructed(PyClass cls, int offset, Token at, Node.Group callArgs, Env env) {
      List<String> fields = fieldParams.get(cls);
      Function init = fields != null ? null : model.method(cls, "__init__");
      Map<String, Taint> attrs = ctorAttributes.get(fields != null ? cls : init == null ? null : init.owner());
      if (attrs == null) {
        return Map.of();
      }
      Map<Integer, Taint> in = fields != null ? fieldArgs(fields, offset, callArgs, env) : mapArgs(init, offset, callArgs, env);
      if (in.isEmpty()) {
        return Map.of();
      }
      List<Step> passed = List.of(step(at, "passed to " + cls.name() + "()"));
      Map<String, Taint> out = new HashMap<>();
      attrs.forEach((a, t) -> t.flows().forEach((o, f) -> {
        Taint v = in.get(o.param());
        if (v != null) {
          out.merge(a, v.then(Taint.append(passed, f.path()), f.cleared()), Taint::union);
        }
      }));
      return out;
    }

    /** Arguments of a dataclass's generated {@code __init__}, by parameter index (self is 0). */
    private Map<Integer, Taint> fieldArgs(List<String> fields, int offset, Node.Group callArgs, Env env) {
      Map<Integer, Taint> out = new HashMap<>();
      int pos = offset;
      for (List<Node> item : callArgs.items()) {
        String kw = Exprs.keyword(item);
        if (kw == null && (Nodes.isLeaf(item.get(0), "*") || Nodes.isLeaf(item.get(0), "**"))) {
          continue;
        }
        int index = kw != null ? fields.indexOf(kw) + 1 : pos++;
        Taint t = index >= 1 && index <= fields.size() ? item(kw != null ? item.subList(2, item.size()) : item, env) : Taint.EMPTY;
        if (!t.isEmpty()) {
          out.merge(index, t, Taint::union);
        }
      }
      return out;
    }

    /** {@code self.url} pseudo parameters from the attributes of an instance. */
    private Map<Integer, Taint> pseudo(Map<String, Taint> attrs) {
      Map<Integer, Taint> out = new HashMap<>();
      attrs.forEach((a, t) -> {
        Integer id = attrIds.get(a);
        if (id != null) {
          out.put(ATTR + id, t);
        }
      });
      return out;
    }

    // ---- expressions

    private Taint eval(List<Node> nodes, Env env) {
      if (nodes.isEmpty()) {
        return Taint.EMPTY;
      }
      Token first = Nodes.leaf(nodes.get(0));
      if (first != null && (first.isIdent("await") || first.is("*") || first.is("**") || first.isIdent("yield"))) {
        return eval(nodes.subList(1, nodes.size()), env);
      }
      if (first != null && (first.isIdent("not") || first.isIdent("lambda"))) {
        return Taint.EMPTY;
      }
      int cond = indexOfIdent(nodes, "if");
      if (cond > 0) {
        int otherwise = indexOfIdent(nodes, "else");
        Taint t = eval(nodes.subList(0, cond), env);
        return otherwise > cond ? t.union(eval(nodes.subList(otherwise + 1, nodes.size()), env)) : t;
      }
      List<List<Node>> bools = splitIdents(nodes, Set.of("and", "or"));
      if (bools.size() > 1) {
        Taint t = Taint.EMPTY;
        for (List<Node> b : bools) {
          t = t.union(eval(b, env));
        }
        return t;
      }
      for (Node n : nodes) {
        Token t = Nodes.leaf(n);
        if (t != null && (t.kind() == TokenKind.OP && COMPARISONS.contains(t.text()) || t.isIdent("in") || t.isIdent("is"))) {
          return Taint.EMPTY;
        }
      }
      Map<Integer, Chain> chains = new HashMap<>();
      for (Chain c : Chains.direct(new Node.Group(null, null, nodes))) {
        chains.put(c.from(), c);
      }
      Taint out = Taint.EMPTY;
      Taint lead0 = null;
      // path + "?" + params.urlencode(): what follows the query mark cannot move the URL
      boolean query = false;
      int i = 0;
      while (i < nodes.size()) {
        Chain c = chains.get(i);
        if (c != null) {
          Taint v = segments(c.segments(), env);
          lead0 = i == 0 ? v : lead0;
          out = out.union(query ? v.clear(URL_KINDS) : v);
          i = c.to();
          continue;
        }
        Node n = nodes.get(i);
        Token t = Nodes.leaf(n);
        Taint v;
        boolean mark = false;
        if (t != null && t.kind() == TokenKind.STRING) {
          v = fstring(t, env);
          String lit = Exprs.literal(t);
          mark = lit != null && (lit.contains("?") || lit.contains("#")) && (i > 0 && Nodes.isLeaf(nodes.get(i - 1), "+")
            || i + 1 < nodes.size() && Nodes.isLeaf(nodes.get(i + 1), "+"));
        } else if (n instanceof Node.Group g) {
          v = group(g, env);
        } else {
          i++;
          continue;
        }
        i++;
        // a method or index on a literal or a bracketed value: ", ".join(parts), "{}".format(x), (a + b).strip()
        while (i < nodes.size()) {
          if (Nodes.isLeaf(nodes.get(i), ".") && i + 1 < nodes.size() && Nodes.leaf(nodes.get(i + 1)) != null) {
            String name = Nodes.leaf(nodes.get(i + 1)).text();
            boolean call = i + 2 < nodes.size() && nodes.get(i + 2) instanceof Node.Group a && a.is("(");
            if (call && models.cleanMethods.contains(name)) {
              v = Taint.EMPTY;
            } else if (call) {
              v = v.union(args((Node.Group) nodes.get(i + 2), env));
              Set<String> kinds = models.sanitizer("*." + name, name, true);
              v = kinds == null ? v : v.clear(kinds);
            }
            i += call ? 3 : 2;
          } else if (nodes.get(i) instanceof Node.Group g && g.is("[")) {
            i++;
          } else {
            break;
          }
        }
        out = out.union(query ? v.clear(URL_KINDS) : v);
        query |= mark;
      }
      // f"https://api.example/items/{x}", "/items/" + x: the literal start fixes the host, x cannot move the URL
      Token lead = Nodes.leaf(nodes.get(0));
      if (lead != null && lead.kind() == TokenKind.STRING && fixesTarget(lead.text()) || !out.isEmpty() && fixedByCleanPrefix(nodes, env)) {
        return out.clear(URL_KINDS);
      }
      // settings.BASE_URL + path, get_root_url() + key: a clean base named for a URL root comes first
      Chain c0 = chains.get(0);
      return lead0 != null && lead0.isEmpty() && c0.to() < nodes.size() && Nodes.isLeaf(nodes.get(c0.to()), "+")
        && URL_BASE.matcher(c0.lastName()).find() ? out.clear(URL_KINDS) : out;
    }

    /**
     * {@code protocol + settings.HOST + "/live/" + name}: server values, then a literal that fixes the target, before
     * any request data.
     */
    private boolean fixedByCleanPrefix(List<Node> nodes, Env env) {
      List<List<Node>> parts = Nodes.split(nodes, "+");
      if (parts.size() < 2) {
        return false;
      }
      boolean server = false;
      for (int k = 0; k < parts.size(); k++) {
        List<Node> part = parts.get(k);
        Token t = part.size() == 1 ? Nodes.leaf(part.get(0)) : null;
        if (t != null && t.kind() == TokenKind.STRING) {
          String v = Exprs.literal(t);
          // after a server value, a "/", "?" or "#" ends the host that value gave
          if (k > 0 && (fixesTarget(t.text()) || server && v != null && !v.isEmpty() && "/?#".indexOf(v.charAt(0)) >= 0)) {
            return true;
          }
        } else if (!eval(part, env).isEmpty()) {
          return false;
        } else {
          Chain c = k == 0 ? Exprs.chain(part) : null;
          if (c != null && URL_BASE.matcher(c.lastName()).find()) {
            // upload_root_url() + path: a base URL of the server's, then the caller's part
            return true;
          }
          server = true;
        }
      }
      return false;
    }

    /** A bracketed expression, list, tuple, set, dict or comprehension: the union of its parts. */
    private Taint group(Node.Group g, Env env) {
      Taint out = Taint.EMPTY;
      for (List<Node> item : g.items()) {
        for (List<Node> part : indexOfIdent(item, "for") > 0 ? List.of(item) : Nodes.split(item, ":")) {
          out = out.union(item(part, env));
        }
      }
      return out;
    }

    /** One item of a bracket or call: a comprehension gives its element and iterables ([f(x) for x in xs if c]). */
    private Taint item(List<Node> item, Env env) {
      if (indexOfIdent(item, "for") <= 0) {
        return eval(item, env);
      }
      List<List<Node>> parts = splitIdents(item, Set.of("for", "in", "if"));
      Taint out = eval(parts.get(0), env);
      for (int k = 2; k < parts.size(); k += 2) {
        out = out.union(eval(parts.get(k), env));
      }
      return out;
    }

    /** The union of a call's argument values. */
    private Taint args(Node.Group call, Env env) {
      Taint out = Taint.EMPTY;
      for (List<Node> item : call.items()) {
        out = out.union(item(Exprs.keyword(item) != null ? item.subList(2, item.size()) : item, env));
      }
      return out;
    }

    /** The values in an f-string's replacement fields. */
    private Taint fstring(Token t, Env env) {
      String text = t.text();
      int q = 0;
      while (q < text.length() && text.charAt(q) != '\'' && text.charAt(q) != '"') {
        q++;
      }
      String prefix = text.substring(0, q).toLowerCase(java.util.Locale.ROOT);
      if (!prefix.contains("f") && !prefix.contains("t") || q >= text.length()) {
        return Taint.EMPTY;
      }
      Taint out = Taint.EMPTY;
      // the text before each field, clean fields as "x": f"https://{region}.example/{key}" fixes the host before key
      StringBuilder before = new StringBuilder();
      int i = q + (text.startsWith("\"\"\"", q) || text.startsWith("'''", q) ? 3 : 1);
      while (i < text.length()) {
        char c = text.charAt(i);
        if (c == '{' && i + 1 < text.length() && text.charAt(i + 1) == '{') {
          before.append('{');
          i += 2;
        } else if (c == '{') {
          int end = fieldEnd(text, i + 1);
          Taint v = field(t, text, i + 1, end, env);
          boolean fixed = FIXED_TARGET.matcher(before).find() || before.indexOf("?") >= 0 || before.indexOf("#") >= 0;
          out = out.union(!v.isEmpty() && fixed ? v.clear(URL_KINDS) : v);
          before.append('x');
          i = end + 1;
        } else {
          before.append(c);
          i++;
        }
      }
      return out;
    }

    private Taint field(Token t, String text, int from, int to, Env env) {
      String expr = text.substring(from, Math.min(to, text.length()));
      int cut = expr.length();
      int depth = 0;
      for (int k = 0; k < expr.length(); k++) {
        char c = expr.charAt(k);
        if ("([{".indexOf(c) >= 0) {
          depth++;
        } else if (")]}".indexOf(c) >= 0) {
          depth--;
        } else if (depth == 0 && (c == ':' || c == '!' && k + 1 < expr.length() && expr.charAt(k + 1) != '=')) {
          cut = k;
          break;
        }
      }
      expr = expr.substring(0, cut).strip();
      if (expr.endsWith("=")) {
        expr = expr.substring(0, expr.length() - 1);
      }
      // place the field's tokens where they are in the file, for the path's locations
      int line = t.line();
      int col = t.column();
      for (int k = 0; k < from; k++) {
        if (text.charAt(k) == '\n') {
          line++;
          col = 0;
        } else {
          col++;
        }
      }
      int baseLine = line;
      int baseCol = col;
      List<Token> tokens = new ArrayList<>();
      for (Token x : PythonLexer.lex(expr).tokens()) {
        if (x.kind() == TokenKind.NEWLINE || x.kind() == TokenKind.INDENT || x.kind() == TokenKind.DEDENT) {
          continue;
        }
        tokens.add(new Token(x.kind(), x.text(), baseLine + x.line() - 1, x.line() == 1 ? baseCol + x.column() : x.column(),
          baseLine + x.endLine() - 1, x.endLine() == 1 ? baseCol + x.endColumn() : x.endColumn()));
      }
      return eval(TreeBuilder.build(tokens).children(), env);
    }

    private static int fieldEnd(String s, int i) {
      int depth = 0;
      while (i < s.length()) {
        char c = s.charAt(i);
        if (c == '\'' || c == '"') {
          int close = s.indexOf(c, i + 1);
          i = close < 0 ? s.length() : close + 1;
          continue;
        }
        if (c == '{' || c == '[' || c == '(') {
          depth++;
        } else if ((c == '}' || c == ']' || c == ')') && depth > 0) {
          depth--;
        } else if (c == '}') {
          return i;
        }
        i++;
      }
      return s.length();
    }

    /** A chain: a request input read, a tainted variable and what is read or called on it, or a call. */
    private Taint segments(List<Chain.Segment> segs, Env env) {
      List<Token> names = new ArrayList<>();
      for (Chain.Segment s : segs) {
        if (!(s instanceof Chain.Name n)) {
          break;
        }
        names.add(n.token());
      }
      int k = names.size();
      for (int j = 1; j <= k; j++) {
        if (isRequestObject(join(names, j), env)) {
          if (j + 1 < k && names.get(j).text().equals("rel_url") && names.get(j + 1).text().equals("query")) {
            // aiohttp request.rel_url.query
            String label = "request.rel_url.query";
            return rest(Taint.source(label, new Step(m, names.get(j + 1), label + " read here"), fn), segs, j + 2);
          }
          if (j < k && models.requestAttributes.contains(names.get(j).text())) {
            String label = "request." + names.get(j).text();
            return rest(Taint.source(label, new Step(m, names.get(j), label + " read here"), fn), segs, j + 1);
          }
          return Taint.EMPTY;
        }
      }
      for (int j = k; j >= 1; j--) {
        Taint v = env.vars.get(join(names, j));
        if (v != null) {
          return rest(v, segs, j);
        }
      }
      if (k > 0 && k + 2 < segs.size() && segs.get(k) instanceof Chain.Call ctor && segs.get(k + 1) instanceof Chain.Name meth
        && segs.get(k + 2) instanceof Chain.Call mc) {
        // Client(url).fetch(): the method's summary, with the attributes the constructor stored
        PyClass cls = projectClass(join(names, k));
        Function target = cls == null ? null : model.method(cls, meth.token().text());
        if (target != null) {
          Summary s = summaries.getOrDefault(target, Summary.EMPTY);
          Map<Integer, Taint> args = s.returns.isEmpty() ? Map.of() : chained(cls, names.get(k - 1), ctor, target, mc, env);
          return rest(returned(target, s, args, meth.token()), segs, k + 3);
        }
      }
      if (k > 0 && k < segs.size() && segs.get(k) instanceof Chain.Call call) {
        return rest(call(join(names, k), names.get(k - 1), call.args(), env), segs, k + 1);
      }
      return Taint.EMPTY;
    }

    /** The arguments of {@code Client(url).fetch(x)}: fetch's own, then the attributes the constructor stored. */
    private Map<Integer, Taint> chained(PyClass cls, Token name, Chain.Call ctor, Function target, Chain.Call call, Env env) {
      Map<Integer, Taint> args = mapArgs(target, target.takesSelf() ? 1 : 0, call.args(), env);
      args.putAll(pseudo(constructed(cls, 1, name, ctor.args(), env)));
      return args;
    }

    /** What follows a tainted value in a chain: attribute and index reads and method calls keep it, clean methods drop it. */
    private Taint rest(Taint t, List<Chain.Segment> segs, int from) {
      for (int i = from; i < segs.size() && !t.isEmpty(); i++) {
        if (segs.get(i) instanceof Chain.Name n && i + 1 < segs.size() && segs.get(i + 1) instanceof Chain.Call) {
          String name = n.token().text();
          if (models.cleanMethods.contains(name) || numberType((Chain.Call) segs.get(i + 1))) {
            return Taint.EMPTY;
          }
          Set<String> kinds = models.sanitizer("*." + name, name, true);
          t = kinds == null ? t : t.clear(kinds);
        }
      }
      return t;
    }

    /** {@code request.args.get("page", type=int)}: werkzeug converts the value, or gives the default. */
    private static boolean numberType(Chain.Call call) {
      List<Node> type = Exprs.kwargs(call).get("type");
      return type != null && Set.of("int", "float", "bool").contains(Exprs.text(type));
    }

    /** The value of a call: a project function's summary, a sanitizer, a propagator, else clean. */
    private Taint call(String head, Token name, Node.Group callArgs, Env env) {
      Function target = resolve(head, env);
      if (target != null) {
        Summary s = summaries.getOrDefault(target, Summary.EMPTY);
        return returned(target, s, s.returns.isEmpty() ? Map.of() : mapArgs(target, head, callArgs, env), name);
      }
      String callee = qualify(head, env);
      String method = name.text();
      boolean receiver = head.contains(".");
      Taint args = args(callArgs, env);
      Set<String> kinds = models.sanitizer(callee, method, receiver);
      if (kinds != null) {
        return args.clear(kinds);
      }
      return models.propagator(callee, method, receiver) ? args : Taint.EMPTY;
    }

    /** The value a call of a project function returns: its own inputs, and the arguments that reach its return. */
    private Taint returned(Function target, Summary s, Map<Integer, Taint> args, Token name) {
      Step in = step(name, "passed to " + target.label() + "()");
      Step back = step(name, "returned by " + target.label() + "()");
      Taint out = s.returnSources.then(List.of(back), Set.of());
      // clean_path(p), safe_filename(n): a project helper named for making a path safe
      boolean pathCleaner = PATH_CLEANER.matcher(target.name()).find();
      for (Map.Entry<Integer, Taint.Flow> r : s.returns.entrySet()) {
        Taint a = args.get(r.getKey());
        if (a != null) {
          Set<String> cleared = r.getValue().cleared();
          if (pathCleaner) {
            cleared = new HashSet<>(cleared);
            cleared.add("path");
          }
          out = out.union(a.then(Taint.append(Taint.append(List.of(in), r.getValue().path()), List.of(back)), cleared));
        }
      }
      return out;
    }

    // ---- sinks, calls into project functions, guards

    /** Every call in the nodes, nested ones too: model sinks, and project functions whose parameters reach sinks. */
    private void sinks(List<Node> nodes, Env env) {
      if (nodes.isEmpty()) {
        return;
      }
      for (Chain c : Chains.in(new Node.Group(null, null, nodes))) {
        List<Chain.Segment> segs = c.segments();
        int k = Exprs.headSize(c);
        for (int ci = 1; ci < segs.size(); ci++) {
          if (!(segs.get(ci) instanceof Chain.Call call) || !(segs.get(ci - 1) instanceof Chain.Name n)) {
            continue;
          }
          List<Chain.Segment> receiverSegs = segs.subList(0, ci - 1);
          String head = ci == k ? Exprs.head(c) : null;
          Function target = head == null ? null : resolve(head, env);
          if (target != null) {
            if (collect) {
              callers.computeIfAbsent(target, x -> new LinkedHashSet<>()).add(fn);
            }
            if (!summaries.getOrDefault(target, Summary.EMPTY).sinks.isEmpty()) {
              paramSinks(target, mapArgs(target, head, call.args(), env), n.token());
            }
            continue;
          }
          // Client(url): its __init__; Client(url).fetch(): fetch with the attributes the constructor stored
          PyClass cls = k > 0 && (ci == k || ci == k + 2 && segs.get(k) instanceof Chain.Call) ? projectClass(Exprs.head(c)) : null;
          Function member = cls == null ? null : model.method(cls, ci == k ? "__init__" : n.token().text());
          if (member != null) {
            if (collect) {
              callers.computeIfAbsent(member, x -> new LinkedHashSet<>()).add(fn);
            }
            if (!summaries.getOrDefault(member, Summary.EMPTY).sinks.isEmpty()) {
              Token ctorName = ((Chain.Name) segs.get(k - 1)).token();
              paramSinks(member, ci == k ? mapArgs(member, 1, call.args(), env)
                : chained(cls, ctorName, (Chain.Call) segs.get(k), member, call, env), n.token());
            }
            continue;
          }
          String callee = head != null ? qualify(head, env) : "*." + n.token().text();
          String shown = head != null ? head : n.token().text();
          boolean receiver = !receiverSegs.isEmpty();
          for (TaintModels.Sink sink : models.sinks) {
            if (!TaintModels.matches(sink.call(), callee, n.token().text(), receiver) || !applies(sink, call)) {
              continue;
            }
            for (int idx : sink.args()) {
              Taint t = idx < 0 ? (receiver ? segments(receiverSegs, env) : Taint.EMPTY) : item(orEmpty(Exprs.arg(call, idx, null)), env);
              report(sink.kind(), shown, n.token(), t);
            }
            Map<String, List<Node>> kw = Exprs.kwargs(call);
            for (String name : sink.kwargs()) {
              if (kw.containsKey(name)) {
                report(sink.kind(), shown, n.token(), eval(kw.get(name), env));
              }
            }
          }
        }
      }
    }

    private boolean applies(TaintModels.Sink sink, Chain.Call call) {
      Map<String, List<Node>> kw = Exprs.kwargs(call);
      for (Map.Entry<String, List<String>> w : sink.when().entrySet()) {
        if (!kw.containsKey(w.getKey()) || !w.getValue().contains(Exprs.text(kw.get(w.getKey())))) {
          return false;
        }
      }
      for (Map.Entry<String, List<String>> u : sink.unless().entrySet()) {
        for (List<Node> item : call.items()) {
          List<Node> v = Exprs.keyword(item) == null ? item : item.subList(2, item.size());
          if ((Exprs.keyword(item) == null || Exprs.keyword(item).equals(u.getKey())) && u.getValue().contains(Exprs.text(v))) {
            return false;
          }
        }
      }
      return true;
    }

    private void report(String kind, String sinkName, Token at, Taint t) {
      if (t.isEmpty()) {
        return;
      }
      Step sink = step(at, "reaches " + sinkName + "()");
      t.flows().forEach((o, f) -> {
        if (!f.clears(kind)) {
          hit(o, kind, sinkName, sink, Taint.append(f.path(), List.of(sink)), f.cleared());
        }
      });
    }

    private void paramSinks(Function target, Map<Integer, Taint> args, Token name) {
      Summary s = summaries.getOrDefault(target, Summary.EMPTY);
      Step in = step(name, "passed to " + target.label() + "()");
      for (Summary.ParamSink ps : s.sinks) {
        Taint a = args.get(ps.param());
        if (a == null) {
          continue;
        }
        a.flows().forEach((o, f) -> {
          if (!f.clears(ps.kind()) && !ps.cleared().contains(ps.kind()) && !ps.cleared().contains("*")) {
            List<Step> path = Taint.append(Taint.append(f.path(), List.of(in)), ps.path());
            hit(o, ps.kind(), ps.sinkName(), ps.path().get(ps.path().size() - 1), path, Taint.plus(f.cleared(), ps.cleared()));
          }
        });
      }
    }

    /** A flow reached a sink: a finding for a request input, a parameter sink of this function's summary otherwise. */
    private void hit(Taint.Origin o, String kind, String sinkName, Step sink, List<Step> path, Set<String> cleared) {
      if (o.isSource()) {
        String key = kind + "|" + sink + "|" + sink.token().column() + "|" + o.source() + "|" + o.source().token().column();
        if (collect && !findings.containsKey(key)) {
          findings.put(key, new Finding(kind, sinkName, o.label(), o.source(), sink, path, o.function(), null));
        }
      } else if (sinkKeys.add(o.param() + "|" + kind + "|" + sink + "|" + sink.token().column())) {
        summary.sinks.add(new Summary.ParamSink(o.param(), kind, sinkName, path, cleared));
      }
    }

    /** Guards in a condition clear the variables they check: url_has_allowed_host_and_scheme(url), x in ALLOWED. */
    private void guards(List<Node> cond, Env env) {
      for (Chain c : Chains.in(new Node.Group(null, null, cond))) {
        List<Chain.Segment> segs = c.segments();
        int k = Exprs.headSize(c);
        for (int ci = 1; ci < segs.size(); ci++) {
          if (segs.get(ci) instanceof Chain.Call call && segs.get(ci - 1) instanceof Chain.Name n) {
            String callee = ci == k ? qualify(Exprs.head(c), env) : "*." + n.token().text();
            Set<String> kinds = models.guard(callee, n.token().text(), ci > 1);
            if (kinds == null && VALIDATOR.matcher(n.token().text()).find()) {
              // if not validate_jobid(jobid): return ... : a check the engine cannot read, trusted for every kind
              kinds = Set.of("*");
            }
            if (kinds != null) {
              List<Node> checked = new ArrayList<>(call.args().children());
              if (ci > 1) {
                checked.addAll(c.container().children().subList(c.from(), c.to()));
              }
              clearVars(checked, kinds, env);
            }
          }
        }
      }
      for (Node n : cond) {
        // if not port: return ... after port = PROXIES.get(host): host is one of the map's keys
        List<Node> key = Nodes.leaf(n) != null && Nodes.leaf(n).kind() == TokenKind.IDENT ? lookups.get(Nodes.leaf(n).text()) : null;
        if (key != null) {
          clearVars(key, Set.of("*"), env);
        }
      }
      for (List<Node> part : splitIdents(cond, Set.of("and", "or"))) {
        int in = indexOfIdent(part, "in");
        if (in > 0) {
          int left = Nodes.isLeaf(part.get(0), "not") ? 1 : 0;
          int end = Nodes.isLeaf(part.get(in - 1), "not") ? in - 1 : in;
          if (end > left) {
            clearVars(part.subList(left, end), Set.of("*"), env);
          }
        }
      }
    }

    /**
     * Records {@code y = MAP.get(x, ...)} where the map is a constant ({@code PROXIES}), configuration
     * ({@code settings.X}, {@code app.config["X"]}) or an item of one; any other assignment of y forgets it.
     */
    private void lookup(List<Node> target, List<Node> value) {
      String y = Exprs.dotted(Exprs.unannotated(target));
      if (y == null || y.contains(".")) {
        return;
      }
      lookups.remove(y);
      Chain c = Exprs.chain(value);
      List<Chain.Segment> segs = c == null ? List.of() : c.segments();
      int n = segs.size();
      if (n < 3 || !c.endsWithCall() || !(segs.get(n - 2) instanceof Chain.Name get) || !get.token().text().equals("get")) {
        return;
      }
      List<List<Node>> args = Exprs.positional((Chain.Call) segs.get(n - 1));
      String first = c.firstName();
      boolean constant = first.equals("settings") || first.length() > 1 && first.equals(first.toUpperCase(java.util.Locale.ROOT))
        || segs.get(n - 3) instanceof Chain.Index && n >= 4 && segs.get(n - 4) instanceof Chain.Name cfg && cfg.token().text().equals("config");
      if (constant && !args.isEmpty()) {
        lookups.put(y, args.get(0));
      }
    }

    /** {@code err = verify_name(name)} then {@code if err: return}: the validated arguments are trusted from here on. */
    private void validatorCalls(List<Node> nodes, Env env) {
      for (Chain c : Chains.in(new Node.Group(null, null, nodes))) {
        List<Chain.Segment> segs = c.segments();
        for (int ci = 1; ci < segs.size(); ci++) {
          if (segs.get(ci) instanceof Chain.Call call && segs.get(ci - 1) instanceof Chain.Name n && VALIDATOR.matcher(n.token().text()).find()) {
            clearVars(call.args().children(), Set.of("*"), env);
          }
        }
      }
    }

    private void clearVars(List<Node> nodes, Set<String> kinds, Env env) {
      for (Chain c : Chains.in(new Node.Group(null, null, nodes))) {
        List<String> names = new ArrayList<>();
        for (Chain.Segment s : c.segments()) {
          if (!(s instanceof Chain.Name n)) {
            break;
          }
          names.add(n.token().text());
        }
        for (int j = names.size(); j >= 1; j--) {
          String key = String.join(".", names.subList(0, j));
          Taint v = env.vars.get(key);
          if (v != null) {
            Taint cleared = v.clear(kinds);
            if (cleared.isEmpty()) {
              env.vars.remove(key);
            } else {
              env.vars.put(key, cleared);
            }
            break;
          }
        }
      }
    }

    // ---- names

    /** The project class a constructor call names ({@code Client}, {@code clients.Client}): capitalised names only. */
    private PyClass projectClass(String head) {
      String last = head.substring(head.lastIndexOf('.') + 1);
      if (last.isEmpty() || !Character.isUpperCase(last.charAt(0))) {
        return null;
      }
      return classes.computeIfAbsent(m, x -> new HashMap<>()).computeIfAbsent(head, h -> java.util.Optional.ofNullable(model.cls(m, h))).orElse(null);
    }

    /** As {@link #resolve(String)}, and a method of an instance built here ({@code client = Client(url)}, then {@code client.fetch()}). */
    private Function resolve(String head, Env env) {
      int dot = head.lastIndexOf('.');
      PyClass c = dot > 0 ? env.classes.get(head.substring(0, dot)) : null;
      Function f = c == null ? null : model.method(c, head.substring(dot + 1));
      return f != null ? f : resolve(head);
    }

    /** The project function a called name denotes: a method of this class, a nested def, a module or imported function. */
    private Function resolve(String head) {
      int dot = head.indexOf('.');
      if (dot > 0 && fn.owner() != null && (head.startsWith("self.") || head.startsWith("cls.")) && head.indexOf('.', dot + 1) < 0) {
        return model.method(fn.owner(), head.substring(dot + 1));
      }
      if (dot < 0) {
        for (Function f : m.functions()) {
          if (f.parent() != null && (f.parent() == fn || f.parent() == fn.parent()) && f.name().equals(head)) {
            return f;
          }
        }
      }
      return model.function(m, head);
    }

    /** A called name through the variable types ({@code client = httpx.Client()}) and the imports. */
    private String qualify(String head, Env env) {
      String first = head.contains(".") ? head.substring(0, head.indexOf('.')) : head;
      String type = env.types.get(first);
      return type != null ? type + head.substring(first.length()) : m.resolve(head);
    }

    private boolean isRequestObject(String dotted, Env env) {
      return env.requests.contains(dotted) || models.globalRequests.contains(m.resolve(dotted));
    }

    /** Argument values by parameter index of the callee: positional, keyword, *args and **kwargs. */
    private Map<Integer, Taint> mapArgs(Function target, String head, Node.Group callArgs, Env env) {
      // obj.method(x) and Class.classmethod(x) pass the receiver themselves; Class.method(obj, x) does not
      boolean bound = target.takesSelf() && head.contains(".") && (model.cls(m, head.substring(0, head.lastIndexOf('.'))) == null
        || target.decorators().stream().anyMatch(d -> d.name().equals("classmethod")));
      Map<Integer, Taint> out = mapArgs(target, bound ? 1 : 0, callArgs, env);
      if (bound) {
        // client.fetch(), self.fetch(): the receiver's attributes for fetch's self.url
        String prefix = head.substring(0, head.lastIndexOf('.') + 1);
        env.vars.forEach((key, t) -> {
          Integer id = key.startsWith(prefix) && key.indexOf('.', prefix.length()) < 0 ? attrIds.get(key.substring(prefix.length())) : null;
          if (id != null) {
            out.merge(ATTR + id, t, Taint::union);
          }
        });
      }
      return out;
    }

    /** Argument values by parameter index, the first positional one at {@code offset}. */
    private Map<Integer, Taint> mapArgs(Function target, int offset, Node.Group callArgs, Env env) {
      List<Function.Param> ps = target.params();
      int varArgs = -1;
      int kwArgs = -1;
      for (int i = 0; i < ps.size(); i++) {
        if (ps.get(i).stars() == 1) {
          varArgs = i;
        } else if (ps.get(i).stars() == 2) {
          kwArgs = i;
        }
      }
      Map<Integer, Taint> out = new HashMap<>();
      int pos = 0;
      for (List<Node> item : callArgs.items()) {
        String kw = Exprs.keyword(item);
        int index;
        List<Node> value = item;
        if (kw != null) {
          value = item.subList(2, item.size());
          Function.Param p = target.param(kw);
          index = p != null ? ps.indexOf(p) : kwArgs;
        } else if (Nodes.isLeaf(item.get(0), "**")) {
          index = kwArgs;
        } else if (Nodes.isLeaf(item.get(0), "*")) {
          index = varArgs;
        } else {
          index = offset + pos++;
          if (varArgs >= 0 && index >= varArgs) {
            index = varArgs;
          }
        }
        if (index >= 0 && index < ps.size()) {
          Taint t = item(value, env);
          if (!t.isEmpty()) {
            out.merge(index, t, Taint::union);
          }
        }
      }
      return out;
    }

    private Step step(Token t, String message) {
      return new Step(m, t, message);
    }
  }

  // ---- helpers

  private static String join(List<Token> names, int n) {
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < n; i++) {
      if (i > 0) {
        sb.append('.');
      }
      sb.append(names.get(i).text());
    }
    return sb.toString();
  }

  private static String lastName(String dotted) {
    String s = dotted.replaceAll("[\\[\\](),|].*", "");
    return s.substring(s.lastIndexOf('.') + 1);
  }

  /** Splits on a separator outside brackets. */
  private static List<String> topLevel(String s, char sep) {
    List<String> out = new ArrayList<>();
    int depth = 0;
    int from = 0;
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      if ("([{".indexOf(c) >= 0) {
        depth++;
      } else if (")]}".indexOf(c) >= 0) {
        depth--;
      } else if (c == sep && depth == 0) {
        out.add(s.substring(from, i));
        from = i + 1;
      }
    }
    out.add(s.substring(from));
    return out;
  }

  /** Whether a string token's text before its first field, %, or quote fixes a URL's host (see {@link #FIXED_TARGET}). */
  static boolean fixesTarget(String text) {
    int q = 0;
    while (q < text.length() && Character.isLetter(text.charAt(q))) {
      q++;
    }
    int from = Math.min(text.length(), q + (text.startsWith("\"\"\"", q) || text.startsWith("'''", q) ? 3 : 1));
    int to = from;
    while (to < text.length() && "{%'\"".indexOf(text.charAt(to)) < 0) {
      to++;
    }
    return FIXED_TARGET.matcher(text.substring(from, to)).find();
  }

  private static int indexOfIdent(List<Node> nodes, String ident) {
    for (int i = 0; i < nodes.size(); i++) {
      if (Nodes.isIdent(nodes.get(i), ident)) {
        return i;
      }
    }
    return -1;
  }

  /** Splits on top-level keyword leaves (and, or; for, in, if); empty parts are kept so indexes stay aligned. */
  private static List<List<Node>> splitIdents(List<Node> nodes, Set<String> idents) {
    List<List<Node>> out = new ArrayList<>();
    List<Node> part = new ArrayList<>();
    for (Node n : nodes) {
      Token t = Nodes.leaf(n);
      if (t != null && t.kind() == TokenKind.IDENT && idents.contains(t.text())) {
        out.add(part);
        part = new ArrayList<>();
      } else {
        part.add(n);
      }
    }
    out.add(part);
    return out;
  }

  private static List<Node> orEmpty(List<Node> nodes) {
    return nodes == null ? List.of() : nodes;
  }
}
