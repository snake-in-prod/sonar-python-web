package io.github.snakeinprod.pythonweb.rules;

import io.github.snakeinprod.pythonweb.lang.python.PyStatement;
import io.github.snakeinprod.pythonweb.model.Endpoint;
import io.github.snakeinprod.pythonweb.model.Exprs;
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
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * A related object read on the loop variable of a loop (or comprehension) over {@code Model.objects....} whose queryset
 * has no select_related or prefetch_related: forward ForeignKey / OneToOneField reads, and {@code all()},
 * {@code count()}... on ManyToMany and reverse relations. Only project Django models with the default manager, and
 * querysets built inline or assigned once in the function.
 */
public class NPlusOneQuery implements PwRule {

  /** Queryset methods that keep model instances and fetch no relation. */
  private static final Set<String> QUERYSET = Set.of("all", "filter", "exclude", "order_by", "distinct", "reverse", "annotate",
    "alias", "only", "defer", "using");
  /** Reads of a related manager that a prefetch serves. */
  private static final Set<String> READS = Set.of("all", "count", "exists", "first", "last");

  /** Per model: relation attribute name to true for a single object (select_related), false for a manager (prefetch_related). */
  private final Map<PyClass, Map<String, Boolean>> relations = new HashMap<>();

  @Override
  public void check(RuleContext ctx) {
    Module m = ctx.module();
    for (PyStatement top : m.py().statements()) {
      for (PyStatement s : top.walk()) {
        Function fn = m.functionAt(s.first().line());
        if (fn == null || s.keyword().equals("def") || s.keyword().equals("class")) {
          continue;
        }
        List<Node> nodes = s.nodes();
        if (s.keyword().equals("for") && !s.isAsync() && nodes.size() > 4 && Nodes.isIdent(nodes.get(2), "in")) {
          List<Chain> body = new ArrayList<>();
          for (PyStatement b : s.body()) {
            for (PyStatement w : b.walk()) {
              body.addAll(Chains.in(w.group()));
            }
          }
          loop(ctx, fn, nodes.get(1), nodes.subList(3, nodes.size() - 1), body, s.first().line());
        }
        Nodes.groups(s.group(), g -> comprehension(ctx, fn, g, s.first().line()));
      }
    }
  }

  /** {@code [o.customer.name for o in Order.objects.all() if ...]}: one for clause only. */
  private void comprehension(RuleContext ctx, Function fn, Node.Group g, int line) {
    if (g.open() == null) {
      return;
    }
    List<Node> kids = g.children();
    int at = -1;
    for (int i = 0; i < kids.size(); i++) {
      if (Nodes.isIdent(kids.get(i), "for")) {
        if (at >= 0) {
          return;
        }
        at = i;
      }
    }
    if (at < 1 || at + 3 >= kids.size() || !Nodes.isIdent(kids.get(at + 2), "in")) {
      return;
    }
    int end = at + 3;
    while (end < kids.size() && !Nodes.isIdent(kids.get(end), "if")) {
      end++;
    }
    List<Node> uses = new ArrayList<>(kids.subList(0, at));
    uses.addAll(kids.subList(end, kids.size()));
    loop(ctx, fn, kids.get(at + 1), kids.subList(at + 3, end), Chains.in(new Node.Group(null, null, uses)), line);
  }

  private void loop(RuleContext ctx, Function fn, Node target, List<Node> iterable, List<Chain> uses, int line) {
    Token var = Nodes.leaf(target);
    Chain it = Exprs.chain(iterable);
    if (var == null || var.kind() != TokenKind.IDENT || it == null) {
      return;
    }
    if (it.segments().size() == 1) {
      List<Node> value = singleAssignment(fn, it.firstName(), line);
      it = value == null ? null : Exprs.chain(value);
      if (it == null) {
        return;
      }
    }
    PyClass model = querysetModel(ctx, it);
    Map<String, Boolean> rels = model == null ? Map.of() : relations(ctx.model(), model);
    if (rels.isEmpty()) {
      return;
    }
    Set<String> done = new HashSet<>();
    for (Chain c : uses) {
      List<Chain.Segment> segs = c.segments();
      if (!c.firstName().equals(var.text()) || segs.size() < 2 || !(segs.get(1) instanceof Chain.Name n)) {
        continue;
      }
      String rel = n.token().text();
      Boolean single = rels.get(rel);
      if (single == null || done.contains(rel)) {
        continue;
      }
      String fix;
      if (single) {
        done.add(rel);
        if (segs.size() == 2 && Nodes.isLeaf(c.after(), "=")) {
          continue; // set before any read: no query
        }
        fix = "select_related";
      } else if (segs.size() >= 4 && segs.get(2) instanceof Chain.Name r && READS.contains(r.token().text()) && segs.get(3) instanceof Chain.Call) {
        done.add(rel);
        fix = "prefetch_related";
      } else {
        continue;
      }
      List<Endpoint> eps = endpoints(ctx.model(), fn);
      String where = eps.isEmpty() ? "" : " of " + String.join("|", eps.get(0).methods()) + " " + eps.get(0).path();
      ctx.report(n.token(), n.token(), "Each " + model.name() + " of this loop" + where + " queries its \"" + rel + "\" again; add " + fix + "(\"" + rel
        + "\") to the queryset.", List.of(new Step(fn.module(), it.first(), "the " + model.name() + " queryset, without " + fix)));
    }
  }

  private static List<Endpoint> endpoints(WebModel model, Function fn) {
    for (Function f = fn; f != null; f = f.parent()) {
      if (!model.endpointsOf(f).isEmpty()) {
        return model.endpointsOf(f);
      }
    }
    return List.of();
  }

  /** {@code Order.objects.filter(...).order_by(...)[:10]} on a project Django model with the default manager, or null. */
  private static PyClass querysetModel(RuleContext ctx, Chain c) {
    List<Chain.Segment> segs = c.segments();
    int k = 0;
    while (k < segs.size() && segs.get(k) instanceof Chain.Name n && !n.token().text().equals("objects")) {
      k++;
    }
    if (k == 0 || k >= segs.size() || !(segs.get(k) instanceof Chain.Name) || segs.size() < k + 3) {
      return null;
    }
    for (int i = k + 1; i < segs.size(); i++) {
      if (segs.get(i) instanceof Chain.Name n && QUERYSET.contains(n.token().text()) && i + 1 < segs.size() && segs.get(i + 1) instanceof Chain.Call) {
        i++;
      } else if (!(segs.get(i) instanceof Chain.Index)) {
        return null;
      }
    }
    List<String> names = new ArrayList<>();
    for (int i = 0; i < k; i++) {
      names.add(((Chain.Name) segs.get(i)).token().text());
    }
    PyClass model = ctx.model().cls(ctx.module(), String.join(".", names));
    return model != null && isModel(ctx.model(), model) && !customManager(ctx.model(), model) ? model : null;
  }

  private static boolean isModel(WebModel model, PyClass c) {
    return model.externalBases(c).stream().anyMatch(b -> b.equals("django.db.models.Model") || b.equals("django.db.models.base.Model"));
  }

  /** An {@code objects} other than {@code models.Manager()}: its get_queryset may fetch relations. */
  private static boolean customManager(WebModel model, PyClass c) {
    for (PyClass k : model.hierarchy(c)) {
      List<Node> v = k.attributes().get("objects");
      if (v != null && !(k.module().resolve(Exprs.text(v)).equals("django.db.models.Manager()"))) {
        return true;
      }
    }
    return false;
  }

  private Map<String, Boolean> relations(WebModel model, PyClass c) {
    return relations.computeIfAbsent(c, x -> {
      Map<String, Boolean> out = new LinkedHashMap<>();
      for (PyClass k : model.hierarchy(c)) {
        for (Map.Entry<String, List<Node>> a : k.attributes().entrySet()) {
          String rel = relation(k.module(), a.getValue());
          if (rel != null) {
            out.putIfAbsent(a.getKey(), !rel.equals("ManyToManyField"));
          }
        }
      }
      for (Module m : model.modules()) {
        if (m.isTest()) {
          continue;
        }
        for (PyClass b : m.classes()) {
          if (isModel(model, b) && !abstractModel(b)) {
            reverse(model, b, c, out);
          }
        }
      }
      return out;
    });
  }

  /** Reverse accessors on {@code c} of the relations declared in {@code b}. */
  private static void reverse(WebModel model, PyClass b, PyClass c, Map<String, Boolean> out) {
    for (List<Node> value : b.attributes().values()) {
      String rel = relation(b.module(), value);
      Chain chain = rel == null ? null : Exprs.chain(value);
      Chain.Call call = chain == null ? null : Exprs.firstCall(chain);
      List<Node> to = call == null ? null : Exprs.arg(call, 0, "to");
      if (to == null || !targets(model, b, to, c)) {
        continue;
      }
      List<Node> named = Exprs.kwargs(call).get("related_name");
      String name = named == null ? null : Exprs.string(named);
      if (named != null && (name == null || name.endsWith("+") || name.contains("%"))) {
        continue;
      }
      if (name == null) {
        name = b.name().toLowerCase(Locale.ROOT) + (rel.equals("OneToOneField") ? "" : "_set");
      }
      out.putIfAbsent(name, rel.equals("OneToOneField"));
    }
  }

  private static boolean targets(WebModel model, PyClass b, List<Node> to, PyClass c) {
    String s = Exprs.string(to);
    if (s != null) {
      return s.equals("self") ? b == c : s.substring(s.lastIndexOf('.') + 1).equals(c.name());
    }
    String dotted = Exprs.dotted(to);
    return dotted != null && model.cls(b.module(), dotted) == c;
  }

  /** "ForeignKey", "OneToOneField" or "ManyToManyField" for a Django relation field declaration, else null. */
  private static String relation(Module m, List<Node> value) {
    Chain chain = Exprs.chain(value);
    if (chain == null || Exprs.firstCall(chain) == null) {
      return null;
    }
    String resolved = m.resolve(Exprs.head(chain));
    String last = resolved.substring(resolved.lastIndexOf('.') + 1);
    return resolved.startsWith("django.db.models.") && Set.of("ForeignKey", "OneToOneField", "ManyToManyField").contains(last) ? last : null;
  }

  private static boolean abstractModel(PyClass c) {
    for (PyStatement s : c.statement().body()) {
      if (s.keyword().equals("class") && "Meta".equals(s.name())
        && s.body().stream().anyMatch(x -> Exprs.text(x.nodes()).equals("abstract=True"))) {
        return true;
      }
    }
    return false;
  }

  /** The value of the only binding of a local name, a plain assignment before {@code line}; null otherwise. */
  private static List<Node> singleAssignment(Function fn, String name, int line) {
    List<Node> value = null;
    for (PyStatement top : fn.body()) {
      for (PyStatement s : top.walk()) {
        List<Node> nodes = s.nodes();
        if (Nodes.tokens(nodes).stream().anyMatch(t -> t.isIdent("prefetch_related_objects"))
          || nodes.size() > 1 && Nodes.isIdent(nodes.get(0), name) && Nodes.leaf(nodes.get(1)) != null
          && Nodes.leaf(nodes.get(1)).kind() == TokenKind.OP && Nodes.leaf(nodes.get(1)).text().matches("[-+*/|&^%@]=")) {
          return null;
        }
        if (!MutableDefaultInModel.rebinds(s, name)) {
          continue;
        }
        List<List<Node>> parts = Exprs.assignment(nodes);
        if (value != null || parts.size() != 2 || !name.equals(Exprs.dotted(Exprs.unannotated(parts.get(0)))) || s.first().line() >= line) {
          return null;
        }
        value = parts.get(1);
      }
    }
    return value;
  }
}
