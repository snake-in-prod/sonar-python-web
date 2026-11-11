package io.github.snakeinprod.pythonweb.model;

import io.github.snakeinprod.pythonweb.lang.python.PyStatement;
import io.github.snakeinprod.pythonweb.parse.Node;
import io.github.snakeinprod.pythonweb.parse.Nodes;
import io.github.snakeinprod.pythonweb.parse.Token;
import io.github.snakeinprod.pythonweb.parse.TokenKind;
import java.util.ArrayList;
import java.util.List;

/** A def: a module function, a method ({@code owner} set) or a nested function ({@code parent} set). */
public final class Function {

  /**
   * A parameter. {@code annotation} and {@code defaultValue} are the nodes after ":" and "=" (empty when absent);
   * {@code stars} is 1 for {@code *args}, 2 for {@code **kwargs}.
   */
  public record Param(String name, Token token, List<Node> annotation, List<Node> defaultValue, int stars) {

    /** The annotation as text without spaces ("Annotated[User,Depends(get_user)]"), "" when absent. */
    public String annotationText() {
      return Exprs.text(annotation);
    }
  }

  private final Module module;
  private final PyStatement def;
  private final PyClass owner;
  private final Function parent;
  private final List<Param> params;
  private final List<Decorator> decorators;

  Function(Module module, PyStatement def, PyClass owner, Function parent) {
    this.module = module;
    this.def = def;
    this.owner = owner;
    this.parent = parent;
    this.params = params(def);
    this.decorators = def.decorators().stream().map(d -> Decorator.of(d, module)).toList();
  }

  public Module module() {
    return module;
  }

  public PyStatement def() {
    return def;
  }

  /** The class of a method, or null. */
  public PyClass owner() {
    return owner;
  }

  /** The enclosing def of a nested function, or null. */
  public Function parent() {
    return parent;
  }

  public String name() {
    return def.name();
  }

  /** The name token, to report on. */
  public Token token() {
    return def.nameToken();
  }

  /** "create_item", or "ItemViewSet.create" for a method. */
  public String label() {
    return owner == null ? name() : owner.name() + "." + name();
  }

  public boolean isAsync() {
    return def.isAsync();
  }

  public List<Param> params() {
    return params;
  }

  /** The parameter of that name, or null. */
  public Param param(String name) {
    return params.stream().filter(p -> p.name().equals(name)).findFirst().orElse(null);
  }

  public List<Decorator> decorators() {
    return decorators;
  }

  /** The statements of the body. */
  public List<PyStatement> body() {
    return def.body();
  }

  /** First line of the def (decorators excluded) and last line of its body. */
  public int firstLine() {
    return def.first().line();
  }

  public int lastLine() {
    return def.last().endLine();
  }

  /** A method that takes the instance first: in a class and not a staticmethod. */
  public boolean takesSelf() {
    return owner != null && decorators.stream().noneMatch(d -> d.name().equals("staticmethod"));
  }

  /** The return annotation ({@code -> Session}), empty when there is none. */
  public List<Node> returns() {
    List<Node> nodes = def.nodes();
    for (int i = 0; i < nodes.size(); i++) {
      if (Nodes.isLeaf(nodes.get(i), "->")) {
        int end = Nodes.isLeaf(nodes.get(nodes.size() - 1), ":") ? nodes.size() - 1 : nodes.size();
        return i + 1 < end ? nodes.subList(i + 1, end) : List.of();
      }
    }
    return List.of();
  }

  private static List<Param> params(PyStatement def) {
    int i = def.isAsync() ? 3 : 2;
    List<Node> nodes = def.nodes();
    if (i >= nodes.size() || !(nodes.get(i) instanceof Node.Group g) || !g.is("(")) {
      return List.of();
    }
    List<Param> out = new ArrayList<>();
    for (List<Node> item : g.items()) {
      int stars = 0;
      int j = 0;
      while (j < item.size() && (Nodes.isLeaf(item.get(j), "*") || Nodes.isLeaf(item.get(j), "**"))) {
        stars += Nodes.leaf(item.get(j)).text().length();
        j++;
      }
      Token t = j < item.size() ? Nodes.leaf(item.get(j)) : null;
      if (t == null || t.kind() != TokenKind.IDENT) {
        continue;
      }
      int colon = -1;
      int eq = -1;
      for (int k = j + 1; k < item.size(); k++) {
        if (colon < 0 && eq < 0 && Nodes.isLeaf(item.get(k), ":")) {
          colon = k;
        } else if (eq < 0 && Nodes.isLeaf(item.get(k), "=")) {
          eq = k;
        }
      }
      List<Node> annotation = colon < 0 ? List.of() : item.subList(colon + 1, eq < 0 ? item.size() : eq);
      List<Node> value = eq < 0 ? List.of() : item.subList(eq + 1, item.size());
      out.add(new Param(t.text(), t, List.copyOf(annotation), List.copyOf(value), stars));
    }
    return List.copyOf(out);
  }

  @Override
  public String toString() {
    return module.path() + "#" + label();
  }
}
