package io.github.snakeinprod.pythonweb.model;

import io.github.snakeinprod.pythonweb.lang.python.PyStatement;
import io.github.snakeinprod.pythonweb.parse.Chain;
import io.github.snakeinprod.pythonweb.parse.Node;

/**
 * One "@..." line of a def or class. {@code name}: the dotted name before the first call as written ("app.get",
 * "login_required", "method_decorator"); {@code resolved}: the same through the module's imports
 * ("django.contrib.auth.decorators.login_required"); {@code call}: the arguments, or null for a bare decorator.
 */
public record Decorator(PyStatement statement, Chain chain, String name, String resolved, Chain.Call call) {

  static Decorator of(PyStatement s, Module m) {
    Chain c = Exprs.chain(s.nodes().subList(1, s.nodes().size()));
    if (c == null) {
      java.util.List<Node> rest = s.nodes().subList(1, s.nodes().size());
      return new Decorator(s, null, Exprs.text(rest), Exprs.text(rest), null);
    }
    String name = Exprs.head(c);
    return new Decorator(s, c, name, m.resolve(name), Exprs.firstCall(c));
  }

  /** The last part of the name: "get" for {@code @router.get("/")}. */
  public String last() {
    return name.substring(name.lastIndexOf('.') + 1);
  }

  /** The part before the last name: "router" for {@code @router.get("/")}, "" for a plain name. */
  public String receiver() {
    int i = name.lastIndexOf('.');
    return i < 0 ? "" : name.substring(0, i);
  }
}
