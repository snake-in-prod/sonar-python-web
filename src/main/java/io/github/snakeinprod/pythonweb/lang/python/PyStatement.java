package io.github.snakeinprod.pythonweb.lang.python;

import io.github.snakeinprod.pythonweb.parse.Node;
import io.github.snakeinprod.pythonweb.parse.Nodes;
import io.github.snakeinprod.pythonweb.parse.Token;
import io.github.snakeinprod.pythonweb.parse.TokenKind;
import java.util.ArrayList;
import java.util.List;

/**
 * One logical line of Python. Built by {@link PyModule#of}.
 *
 * @param nodes      the token tree children of the line, without its NEWLINE; for a compound statement only its header,
 *                   up to and including the ":" ({@code if x: return 1} gives [if, x, :] and a body of [return, 1])
 * @param first      the first token of the line (for a decorated def, "def" or "async", not the "@")
 * @param decorators the "@..." lines right before a def or class, in order
 * @param body       the indented block, or the one-line suite after the ":", empty for a simple statement
 */
public record PyStatement(List<Node> nodes, Token first, List<PyStatement> decorators, List<PyStatement> body) {

  /** A def parameter: {@code *args} has {@code varArgs}, {@code **kwargs} has {@code kwArgs}. */
  public record Param(String name, Token token, boolean varArgs, boolean kwArgs) {
  }

  /** The first identifier of the line, skipping "async": "def", "class", "with", "assert", "return", or a name. */
  public String keyword() {
    Token t = Nodes.leaf(nodes.get(isAsync() ? 1 : 0));
    return t != null && t.kind() == TokenKind.IDENT ? t.text() : "";
  }

  /** {@code async def}, {@code async with}, {@code async for}. */
  public boolean isAsync() {
    return nodes.size() > 1 && Nodes.isIdent(nodes.get(0), "async") && Nodes.leaf(nodes.get(1)) != null
      && Nodes.leaf(nodes.get(1)).kind() == TokenKind.IDENT;
  }

  /** The name token of a def or class, or null. */
  public Token nameToken() {
    String kw = keyword();
    int i = isAsync() ? 2 : 1;
    if ((kw.equals("def") || kw.equals("class")) && i < nodes.size()) {
      Token t = Nodes.leaf(nodes.get(i));
      return t != null && t.kind() == TokenKind.IDENT ? t : null;
    }
    return null;
  }

  /** The name of a def or class, or null. */
  public String name() {
    Token t = nameToken();
    return t == null ? null : t.text();
  }

  /** The parameters of a def in order (self and cls included, defaults and annotations ignored, bare "*" and "/" left out). */
  public List<Param> params() {
    Node.Group g = keyword().equals("def") ? groupAfterName() : null;
    if (g == null) {
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
      if (t != null && t.kind() == TokenKind.IDENT) {
        out.add(new Param(t.text(), t, stars == 1, stars == 2));
      }
    }
    return out;
  }

  /** The base classes of a class as written ("TestCase", "unittest.TestCase"); keyword arguments left out. */
  public List<String> bases() {
    Node.Group g = keyword().equals("class") ? groupAfterName() : null;
    if (g == null) {
      return List.of();
    }
    List<String> out = new ArrayList<>();
    for (List<Node> item : g.items()) {
      if (item.stream().noneMatch(x -> Nodes.isLeaf(x, "=")) && !Nodes.isLeaf(item.get(0), "*") && !Nodes.isLeaf(item.get(0), "**")) {
        StringBuilder sb = new StringBuilder();
        Nodes.tokens(item).forEach(t -> sb.append(t.text()));
        out.add(sb.toString());
      }
    }
    return out;
  }

  /** This statement and every statement nested in its body, depth first in source order. Decorators are not included. */
  public List<PyStatement> walk() {
    List<PyStatement> out = new ArrayList<>();
    collect(this, out);
    return out;
  }

  /** The last token of the statement, its body included. */
  public Token last() {
    return body.isEmpty() ? nodes.get(nodes.size() - 1).last() : body.get(body.size() - 1).last();
  }

  /** The line as a group with no brackets, for {@link io.github.snakeinprod.pythonweb.parse.Chains}. */
  public Node.Group group() {
    return new Node.Group(null, null, nodes);
  }

  private Node.Group groupAfterName() {
    int i = isAsync() ? 3 : 2;
    return i < nodes.size() && nodes.get(i) instanceof Node.Group g && g.is("(") ? g : null;
  }

  private static void collect(PyStatement s, List<PyStatement> out) {
    out.add(s);
    for (PyStatement b : s.body) {
      collect(b, out);
    }
  }

  @Override
  public String toString() {
    return Nodes.text(nodes) + (body.isEmpty() ? "" : " " + body);
  }
}
