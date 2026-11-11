package io.github.snakeinprod.pythonweb.model;

import io.github.snakeinprod.pythonweb.parse.Chain;
import io.github.snakeinprod.pythonweb.parse.Chains;
import io.github.snakeinprod.pythonweb.parse.Node;
import io.github.snakeinprod.pythonweb.parse.Nodes;
import io.github.snakeinprod.pythonweb.parse.Token;
import io.github.snakeinprod.pythonweb.parse.TokenKind;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Small readings of expressions on the token tree: string literals, call arguments, dotted names, single chains. */
public final class Exprs {

  private Exprs() {
  }

  /** The chain that spans all of {@code nodes}, or null ({@code views.index} yes, {@code a + b} no). */
  public static Chain chain(List<Node> nodes) {
    if (nodes.isEmpty()) {
      return null;
    }
    List<Chain> cs = Chains.direct(new Node.Group(null, null, nodes));
    return cs.size() == 1 && cs.get(0).from() == 0 && cs.get(0).to() == nodes.size() ? cs.get(0) : null;
  }

  /** The names of a chain before its first call or index: {@code a.b.c(x).d} gives "a.b.c". */
  public static String head(Chain c) {
    List<String> names = new ArrayList<>();
    for (Chain.Segment s : c.segments()) {
      if (!(s instanceof Chain.Name n)) {
        break;
      }
      names.add(n.token().text());
    }
    return String.join(".", names);
  }

  /** Number of name segments before the first call or index. */
  public static int headSize(Chain c) {
    int k = 0;
    for (Chain.Segment s : c.segments()) {
      if (!(s instanceof Chain.Name)) {
        break;
      }
      k++;
    }
    return k;
  }

  /** The call right after the head ({@code f(x)} of {@code f(x).y}), or null. */
  public static Chain.Call firstCall(Chain c) {
    int k = headSize(c);
    return k < c.segments().size() && c.segments().get(k) instanceof Chain.Call call ? call : null;
  }

  /** A dotted name spanning the nodes ({@code views.index}), or null. */
  public static String dotted(List<Node> nodes) {
    Chain c = chain(nodes);
    return c != null && headSize(c) == c.segments().size() ? head(c) : null;
  }

  /** Positional arguments of a call (no "name=" and no "*"/"**" ones). */
  public static List<List<Node>> positional(Chain.Call call) {
    List<List<Node>> out = new ArrayList<>();
    for (List<Node> item : call.items()) {
      if (keyword(item) == null && !Nodes.isLeaf(item.get(0), "*") && !Nodes.isLeaf(item.get(0), "**")) {
        out.add(item);
      }
    }
    return out;
  }

  /** Keyword arguments of a call: name to value nodes, in order. */
  public static Map<String, List<Node>> kwargs(Chain.Call call) {
    Map<String, List<Node>> out = new LinkedHashMap<>();
    for (List<Node> item : call.items()) {
      String k = keyword(item);
      if (k != null) {
        out.put(k, item.subList(2, item.size()));
      }
    }
    return out;
  }

  /** The name of a keyword argument item ({@code shell=True} gives "shell"), or null. */
  public static String keyword(List<Node> item) {
    return item.size() > 2 && Nodes.leaf(item.get(0)) != null && Nodes.leaf(item.get(0)).kind() == TokenKind.IDENT
      && Nodes.isLeaf(item.get(1), "=") ? Nodes.leaf(item.get(0)).text() : null;
  }

  /** Argument {@code index} or keyword {@code name}, or null. */
  public static List<Node> arg(Chain.Call call, int index, String name) {
    List<Node> k = name == null ? null : kwargs(call).get(name);
    if (k != null) {
      return k;
    }
    List<List<Node>> p = positional(call);
    return index >= 0 && index < p.size() ? p.get(index) : null;
  }

  /** The value of a plain string literal (adjacent literals joined), or null for anything else, f-strings included. */
  public static String string(List<Node> nodes) {
    if (nodes == null || nodes.isEmpty()) {
      return null;
    }
    if (nodes.size() == 1 && nodes.get(0) instanceof Node.Group g && g.is("(") && g.items().size() == 1) {
      // ("a" "b") spread over lines
      return string(g.items().get(0));
    }
    StringBuilder sb = new StringBuilder();
    for (Node n : nodes) {
      Token t = Nodes.leaf(n);
      if (t == null || t.kind() != TokenKind.STRING) {
        return null;
      }
      String v = literal(t);
      if (v == null) {
        return null;
      }
      sb.append(v);
    }
    return sb.toString();
  }

  /** The value of a string token without prefix and quotes, or null for an f-string. Escapes are kept as written. */
  public static String literal(Token t) {
    String s = t.text();
    int q = 0;
    while (q < s.length() && s.charAt(q) != '\'' && s.charAt(q) != '"') {
      q++;
    }
    if (s.substring(0, q).toLowerCase(Locale.ROOT).contains("f") || q >= s.length()) {
      return null;
    }
    String body = s.substring(q);
    int quote = body.startsWith("\"\"\"") || body.startsWith("'''") ? 3 : 1;
    return body.length() >= 2 * quote ? body.substring(quote, body.length() - quote) : "";
  }

  /** The string items of a list or tuple literal ({@code ["GET", "POST"]}), or of a single string; empty otherwise. */
  public static List<String> strings(List<Node> nodes) {
    List<String> out = new ArrayList<>();
    if (nodes == null) {
      return out;
    }
    String single = string(nodes);
    if (single != null) {
      out.add(single);
    } else if (nodes.size() == 1 && nodes.get(0) instanceof Node.Group g) {
      for (List<Node> item : g.items()) {
        String s = string(item);
        if (s != null) {
          out.add(s);
        }
      }
    }
    return out;
  }

  /** The items of a list, tuple or set literal; the nodes themselves as one item otherwise. */
  public static List<List<Node>> items(List<Node> nodes) {
    if (nodes.size() == 1 && nodes.get(0) instanceof Node.Group g && !g.is("{")) {
      return g.items();
    }
    return List.of(nodes);
  }

  /** Source-like text without spaces around dots and brackets, for matching names in an expression. */
  public static String text(List<? extends Node> nodes) {
    StringBuilder sb = new StringBuilder();
    for (Token t : Nodes.tokens(nodes)) {
      if (t.kind() != TokenKind.NEWLINE && t.kind() != TokenKind.INDENT && t.kind() != TokenKind.DEDENT) {
        if (!sb.isEmpty() && t.kind() == TokenKind.IDENT && Character.isJavaIdentifierPart(sb.charAt(sb.length() - 1))) {
          sb.append(' ');
        }
        sb.append(t.text());
      }
    }
    return sb.toString();
  }

  /** The nodes split on top-level "=" (assignment targets and the value last); one part when there is none. */
  public static List<List<Node>> assignment(List<Node> nodes) {
    List<List<Node>> out = new ArrayList<>();
    List<Node> part = new ArrayList<>();
    for (Node n : nodes) {
      if (n instanceof Node.Leaf l && l.token().kind() == TokenKind.OP && l.token().is("=")) {
        out.add(part);
        part = new ArrayList<>();
      } else {
        part.add(n);
      }
    }
    out.add(part);
    return out;
  }

  /** An assignment target without its annotation: {@code x: int} gives [x]. */
  public static List<Node> unannotated(List<Node> target) {
    for (int i = 1; i < target.size(); i++) {
      if (Nodes.isLeaf(target.get(i), ":")) {
        return target.subList(0, i);
      }
    }
    return target;
  }
}
