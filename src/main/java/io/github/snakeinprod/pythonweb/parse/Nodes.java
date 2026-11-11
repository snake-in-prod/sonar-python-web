package io.github.snakeinprod.pythonweb.parse;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/** Small helpers over token trees. */
public final class Nodes {

  private Nodes() {
  }

  /** Splits a node list on top-level leaves with the given text (a comma, a semicolon). Empty parts are dropped. */
  public static List<List<Node>> split(List<Node> nodes, String separator) {
    List<List<Node>> out = new ArrayList<>();
    List<Node> part = new ArrayList<>();
    for (Node n : nodes) {
      if (n instanceof Node.Leaf l && l.token().is(separator) && l.token().kind() == TokenKind.OP) {
        if (!part.isEmpty()) {
          out.add(part);
        }
        part = new ArrayList<>();
      } else {
        part.add(n);
      }
    }
    if (!part.isEmpty()) {
      out.add(part);
    }
    return out;
  }

  /** All tokens of the nodes in source order, brackets included. */
  public static List<Token> tokens(List<? extends Node> nodes) {
    List<Token> out = new ArrayList<>();
    for (Node n : nodes) {
      collect(n, out);
    }
    return out;
  }

  public static List<Token> tokens(Node node) {
    List<Token> out = new ArrayList<>();
    collect(node, out);
    return out;
  }

  private static void collect(Node n, List<Token> out) {
    if (n instanceof Node.Leaf l) {
      out.add(l.token());
    } else if (n instanceof Node.Group g) {
      if (g.open() != null) {
        out.add(g.open());
      }
      for (Node c : g.children()) {
        collect(c, out);
      }
      if (g.close() != null) {
        out.add(g.close());
      }
    }
  }

  /** Source-like text of the nodes: token texts joined with one space. For messages and comparisons, not for display. */
  public static String text(List<? extends Node> nodes) {
    StringBuilder sb = new StringBuilder();
    for (Token t : tokens(nodes)) {
      if (t.kind() == TokenKind.NEWLINE || t.kind() == TokenKind.INDENT || t.kind() == TokenKind.DEDENT) {
        continue;
      }
      if (!sb.isEmpty()) {
        sb.append(' ');
      }
      sb.append(t.text());
    }
    return sb.toString();
  }

  public static String text(Node node) {
    return text(List.of(node));
  }

  /** Visits every group, depth first, the given one included. */
  public static void groups(Node.Group root, Consumer<Node.Group> visitor) {
    visitor.accept(root);
    for (Node c : root.children()) {
      if (c instanceof Node.Group g) {
        groups(g, visitor);
      }
    }
  }

  /** True when the node is a leaf with exactly this text. */
  public static boolean isLeaf(Node n, String text) {
    return n instanceof Node.Leaf l && l.token().is(text);
  }

  public static boolean isIdent(Node n, String text) {
    return n instanceof Node.Leaf l && l.token().isIdent(text);
  }

  /** The leaf token of a node, or null when it is a group. */
  public static Token leaf(Node n) {
    return n instanceof Node.Leaf l ? l.token() : null;
  }
}
