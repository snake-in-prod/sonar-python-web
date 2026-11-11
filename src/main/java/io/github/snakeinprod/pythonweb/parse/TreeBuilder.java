package io.github.snakeinprod.pythonweb.parse;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;

/**
 * Builds the token tree from a token list: "(", "[" and "{" open a group, the matching closer ends it. A closer with no
 * open group, or one that does not match, is kept as a leaf; groups still open at the end are closed with a null
 * closer, so a broken file still gives a tree.
 */
public final class TreeBuilder {

  private TreeBuilder() {
  }

  public static Node.Group build(List<Token> tokens) {
    Deque<Token> opens = new ArrayDeque<>();
    Deque<List<Node>> stack = new ArrayDeque<>();
    List<Node> current = new ArrayList<>();
    for (Token t : tokens) {
      if (t.kind() == TokenKind.OP && isOpen(t.text())) {
        opens.push(t);
        stack.push(current);
        current = new ArrayList<>();
      } else if (t.kind() == TokenKind.OP && isClose(t.text()) && !opens.isEmpty() && matches(opens.peek().text(), t.text())) {
        Node.Group g = new Node.Group(opens.pop(), t, List.copyOf(current));
        current = stack.pop();
        current.add(g);
      } else {
        current.add(new Node.Leaf(t));
      }
    }
    while (!opens.isEmpty()) {
      Node.Group g = new Node.Group(opens.pop(), null, List.copyOf(current));
      current = stack.pop();
      current.add(g);
    }
    return new Node.Group(null, null, List.copyOf(current));
  }

  private static boolean isOpen(String s) {
    return s.equals("(") || s.equals("[") || s.equals("{");
  }

  private static boolean isClose(String s) {
    return s.equals(")") || s.equals("]") || s.equals("}");
  }

  private static boolean matches(String open, String close) {
    return open.equals("(") && close.equals(")") || open.equals("[") && close.equals("]") || open.equals("{") && close.equals("}");
  }
}
