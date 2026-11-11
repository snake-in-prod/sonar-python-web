package io.github.snakeinprod.pythonweb.rules;

import io.github.snakeinprod.pythonweb.lang.python.PyStatement;
import io.github.snakeinprod.pythonweb.parse.Node;
import io.github.snakeinprod.pythonweb.parse.Nodes;
import io.github.snakeinprod.pythonweb.parse.Token;
import io.github.snakeinprod.pythonweb.taint.Step;
import java.util.List;

/** Source around the steps of a taint path, for the checks a taint rule makes beyond the engine's finding. */
final class SinkCalls {

  private SinkCalls() {
  }

  /** The tokens of the line (a compound statement's header) holding the step, f-string fields included by position. */
  static List<Token> statement(Step s) {
    Token t = s.token();
    for (PyStatement st : s.module().py().walk()) {
      List<Token> tokens = Nodes.tokens(st.nodes());
      if (!tokens.isEmpty() && before(tokens.get(0), t) && before(t, tokens.get(tokens.size() - 1))) {
        return tokens;
      }
    }
    return List.of();
  }

  /** The argument group of the call whose name is the sink step's token, or null. */
  static Node.Group args(Step sink) {
    Token t = sink.token();
    for (PyStatement st : sink.module().py().walk()) {
      Node.Group[] found = new Node.Group[1];
      Nodes.groups(st.group(), g -> {
        List<Node> c = g.children();
        for (int i = 0; i + 1 < c.size() && found[0] == null; i++) {
          if (Nodes.leaf(c.get(i)) != null && Nodes.leaf(c.get(i)).equals(t) && c.get(i + 1) instanceof Node.Group a && a.is("(")) {
            found[0] = a;
          }
        }
      });
      if (found[0] != null) {
        return found[0];
      }
    }
    return null;
  }

  private static boolean before(Token a, Token b) {
    return a.line() < b.line() || a.line() == b.line() && a.column() <= b.column();
  }
}
