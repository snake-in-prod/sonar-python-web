package io.github.snakeinprod.pythonweb.parse;

import java.util.List;

/**
 * A token tree: every bracket pair becomes a {@link Group} holding what is between the brackets, everything else is a
 * {@link Leaf}. The file itself is a {@link Group} with null brackets. Built by {@link TreeBuilder}.
 */
public sealed interface Node permits Node.Leaf, Node.Group {

  Token first();

  Token last();

  record Leaf(Token token) implements Node {
    @Override
    public Token first() {
      return token;
    }

    @Override
    public Token last() {
      return token;
    }

    @Override
    public String toString() {
      return token.text();
    }
  }

  /** {@code open} is "(", "[" or "{" (null for the file); {@code close} is null when the file ends before it. */
  record Group(Token open, Token close, List<Node> children) implements Node {

    public boolean is(String bracket) {
      return open != null && open.is(bracket);
    }

    @Override
    public Token first() {
      return open != null ? open : children.isEmpty() ? null : children.get(0).first();
    }

    @Override
    public Token last() {
      return close != null ? close : children.isEmpty() ? open : children.get(children.size() - 1).last();
    }

    /** Children split on top-level commas: the arguments of a call, the items of a list. Empty parts are dropped. */
    public List<List<Node>> items() {
      return Nodes.split(children, ",");
    }

    @Override
    public String toString() {
      return (open == null ? "" : open.text()) + children + (close == null ? "" : close.text());
    }
  }
}
