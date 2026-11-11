package io.github.snakeinprod.pythonweb.parse;

import java.util.ArrayList;
import java.util.List;

/**
 * A member and call chain such as {@code request.GET.get("q")}, {@code self.assertEqual(a, b)},
 * {@code mock.patch("a.b")} or {@code os.path.join(a, b)}: a name, then names after ".",
 * calls and index groups. Found by {@link Chains#in}. {@code container} is the group whose children hold the chain,
 * {@code from}..{@code to} (exclusive) its children range, so rules can look at what comes before and after it.
 */
public record Chain(List<Segment> segments, Node.Group container, int from, int to) {

  public sealed interface Segment permits Name, Call, Index {
  }

  /** A name and the accessor before it ("" for the first one, else "."). */
  public record Name(Token token, String accessor) implements Segment {
  }

  public record Call(Node.Group args) implements Segment {
    public List<List<Node>> items() {
      return args.items();
    }
  }

  public record Index(Node.Group index) implements Segment {
  }

  /** The names only: {@code expect(x).resolves.toEqual(1)} gives [expect, resolves, toEqual]. */
  public List<String> names() {
    List<String> out = new ArrayList<>();
    for (Segment s : segments) {
      if (s instanceof Name n) {
        out.add(n.token().text());
      }
    }
    return out;
  }

  /** Names joined by ".": "expect.resolves.toEqual", "self.assertEqual", "mock.patch". */
  public String path() {
    return String.join(".", names());
  }

  public String firstName() {
    return ((Name) segments.get(0)).token().text();
  }

  public String lastName() {
    for (int i = segments.size() - 1; i >= 0; i--) {
      if (segments.get(i) instanceof Name n) {
        return n.token().text();
      }
    }
    return "";
  }

  /** Every call segment, in order. */
  public List<Call> calls() {
    List<Call> out = new ArrayList<>();
    for (Segment s : segments) {
      if (s instanceof Call c) {
        out.add(c);
      }
    }
    return out;
  }

  /** The call right after the name at {@code nameIndex} (0 = first name), or null. */
  public Call callAfter(int nameIndex) {
    int seen = -1;
    for (int i = 0; i < segments.size(); i++) {
      if (segments.get(i) instanceof Name) {
        seen++;
        if (seen == nameIndex) {
          return i + 1 < segments.size() && segments.get(i + 1) instanceof Call c ? c : null;
        }
      }
    }
    return null;
  }

  /** The chain ends with a call: {@code a.b()} yes, {@code a.b} no. */
  public boolean endsWithCall() {
    return segments.get(segments.size() - 1) instanceof Call;
  }

  public Token first() {
    return ((Name) segments.get(0)).token();
  }

  public Token last() {
    Segment s = segments.get(segments.size() - 1);
    return switch (s) {
      case Name n -> n.token();
      case Call c -> c.args().last();
      case Index x -> x.index().last();
    };
  }

  /** The node right before the chain in its container, or null. */
  public Node before() {
    return from > 0 ? container.children().get(from - 1) : null;
  }

  /** The node right after the chain in its container, or null. */
  public Node after() {
    return to < container.children().size() ? container.children().get(to) : null;
  }

  public boolean precededBy(String text) {
    return Nodes.isLeaf(before(), text);
  }

  public int line() {
    return first().line();
  }

  @Override
  public String toString() {
    return path() + "@" + line();
  }
}
