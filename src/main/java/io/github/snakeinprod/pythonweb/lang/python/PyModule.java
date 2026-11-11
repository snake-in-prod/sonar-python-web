package io.github.snakeinprod.pythonweb.lang.python;

import io.github.snakeinprod.pythonweb.parse.Node;
import io.github.snakeinprod.pythonweb.parse.Nodes;
import io.github.snakeinprod.pythonweb.parse.Token;
import io.github.snakeinprod.pythonweb.parse.TokenKind;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The statement tree of a Python file and its imports. {@code imports} maps a local name to the dotted path it comes
 * from: {@code import a.b as c} gives c -> a.b, {@code import a.b} gives a -> a and a.b -> a.b, {@code from a.b import c
 * as d} gives d -> a.b.c, {@code from . import x} gives x -> .x (relative paths are kept as written). Imports anywhere
 * in the file count, function-local ones and those inside try blocks included.
 */
public record PyModule(List<PyStatement> statements, Map<String, String> imports) {

  private static final Set<String> COMPOUND = Set.of("if", "elif", "else", "while", "for", "try", "except", "finally",
    "with", "def", "class", "match", "case");

  /** Builds the statements from the file's token tree (whose root holds the NEWLINE, INDENT and DEDENT leaves). */
  public static PyModule of(Node.Group root) {
    List<PyStatement> statements = new Builder(root.children()).block(false);
    Map<String, String> imports = new HashMap<>();
    for (PyStatement s : statements) {
      for (PyStatement x : s.walk()) {
        addImports(x, imports);
      }
    }
    return new PyModule(statements, Map.copyOf(imports));
  }

  /** The imports bound when the module loads: {@link #imports} without those inside functions, which run at call time. */
  public Map<String, String> loadImports() {
    Map<String, String> out = new HashMap<>();
    addLoadImports(statements, out);
    return out;
  }

  private static void addLoadImports(List<PyStatement> block, Map<String, String> out) {
    for (PyStatement s : block) {
      addImports(s, out);
      if (!s.keyword().equals("def")) {
        addLoadImports(s.body(), out);
      }
    }
  }

  /** Every statement, nested ones included, in source order. */
  public List<PyStatement> walk() {
    List<PyStatement> out = new ArrayList<>();
    statements.forEach(s -> out.addAll(s.walk()));
    return out;
  }

  /**
   * Replaces the longest imported prefix of a dotted name with where it comes from: with {@code from unittest import
   * mock}, "mock.patch.object" gives "unittest.mock.patch.object". Names not imported are returned as they are.
   */
  public String resolve(String dotted) {
    int cut = dotted.length();
    while (cut > 0) {
      String from = imports.get(dotted.substring(0, cut));
      if (from != null) {
        return from + dotted.substring(cut);
      }
      cut = dotted.lastIndexOf('.', cut - 1);
    }
    return dotted;
  }

  private static void addImports(PyStatement s, Map<String, String> imports) {
    List<Node> nodes = s.nodes();
    String kw = s.keyword();
    if (kw.equals("import")) {
      for (List<Node> item : Nodes.split(nodes.subList(1, nodes.size()), ",")) {
        String alias = alias(item);
        String path = dotted(item);
        if (alias != null) {
          imports.put(alias, path);
        } else if (!path.isEmpty()) {
          imports.put(path, path);
          String head = path.contains(".") ? path.substring(0, path.indexOf('.')) : path;
          imports.put(head, head);
        }
      }
    } else if (kw.equals("from")) {
      int imp = 1;
      while (imp < nodes.size() && !Nodes.isIdent(nodes.get(imp), "import")) {
        imp++;
      }
      if (imp >= nodes.size()) {
        return;
      }
      String module = dotted(nodes.subList(1, imp));
      List<Node> names = nodes.subList(imp + 1, nodes.size());
      if (names.size() == 1 && names.get(0) instanceof Node.Group g) {
        names = g.children();
      }
      for (List<Node> item : Nodes.split(names, ",")) {
        String name = dotted(item);
        if (!name.isEmpty() && !name.equals("*")) {
          String alias = alias(item);
          imports.put(alias != null ? alias : name, module.endsWith(".") ? module + name : module + "." + name);
        }
      }
    }
  }

  /** The token texts before "as", joined without spaces. */
  private static String dotted(List<Node> nodes) {
    StringBuilder sb = new StringBuilder();
    for (Node n : nodes) {
      if (Nodes.isIdent(n, "as")) {
        break;
      }
      Nodes.tokens(n).forEach(t -> sb.append(t.text()));
    }
    return sb.toString();
  }

  private static String alias(List<Node> item) {
    for (int i = 0; i + 1 < item.size(); i++) {
      if (Nodes.isIdent(item.get(i), "as") && Nodes.leaf(item.get(i + 1)) != null) {
        return Nodes.leaf(item.get(i + 1)).text();
      }
    }
    return null;
  }

  /** Splits the root children into statements on NEWLINE and nests them on INDENT / DEDENT. */
  private static final class Builder {
    private final List<Node> kids;
    private int i;

    Builder(List<Node> kids) {
      this.kids = kids;
    }

    List<PyStatement> block(boolean nested) {
      List<PyStatement> out = new ArrayList<>();
      List<PyStatement> decorators = new ArrayList<>();
      while (i < kids.size()) {
        TokenKind kind = layout(kids.get(i));
        if (kind == TokenKind.DEDENT) {
          i++;
          if (nested) {
            break;
          }
          continue;
        }
        if (kind == TokenKind.INDENT) {
          // an indented block no header opened: keep its statements at this level
          i++;
          out.addAll(block(true));
          continue;
        }
        if (kind == TokenKind.NEWLINE) {
          i++;
          continue;
        }
        int s = i;
        while (i < kids.size() && layout(kids.get(i)) == null) {
          i++;
        }
        List<Node> line = List.copyOf(kids.subList(s, i));
        if (i < kids.size() && layout(kids.get(i)) == TokenKind.NEWLINE) {
          i++;
        }
        if (Nodes.isLeaf(line.get(0), "@")) {
          decorators.add(new PyStatement(line, line.get(0).first(), List.of(), List.of()));
          continue;
        }
        PyStatement st = statement(line);
        String kw = st.keyword();
        if (kw.equals("def") || kw.equals("class")) {
          st = new PyStatement(st.nodes(), st.first(), List.copyOf(decorators), st.body());
        } else {
          out.addAll(decorators);
        }
        decorators.clear();
        out.add(st);
      }
      out.addAll(decorators);
      return out;
    }

    private PyStatement statement(List<Node> line) {
      PyStatement simple = new PyStatement(line, line.get(0).first(), List.of(), List.of());
      if (!COMPOUND.contains(simple.keyword())) {
        return simple;
      }
      int colon = 0;
      while (colon < line.size() && !(Nodes.isLeaf(line.get(colon), ":") && Nodes.leaf(line.get(colon)).kind() == TokenKind.OP)) {
        colon++;
      }
      if (colon >= line.size()) {
        return simple;
      }
      if (colon == line.size() - 1) {
        List<PyStatement> body = List.of();
        if (i < kids.size() && layout(kids.get(i)) == TokenKind.INDENT) {
          i++;
          body = List.copyOf(block(true));
        }
        return new PyStatement(line, simple.first(), List.of(), body);
      }
      List<Node> rest = line.subList(colon + 1, line.size());
      PyStatement suite = new PyStatement(rest, rest.get(0).first(), List.of(), List.of());
      return new PyStatement(line.subList(0, colon + 1), simple.first(), List.of(), List.of(suite));
    }

    private static TokenKind layout(Node n) {
      Token t = Nodes.leaf(n);
      return t != null && (t.kind() == TokenKind.NEWLINE || t.kind() == TokenKind.INDENT || t.kind() == TokenKind.DEDENT)
        ? t.kind() : null;
    }
  }
}
