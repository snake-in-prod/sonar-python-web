package io.github.snakeinprod.pythonweb.model;

import io.github.snakeinprod.pythonweb.lang.python.PyModule;
import io.github.snakeinprod.pythonweb.lang.python.PyStatement;
import io.github.snakeinprod.pythonweb.parse.Node;
import io.github.snakeinprod.pythonweb.parse.ParsedFile;
import io.github.snakeinprod.pythonweb.parse.TokenKind;
import io.github.snakeinprod.pythonweb.parse.Nodes;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/** One Python file: its parse, functions (methods and nested ones included), classes, assignments and frameworks. */
public final class Module {

  /** test_*.py, *_test.py, conftest.py and anything under tests/ or fixtures/. */
  private static final Pattern TEST = Pattern.compile("(^|.*/)(test_[^/]*|[^/]*_test\\.py|conftest\\.py)$|(^|.*/)(tests|fixtures)/.*");

  private final String path;
  private final ParsedFile file;
  private final boolean test;
  private final List<Function> functions = new ArrayList<>();
  private final List<PyClass> classes = new ArrayList<>();
  private final Map<String, List<List<Node>>> assignments = new LinkedHashMap<>();
  private final Set<Framework> frameworks = EnumSet.noneOf(Framework.class);

  Module(String path, String source) {
    this.path = path;
    this.file = ParsedFile.parse(path, source);
    this.test = isTestPath(path);
    collect(file.py().statements(), null, null, true);
    for (String dotted : file.py().imports().values()) {
      Framework f = Framework.of(dotted);
      if (f != null) {
        frameworks.add(f);
      }
    }
    if (frameworks.contains(Framework.DRF)) {
      frameworks.add(Framework.DJANGO);
    }
  }

  /** Test file: test_*.py, *_test.py, conftest.py, or under a tests/ or fixtures/ directory. */
  public static boolean isTestPath(String path) {
    return TEST.matcher(path).matches() && path.endsWith(".py");
  }

  private void collect(List<PyStatement> block, PyClass owner, Function parent, boolean topLevel) {
    for (PyStatement s : block) {
      String kw = s.keyword();
      if (kw.equals("def") && s.name() != null) {
        Function f = new Function(this, s, owner, parent);
        functions.add(f);
        if (owner != null) {
          owner.add(f);
        }
        collect(s.body(), null, f, false);
      } else if (kw.equals("class") && s.name() != null) {
        PyClass c = new PyClass(this, s);
        classes.add(c);
        collect(s.body(), c, parent, false);
      } else {
        if (topLevel && s.body().isEmpty()) {
          assignment(s);
        }
        // module-level if / try blocks still define module names
        collect(s.body(), owner, parent, topLevel && owner == null && parent == null);
      }
    }
  }

  private void assignment(PyStatement s) {
    List<Node> nodes = s.nodes();
    for (int i = 1; i < nodes.size(); i++) {
      if (Nodes.isLeaf(nodes.get(i), "+=") && Nodes.leaf(nodes.get(i)).kind() == TokenKind.OP) {
        String target = Exprs.dotted(nodes.subList(0, i));
        if (target != null) {
          assignments.computeIfAbsent(target, k -> new ArrayList<>()).add(List.copyOf(nodes.subList(i + 1, nodes.size())));
        }
        return;
      }
    }
    List<List<Node>> parts = Exprs.assignment(nodes);
    if (parts.size() < 2) {
      return;
    }
    List<Node> value = parts.get(parts.size() - 1);
    for (List<Node> t : parts.subList(0, parts.size() - 1)) {
      String target = Exprs.dotted(Exprs.unannotated(t));
      if (target != null) {
        List<List<Node>> values = new ArrayList<>();
        values.add(value);
        assignments.put(target, values);
      }
    }
  }

  public String path() {
    return path;
  }

  public ParsedFile file() {
    return file;
  }

  public PyModule py() {
    return file.py();
  }

  public boolean isTest() {
    return test;
  }

  /** Every def of the file: module functions, methods, nested functions. */
  public List<Function> functions() {
    return functions;
  }

  /** The module-level function of that name, or null. */
  public Function function(String name) {
    return functions.stream().filter(f -> f.owner() == null && f.parent() == null && f.name().equals(name)).findFirst().orElse(null);
  }

  public List<PyClass> classes() {
    return classes;
  }

  public PyClass cls(String name) {
    return classes.stream().filter(c -> c.name().equals(name)).findFirst().orElse(null);
  }

  /**
   * Module-level assignments ({@code if} and {@code try} blocks included): name to the value nodes, the last plain
   * assignment first, then each {@code +=} in order.
   */
  public Map<String, List<List<Node>>> assignments() {
    return assignments;
  }

  /** The value of the last plain module-level assignment of a name, or null. */
  public List<Node> assignment(String name) {
    List<List<Node>> v = assignments.get(name);
    return v == null ? null : v.get(0);
  }

  /** The frameworks this file imports. */
  public Set<Framework> frameworks() {
    return frameworks;
  }

  /** A dotted name through the imports of the file, see {@link PyModule#resolve}. */
  public String resolve(String dotted) {
    return file.py().resolve(dotted);
  }

  /** The innermost function whose lines hold this line, or null. */
  public Function functionAt(int line) {
    Function best = null;
    for (Function f : functions) {
      if (f.firstLine() <= line && line <= f.lastLine() && (best == null || f.firstLine() >= best.firstLine())) {
        best = f;
      }
    }
    return best;
  }

  @Override
  public String toString() {
    return path;
  }
}
