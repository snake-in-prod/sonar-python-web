package io.github.snakeinprod.pythonweb.model;

import io.github.snakeinprod.pythonweb.lang.python.PyStatement;
import io.github.snakeinprod.pythonweb.parse.Node;
import io.github.snakeinprod.pythonweb.parse.Token;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** A class: its bases as written, decorators, methods and class-body assignments ({@code permission_classes = [...]}). */
public final class PyClass {

  private final Module module;
  private final PyStatement statement;
  private final List<Decorator> decorators;
  private final List<Function> methods = new ArrayList<>();
  private final Map<String, List<Node>> attributes = new LinkedHashMap<>();

  PyClass(Module module, PyStatement statement) {
    this.module = module;
    this.statement = statement;
    this.decorators = statement.decorators().stream().map(d -> Decorator.of(d, module)).toList();
    for (PyStatement s : statement.body()) {
      List<List<Node>> parts = Exprs.assignment(s.nodes());
      if (s.body().isEmpty() && parts.size() > 1) {
        String target = Exprs.dotted(Exprs.unannotated(parts.get(0)));
        if (target != null) {
          attributes.put(target, parts.get(parts.size() - 1));
        }
      }
    }
  }

  void add(Function f) {
    methods.add(f);
  }

  public Module module() {
    return module;
  }

  public PyStatement statement() {
    return statement;
  }

  public String name() {
    return statement.name();
  }

  public Token token() {
    return statement.nameToken();
  }

  /** Base classes as written: "LoginRequiredMixin", "viewsets.ModelViewSet". */
  public List<String> bases() {
    return statement.bases();
  }

  /** Base classes through the module's imports: "rest_framework.viewsets.ModelViewSet". */
  public List<String> resolvedBases() {
    return bases().stream().map(module::resolve).toList();
  }

  public List<Decorator> decorators() {
    return decorators;
  }

  public List<Function> methods() {
    return methods;
  }

  public Function method(String name) {
    return methods.stream().filter(f -> f.name().equals(name)).findFirst().orElse(null);
  }

  /** Class-body assignments: name to value nodes. */
  public Map<String, List<Node>> attributes() {
    return attributes;
  }

  public int firstLine() {
    return statement.first().line();
  }

  public int lastLine() {
    return statement.last().endLine();
  }

  @Override
  public String toString() {
    return module.path() + "#" + name();
  }
}
