package io.github.snakeinprod.pythonweb.model;

import io.github.snakeinprod.pythonweb.parse.Chain;
import io.github.snakeinprod.pythonweb.parse.Node;
import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * The project model: every Python file as a {@link Module}, the frameworks they import, the endpoints of the FastAPI,
 * Django (REST framework included) and Flask apps, and name resolution across modules. Built once per analysis.
 */
public final class WebModel {

  /** A module and a dotted name inside it ("" for the module itself). */
  public record Ref(Module module, String name) {
  }

  private final Map<String, Module> modules = new LinkedHashMap<>();
  private final List<String> skipped = new ArrayList<>();
  private final Set<Framework> frameworks = EnumSet.noneOf(Framework.class);
  private final List<Endpoint> endpoints = new ArrayList<>();
  private final Map<Function, List<Endpoint>> byFunction = new IdentityHashMap<>();
  private boolean usesAuth;

  private WebModel() {
  }

  public static WebModel build(Project project) {
    WebModel model = new WebModel();
    for (String path : new TreeSet<>(project.paths())) {
      if (!path.endsWith(".py")) {
        continue;
      }
      String source = project.read(path);
      if (source == null) {
        model.skipped.add(path + ": not readable");
        continue;
      }
      try {
        model.modules.put(path, new Module(path, source));
      } catch (RuntimeException e) {
        model.skipped.add(path + ": " + e);
      }
    }
    for (Module m : model.modules.values()) {
      if (!m.isTest()) {
        model.frameworks.addAll(m.frameworks());
        model.usesAuth |= m.py().imports().values().stream().anyMatch(AuthHints::authPackage);
      }
    }
    if (model.frameworks.contains(Framework.FASTAPI)) {
      model.endpoints.addAll(FastApiRoutes.find(model));
    }
    if (model.frameworks.contains(Framework.DJANGO)) {
      model.endpoints.addAll(DjangoRoutes.find(model));
    }
    if (model.frameworks.contains(Framework.FLASK)) {
      model.endpoints.addAll(FlaskRoutes.find(model));
    }
    for (Endpoint e : model.endpoints) {
      if (e.function() != null) {
        model.byFunction.computeIfAbsent(e.function(), k -> new ArrayList<>()).add(e);
      }
      model.usesAuth |= e.auth().present();
    }
    return model;
  }

  public Collection<Module> modules() {
    return modules.values();
  }

  public Module module(String path) {
    return modules.get(path);
  }

  public Set<String> paths() {
    return modules.keySet();
  }

  /** Files that could not be read or parsed. */
  public List<String> skipped() {
    return skipped;
  }

  /** The frameworks imported by the project's non-test files. */
  public Set<Framework> frameworks() {
    return frameworks;
  }

  /** At least one of Django, DRF, FastAPI, Flask is imported. */
  public boolean hasFramework() {
    return !frameworks.isEmpty();
  }

  public List<Endpoint> endpoints() {
    return endpoints;
  }

  /** The endpoints a function handles (usually one; a view routed twice has two). */
  public List<Endpoint> endpointsOf(Function f) {
    return byFunction.getOrDefault(f, List.of());
  }

  /** The app has authentication somewhere: an auth package is imported or an endpoint checks the caller. */
  public boolean usesAuth() {
    return usesAuth;
  }

  /**
   * What a dotted name used in {@code from} denotes in the project: the module defining it and the name there. Local
   * definitions win; imports are followed, re-exports in {@code __init__.py} included. Null for anything outside the
   * project (a package, a builtin).
   */
  public Ref locate(Module from, String dotted) {
    for (int depth = 0; depth < 6; depth++) {
      String first = dotted.contains(".") ? dotted.substring(0, dotted.indexOf('.')) : dotted;
      Map<String, String> imports = from.py().imports();
      boolean local = from.function(first) != null || from.cls(first) != null || from.assignments().containsKey(first);
      String d = dotted;
      if (local || imports.keySet().stream().noneMatch(k -> d.equals(k) || d.startsWith(k + "."))) {
        return dotted.isEmpty() || local ? new Ref(from, dotted) : star(from, dotted, 0);
      }
      Imports.Target t = Imports.split(from.resolve(dotted), from.path(), modules.keySet());
      if (t == null) {
        return null;
      }
      Module m = modules.get(t.path());
      if (t.rest().isEmpty() || m == from && t.rest().equals(dotted)) {
        return new Ref(m, t.rest());
      }
      from = m;
      dotted = t.rest();
    }
    return null;
  }

  /** A name that {@code from x import *} brings in: the first star-imported project module that defines it. */
  private Ref star(Module from, String dotted, int depth) {
    if (depth > 3) {
      return null;
    }
    String first = dotted.contains(".") ? dotted.substring(0, dotted.indexOf('.')) : dotted;
    for (Map.Entry<String, String> e : from.py().imports().entrySet()) {
      if (!e.getKey().startsWith("*")) {
        continue;
      }
      Module m = moduleNamed(from, e.getValue());
      if (m == null || m == from) {
        continue;
      }
      boolean defines = m.function(first) != null || m.cls(first) != null || m.assignments().containsKey(first);
      Ref r = defines ? new Ref(m, dotted) : star(m, dotted, depth + 1);
      if (r != null) {
        return r;
      }
    }
    return null;
  }

  /** The project module a dotted import path names ({@code "blog.urls"} from a urls.py), or null. */
  public Module moduleNamed(Module from, String dotted) {
    Imports.Target t = Imports.split(dotted, from.path(), modules.keySet());
    return t != null && t.rest().isEmpty() ? modules.get(t.path()) : null;
  }

  /** The project function a name denotes: {@code helper}, {@code utils.helper}, {@code Service.run}; or null. */
  public Function function(Module from, String dotted) {
    Ref r = locate(from, dotted);
    if (r == null || r.name().isEmpty()) {
      return null;
    }
    int dot = r.name().indexOf('.');
    if (dot < 0) {
      return r.module().function(r.name());
    }
    String first = r.name().substring(0, dot);
    String rest = r.name().substring(dot + 1);
    PyClass c = r.module().cls(first);
    if (c == null && !rest.contains(".")) {
      // dao = Dao() at module level, then dao.query(...)
      List<Node> v = r.module().assignment(first);
      Chain ch = v == null ? null : Exprs.chain(v);
      if (ch != null && ch.endsWithCall() && ch.calls().size() == 1 && Exprs.headSize(ch) + 1 == ch.segments().size()) {
        c = cls(r.module(), Exprs.head(ch));
      }
    }
    return c == null ? null : method(c, rest);
  }

  /** The project class a name denotes, or null. */
  public PyClass cls(Module from, String dotted) {
    Ref r = locate(from, dotted);
    return r == null || r.name().isEmpty() || r.name().contains(".") ? null : r.module().cls(r.name());
  }

  /** The value nodes of the module-level variable a name denotes ({@code CurrentUser = Annotated[...]}), or null. */
  public List<Node> value(Module from, String dotted) {
    Ref r = locate(from, dotted);
    return r == null || r.name().isEmpty() ? null : r.module().assignment(r.name());
  }

  /** A method of the class or of a project base class (breadth first), or null. */
  public Function method(PyClass c, String name) {
    for (PyClass k : hierarchy(c)) {
      Function f = k.method(name);
      if (f != null) {
        return f;
      }
    }
    return null;
  }

  /** The class and its project base classes, nearest first. */
  public List<PyClass> hierarchy(PyClass c) {
    List<PyClass> out = new ArrayList<>();
    Set<PyClass> seen = new HashSet<>();
    List<PyClass> queue = new ArrayList<>(List.of(c));
    for (int i = 0; i < queue.size() && i < 32; i++) {
      PyClass k = queue.get(i);
      if (seen.add(k)) {
        out.add(k);
        for (String b : k.bases()) {
          PyClass base = cls(k.module(), b);
          if (base != null) {
            queue.add(base);
          }
        }
      }
    }
    return out;
  }

  /** Every base class name of the hierarchy that is not a project class, through imports ("rest_framework.viewsets.ModelViewSet"). */
  public List<String> externalBases(PyClass c) {
    List<String> out = new ArrayList<>();
    for (PyClass k : hierarchy(c)) {
      for (String b : k.bases()) {
        if (cls(k.module(), b) == null) {
          out.add(k.module().resolve(b));
        }
      }
    }
    return out;
  }
}
