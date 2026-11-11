package io.github.snakeinprod.pythonweb.taint;

import io.github.snakeinprod.pythonweb.model.Function;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * What a value may carry: for each origin (a request input, or a parameter of the function being summarised) the path
 * it took and the sink kinds it was sanitized for on the way. Immutable.
 */
public final class Taint {

  /** Paths longer than this keep their first steps and the last ones. */
  static final int MAX_PATH = 16;

  /**
   * A request input ({@code param} -1, {@code label} like "request.GET", {@code source} where it is read, {@code function}
   * the function reading it) or a parameter of the analysed function ({@code param} its index).
   */
  public record Origin(int param, String label, Step source, Function function) {
    boolean isSource() {
      return param < 0;
    }
  }

  /** The steps from the origin, and the sink kinds this flow no longer reaches. */
  public record Flow(List<Step> path, Set<String> cleared) {
    boolean clears(String kind) {
      return cleared.contains(kind) || cleared.contains("*");
    }
  }

  public static final Taint EMPTY = new Taint(Map.of());

  private final Map<Origin, Flow> flows;

  private Taint(Map<Origin, Flow> flows) {
    this.flows = flows;
  }

  static Taint source(String label, Step at, Function function) {
    return new Taint(Map.of(new Origin(-1, label, at, function), new Flow(List.of(at), Set.of())));
  }

  static Taint param(int index, String name) {
    return new Taint(Map.of(new Origin(index, name, null, null), new Flow(List.of(), Set.of())));
  }

  public boolean isEmpty() {
    return flows.isEmpty();
  }

  public Map<Origin, Flow> flows() {
    return Collections.unmodifiableMap(flows);
  }

  /** Both; for an origin in both, the flow that is cleared for fewer kinds (then the shorter path). */
  Taint union(Taint other) {
    if (other.isEmpty()) {
      return this;
    }
    if (isEmpty()) {
      return other;
    }
    Map<Origin, Flow> out = new LinkedHashMap<>(flows);
    other.flows.forEach((o, f) -> out.merge(o, f, Taint::better));
    return new Taint(out);
  }

  private static Flow better(Flow a, Flow b) {
    if (a.cleared().size() != b.cleared().size()) {
      return a.cleared().size() < b.cleared().size() ? a : b;
    }
    return a.path().size() <= b.path().size() ? a : b;
  }

  /** Only the origins that pass the test. */
  Taint filter(java.util.function.Predicate<Origin> test) {
    Map<Origin, Flow> out = new LinkedHashMap<>();
    flows.forEach((o, f) -> {
      if (test.test(o)) {
        out.put(o, f);
      }
    });
    return out.size() == flows.size() ? this : new Taint(out);
  }

  /** Every path with one more step. */
  Taint step(Step s) {
    if (isEmpty()) {
      return this;
    }
    Map<Origin, Flow> out = new LinkedHashMap<>();
    flows.forEach((o, f) -> out.put(o, new Flow(append(f.path(), List.of(s)), f.cleared())));
    return new Taint(out);
  }

  /** Every flow, followed by {@code steps}, also cleared for {@code kinds}. */
  Taint then(List<Step> steps, Set<String> kinds) {
    if (isEmpty()) {
      return this;
    }
    Map<Origin, Flow> out = new LinkedHashMap<>();
    flows.forEach((o, f) -> out.put(o, new Flow(append(f.path(), steps), plus(f.cleared(), kinds))));
    return new Taint(out);
  }

  /** Cleared for these kinds; "*" drops everything. */
  Taint clear(Set<String> kinds) {
    if (isEmpty() || kinds.isEmpty()) {
      return this;
    }
    if (kinds.contains("*")) {
      return EMPTY;
    }
    return then(List.of(), kinds);
  }

  static List<Step> append(List<Step> a, List<Step> b) {
    if (b.isEmpty()) {
      return a;
    }
    List<Step> out = new ArrayList<>(a.size() + b.size());
    out.addAll(a);
    out.addAll(b);
    if (out.size() > MAX_PATH) {
      List<Step> cut = new ArrayList<>(out.subList(0, MAX_PATH / 2));
      cut.addAll(out.subList(out.size() - MAX_PATH / 2, out.size()));
      out = cut;
    }
    return List.copyOf(out);
  }

  static Set<String> plus(Set<String> a, Set<String> b) {
    if (b.isEmpty()) {
      return a;
    }
    Set<String> out = new HashSet<>(a);
    out.addAll(b);
    return Set.copyOf(out);
  }

  @Override
  public String toString() {
    return flows.keySet().toString();
  }
}
