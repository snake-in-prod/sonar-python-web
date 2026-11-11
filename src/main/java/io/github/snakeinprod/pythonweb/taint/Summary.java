package io.github.snakeinprod.pythonweb.taint;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * What a project function does with taint, as seen by its callers: which parameters reach its return value (and how),
 * which request inputs it returns itself, and which parameters reach a sink inside it (or inside what it calls).
 */
public final class Summary {

  /** A parameter reaching a sink: the path from the parameter to the sink, the sink step last. */
  public record ParamSink(int param, String kind, String sinkName, List<Step> path, Set<String> cleared) {
  }

  static final Summary EMPTY = new Summary();

  final Map<Integer, Taint.Flow> returns = new LinkedHashMap<>();
  Taint returnSources = Taint.EMPTY;
  final List<ParamSink> sinks = new ArrayList<>();

  public Map<Integer, Taint.Flow> returns() {
    return returns;
  }

  public Taint returnSources() {
    return returnSources;
  }

  public List<ParamSink> sinks() {
    return sinks;
  }

  /** What callers depend on, without the paths: the fixpoint stops when no signature changes. */
  String signature() {
    Set<String> out = new TreeSet<>();
    returns.forEach((p, f) -> out.add("r" + p + new TreeSet<>(f.cleared())));
    returnSources.flows().forEach((o, f) -> out.add("s" + o.label() + o.source() + new TreeSet<>(f.cleared())));
    for (ParamSink s : sinks) {
      out.add("k" + s.param() + s.kind() + s.path().get(s.path().size() - 1) + new TreeSet<>(s.cleared()));
    }
    return out.toString();
  }
}
