package io.github.snakeinprod.pythonweb.taint;

import io.github.snakeinprod.pythonweb.model.Function;
import io.github.snakeinprod.pythonweb.model.Module;
import java.util.List;
import java.util.Map;

/** The findings of one analysis and the function summaries they were computed with. */
public record TaintResult(List<Finding> findings, Map<Function, Summary> summaries) {

  /** Findings of one sink kind. */
  public List<Finding> findings(String kind) {
    return findings.stream().filter(f -> f.kind().equals(kind)).toList();
  }

  /** Findings whose sink is in this module (where a rule reports them). */
  public List<Finding> findingsIn(Module m) {
    return findings.stream().filter(f -> f.sink().module() == m).toList();
  }

  public Summary summary(Function f) {
    return summaries.getOrDefault(f, Summary.EMPTY);
  }
}
