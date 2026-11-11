package io.github.snakeinprod.pythonweb.sensor;

import io.github.snakeinprod.pythonweb.model.Module;
import io.github.snakeinprod.pythonweb.model.WebModel;
import io.github.snakeinprod.pythonweb.parse.Token;
import io.github.snakeinprod.pythonweb.rules.PwRule;
import io.github.snakeinprod.pythonweb.rules.RuleCatalog;
import io.github.snakeinprod.pythonweb.rules.RuleContext;
import io.github.snakeinprod.pythonweb.taint.Step;
import io.github.snakeinprod.pythonweb.taint.TaintEngine;
import io.github.snakeinprod.pythonweb.taint.TaintModels;
import io.github.snakeinprod.pythonweb.taint.TaintResult;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Runs rules on the modules of a model, with the taint findings computed once. Shared by the sensor, the command line
 * scanner and the tests, so that all three see the same results. A line with a NOSONAR comment gets no issue.
 */
public final class Analyzer {

  /** A location; lines 1-based, columns 0-based, {@code endColumn} exclusive. */
  public record Location(String path, int line, int column, int endLine, int endColumn, String message) {
  }

  /** An issue at {@code path}:{@code line}, with its secondary locations. */
  public record Issue(String path, String rule, int line, int column, int endLine, int endColumn, String message,
    List<Location> secondaries) {
  }

  private final WebModel model;
  private final TaintResult taint;
  private final Map<String, PwRule> rules;

  /** {@code rules}: rule key to a fresh instance, run in this order. */
  public Analyzer(WebModel model, TaintResult taint, Map<String, PwRule> rules) {
    this.model = model;
    this.taint = taint;
    this.rules = rules;
  }

  /** Every rule of the catalog, active in the profile or not, with the bundled taint models. */
  public static Analyzer all(WebModel model) {
    Map<String, PwRule> rules = new LinkedHashMap<>();
    for (RuleCatalog.Spec s : RuleCatalog.ALL) {
      rules.put(s.key(), s.factory().get());
    }
    return new Analyzer(model, TaintEngine.run(model, TaintModels.defaults()), rules);
  }

  public WebModel model() {
    return model;
  }

  public TaintResult taint() {
    return taint;
  }

  /** The issues of one module, sorted by position; none in a test file. Throws only on an internal error of a rule. */
  public List<Issue> analyze(Module module) {
    if (module.isTest()) {
      return List.of();
    }
    Set<Integer> nosonar = new HashSet<>();
    for (Token c : module.file().comments()) {
      if (c.text().contains("NOSONAR")) {
        nosonar.add(c.line());
      }
    }
    List<Issue> issues = new ArrayList<>();
    for (Map.Entry<String, PwRule> e : rules.entrySet()) {
      String key = e.getKey();
      e.getValue().check(new RuleContext() {
        @Override
        public Module module() {
          return module;
        }

        @Override
        public WebModel model() {
          return model;
        }

        @Override
        public TaintResult taint() {
          return taint;
        }

        @Override
        public void report(Token from, Token to, String message, List<Step> secondaries) {
          if (!nosonar.contains(from.line())) {
            List<Location> locations = secondaries.stream().map(s -> new Location(s.module().path(), s.token().line(),
              s.token().column(), s.token().endLine(), s.token().endColumn(), s.message())).toList();
            issues.add(new Issue(module.path(), key, from.line(), from.column(), to.endLine(), to.endColumn(), message, locations));
          }
        }
      });
    }
    issues.sort((a, b) -> a.line() != b.line() ? Integer.compare(a.line(), b.line()) : Integer.compare(a.column(), b.column()));
    return List.copyOf(issues);
  }
}
