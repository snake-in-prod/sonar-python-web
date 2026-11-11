package io.github.snakeinprod.pythonweb.sensor;

import io.github.snakeinprod.pythonweb.metrics.EndpointsJson;
import io.github.snakeinprod.pythonweb.metrics.PwMetrics;
import io.github.snakeinprod.pythonweb.model.Endpoint;
import io.github.snakeinprod.pythonweb.model.Module;
import io.github.snakeinprod.pythonweb.model.Project;
import io.github.snakeinprod.pythonweb.model.WebModel;
import io.github.snakeinprod.pythonweb.rules.RuleCatalog;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.batch.fs.FileSystem;
import org.sonar.api.batch.fs.InputFile;
import org.sonar.api.batch.fs.TextRange;
import org.sonar.api.batch.sensor.Sensor;
import org.sonar.api.batch.sensor.SensorContext;
import org.sonar.api.batch.sensor.SensorDescriptor;
import org.sonar.api.batch.sensor.issue.NewIssue;
import org.sonar.api.measures.Metric;
import org.sonar.api.rule.RuleKey;

/**
 * Builds the model of the project's Python files once, runs the taint engine and the rules, saves the issues of the
 * active rules (with their secondary locations) and the pw_* measures. Does nothing when no file imports Django, DRF,
 * FastAPI, Starlette, Flask or aiohttp. Test files are read for nothing and get no issue.
 */
public class PythonWebSensor implements Sensor {

  private static final Logger LOG = LoggerFactory.getLogger(PythonWebSensor.class);

  @Override
  public void describe(SensorDescriptor descriptor) {
    descriptor.name("Python Web").onlyOnLanguage(RuleCatalog.LANGUAGE);
  }

  @Override
  public void execute(SensorContext context) {
    FileSystem fs = context.fileSystem();
    Map<String, InputFile> byPath = new HashMap<>();
    for (InputFile f : fs.inputFiles(fs.predicates().hasLanguage(RuleCatalog.LANGUAGE))) {
      byPath.put(f.relativePath(), f);
    }
    WebModel model = WebModel.build(new Project() {
      @Override
      public Set<String> paths() {
        return byPath.keySet();
      }

      @Override
      public String read(String path) {
        try {
          return byPath.get(path).contents();
        } catch (IOException | UncheckedIOException | NullPointerException e) {
          return null;
        }
      }
    });
    if (!model.hasFramework()) {
      LOG.info("Python Web: no file imports Django, FastAPI, Flask or aiohttp, nothing to analyse");
      return;
    }
    model.skipped().forEach(s -> LOG.warn("Python Web: skipped {}", s));
    Analyzer analyzer = Analyzer.all(model);
    Map<String, List<Endpoint>> endpoints = new HashMap<>();
    model.endpoints().forEach(e -> endpoints.computeIfAbsent(e.module().path(), k -> new ArrayList<>()).add(e));
    Map<String, List<Analyzer.Issue>> saved = new HashMap<>();
    Map<String, List<Analyzer.Issue>> all = new HashMap<>();
    Map<String, Integer> totals = new HashMap<>();
    int failed = 0;
    for (Module m : model.modules()) {
      InputFile f = byPath.get(m.path());
      if (f == null) {
        continue;
      }
      List<Analyzer.Issue> issues;
      try {
        issues = analyzer.analyze(m);
      } catch (RuntimeException e) {
        failed++;
        LOG.warn("Python Web: skipped {}: {}", m.path(), e.toString());
        issues = List.of();
      }
      saved.put(m.path(), save(context, f, byPath, issues));
      all.put(m.path(), issues);
      for (Map.Entry<Metric<Integer>, Integer> e : PwMetrics.fileValues(m, endpoints.getOrDefault(m.path(), List.of()), issues)
        .entrySet()) {
        context.<Integer>newMeasure().on(f).forMetric(e.getKey()).withValue(e.getValue()).save();
        totals.merge(e.getKey().getKey(), e.getValue(), Integer::sum);
      }
    }
    context.<String>newMeasure().on(context.project()).forMetric(PwMetrics.ENDPOINTS_JSON).withValue(EndpointsJson.build(model, saved, all))
      .save();
    // a pull request keeps the measures of its changed files only: the whole app's numbers for the page
    context.<String>newMeasure().on(context.project()).forMetric(PwMetrics.APP_JSON).withValue(PwMetrics.appJson(totals)).save();
    LOG.info("Python Web: {} modules, {} endpoints, {} taint findings, {} failed", model.modules().size(), model.endpoints().size(),
      analyzer.taint().findings().size(), failed);
  }

  /** Saves the issues of active rules; returns them. */
  private static List<Analyzer.Issue> save(SensorContext context, InputFile f, Map<String, InputFile> byPath,
    List<Analyzer.Issue> found) {
    List<Analyzer.Issue> out = new ArrayList<>();
    for (Analyzer.Issue i : found) {
      RuleKey key = RuleKey.of(RuleCatalog.REPOSITORY, i.rule());
      if (context.activeRules().find(key) == null) {
        continue;
      }
      NewIssue issue = context.newIssue().forRule(key);
      issue.at(issue.newLocation().on(f).at(range(f, i.line(), i.column(), i.endLine(), i.endColumn())).message(i.message()));
      for (Analyzer.Location l : i.secondaries()) {
        InputFile lf = byPath.get(l.path());
        if (lf != null) {
          issue.addLocation(issue.newLocation().on(lf).at(range(lf, l.line(), l.column(), l.endLine(), l.endColumn()))
            .message(l.message()));
        }
      }
      issue.save();
      out.add(i);
    }
    return out;
  }

  private static TextRange range(InputFile f, int line, int column, int endLine, int endColumn) {
    try {
      int last = Math.min(endLine, f.lines());
      int lastColumn = endLine > f.lines() ? f.selectLine(f.lines()).end().lineOffset() : endColumn;
      TextRange r = f.newRange(line, column, last, lastColumn);
      return r.start().equals(r.end()) ? f.selectLine(line) : r;
    } catch (IllegalArgumentException e) {
      return f.selectLine(Math.max(1, Math.min(line, f.lines())));
    }
  }
}
