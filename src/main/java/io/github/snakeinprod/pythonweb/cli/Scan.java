package io.github.snakeinprod.pythonweb.cli;

import io.github.snakeinprod.pythonweb.metrics.EndpointsJson;
import io.github.snakeinprod.pythonweb.metrics.PwMetrics;
import io.github.snakeinprod.pythonweb.model.Endpoint;
import io.github.snakeinprod.pythonweb.model.Module;
import io.github.snakeinprod.pythonweb.model.Project;
import io.github.snakeinprod.pythonweb.model.WebModel;
import io.github.snakeinprod.pythonweb.sensor.Analyzer;
import io.github.snakeinprod.pythonweb.taint.Finding;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.stream.Stream;
import org.sonar.api.measures.Metric;

/**
 * Runs every rule on a directory without SonarQube, for checking rules on real apps:
 * {@code java -cp target/classes:<gson.jar> io.github.snakeinprod.pythonweb.cli.Scan <dir> [--endpoints] [--findings] [--json]}.
 * Prints one issue per line ({@code path:line:column rule message}), then the measures and a count per rule;
 * {@code --endpoints} adds every endpoint, {@code --findings} every taint finding with its path, {@code --json} the
 * endpoints JSON.
 */
public final class Scan {

  /** Directories never read: virtual environments, dependencies, build output, hidden directories. */
  private static final Set<String> SKIPPED_DIRS = Set.of("venv", "env", "site-packages", "node_modules", "__pycache__", "build",
    "dist");

  private Scan() {
  }

  public static void main(String[] args) throws IOException {
    Path root = Path.of(args[0]).toAbsolutePath().normalize();
    List<String> flags = List.of(args).subList(1, args.length);
    Set<String> paths = new TreeSet<>();
    try (Stream<Path> files = Files.walk(root)) {
      files.filter(p -> Files.isRegularFile(p) && p.toString().endsWith(".py")).forEach(p -> {
        String rel = root.relativize(p).toString().replace('\\', '/');
        for (String part : rel.split("/")) {
          if (part.startsWith(".") || SKIPPED_DIRS.contains(part)) {
            return;
          }
        }
        paths.add(rel);
      });
    }
    WebModel model = WebModel.build(project(root, paths));
    if (!model.hasFramework()) {
      System.out.println("== no file imports Django, FastAPI, Flask or aiohttp");
      return;
    }
    model.skipped().forEach(s -> System.err.println("SKIPPED " + s));
    Analyzer analyzer = Analyzer.all(model);
    Map<String, List<Endpoint>> endpoints = new HashMap<>();
    model.endpoints().forEach(e -> endpoints.computeIfAbsent(e.module().path(), k -> new ArrayList<>()).add(e));
    Map<String, Integer> perRule = new TreeMap<>();
    Map<String, Integer> totals = new LinkedHashMap<>();
    Map<String, List<Analyzer.Issue>> all = new HashMap<>();
    for (Module m : model.modules()) {
      List<Analyzer.Issue> issues;
      try {
        issues = analyzer.analyze(m);
      } catch (RuntimeException e) {
        System.err.println("SKIPPED " + m.path() + ": " + e);
        continue;
      }
      all.put(m.path(), issues);
      for (Analyzer.Issue i : issues) {
        System.out.println(i.path() + ":" + i.line() + ":" + i.column() + " " + i.rule() + " " + i.message());
        perRule.merge(i.rule(), 1, Integer::sum);
      }
      for (Map.Entry<Metric<Integer>, Integer> e : PwMetrics.fileValues(m, endpoints.getOrDefault(m.path(), List.of()), issues)
        .entrySet()) {
        totals.merge(e.getKey().getKey(), e.getValue(), Integer::sum);
      }
    }
    if (flags.contains("--endpoints")) {
      model.endpoints().forEach(e -> System.out.println("-- " + e));
    }
    if (flags.contains("--findings")) {
      for (Finding f : analyzer.taint().findings()) {
        System.out.println("-- " + f.kind() + " " + f.sink() + " <- " + f.label() + " in " + f.where());
        f.path().forEach(s -> System.out.println("     " + s));
      }
    }
    System.out.println("== frameworks " + model.frameworks() + (model.usesAuth() ? ", uses auth" : ""));
    System.out.println("== " + model.modules().size() + " modules, " + model.endpoints().size() + " endpoints, "
      + analyzer.taint().findings().size() + " taint findings");
    totals.forEach((k, v) -> System.out.println("== " + k + " " + v));
    perRule.forEach((k, v) -> System.out.println("== " + k + " " + v));
    if (flags.contains("--json")) {
      System.out.println(EndpointsJson.build(model, all));
    }
  }

  private static Project project(Path root, Set<String> paths) {
    return new Project() {
      @Override
      public Set<String> paths() {
        return paths;
      }

      @Override
      public String read(String path) {
        Path p = root.resolve(path).normalize();
        try {
          return p.startsWith(root) && Files.isRegularFile(p) ? Files.readString(p, StandardCharsets.UTF_8) : null;
        } catch (IOException | UncheckedIOException e) {
          return null;
        }
      }
    };
  }
}
