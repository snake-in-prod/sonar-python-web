package io.github.snakeinprod.pythonweb;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.snakeinprod.pythonweb.lang.python.PythonLexer;
import io.github.snakeinprod.pythonweb.model.Module;
import io.github.snakeinprod.pythonweb.model.WebModel;
import io.github.snakeinprod.pythonweb.parse.Token;
import io.github.snakeinprod.pythonweb.rules.PwRule;
import io.github.snakeinprod.pythonweb.rules.RuleCatalog;
import io.github.snakeinprod.pythonweb.sensor.Analyzer;
import io.github.snakeinprod.pythonweb.taint.TaintEngine;
import io.github.snakeinprod.pythonweb.taint.TaintModels;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Checks one rule against a fixture: {@code src/test/resources/fixtures/<Key>.py}, a single file at the project root,
 * or a directory {@code fixtures/<Key>/} holding a small app. Every file of the fixture is analysed. Every line with a
 * comment containing {@code Noncompliant} must get exactly one issue (or N with {@code Noncompliant N}); {@code {{text}}}
 * after it must be part of the message, and {@code [[n]]} gives the number of secondary locations. No other line may
 * get an issue. The marks are blanked out before analysis, so a rule that reads comments sees only the fixture's own.
 */
public final class RuleVerifier {

  private static final Pattern MARK = Pattern.compile("Noncompliant(?:\\s+(\\d+))?(?:\\s*\\{\\{(.*?)}})?(?:\\s*\\[\\[(\\d+)]])?");
  private static final Path BASE = Path.of("src/test/resources/fixtures");

  private RuleVerifier() {
  }

  /** A catalog rule against its fixture. */
  public static WebModel verify(String key) {
    RuleCatalog.Spec spec = RuleCatalog.spec(key);
    assertThat(spec).as("rule " + key + " in the catalog").isNotNull();
    return verify(key, spec.factory().get());
  }

  /** Any rule against the fixture named {@code key}; returns the model, for further checks. */
  public static WebModel verify(String key, PwRule rule) {
    Map<String, String> files = new TreeMap<>();
    Path dir = BASE.resolve(key);
    Path single = BASE.resolve(key + ".py");
    if (Files.isDirectory(dir)) {
      files.putAll(TestProjects.files(dir));
    } else if (Files.isRegularFile(single)) {
      try {
        files.put(key + ".py", Files.readString(single, StandardCharsets.UTF_8));
      } catch (IOException e) {
        throw new UncheckedIOException(e);
      }
    }
    assertThat(files).as("fixture for " + key).isNotEmpty();
    Map<String, List<Token>> marks = new HashMap<>();
    Map<String, String> blanked = new TreeMap<>(files);
    for (Map.Entry<String, String> e : files.entrySet()) {
      if (e.getKey().endsWith(".py")) {
        List<Token> comments = PythonLexer.lex(e.getValue()).comments().stream().filter(c -> MARK.matcher(c.text()).find()).toList();
        marks.put(e.getKey(), comments);
        blanked.put(e.getKey(), blank(e.getValue(), comments));
      }
    }
    WebModel model = WebModel.build(TestProjects.of(blanked));
    assertThat(model.skipped()).as("files the model could not read").isEmpty();
    Analyzer analyzer = new Analyzer(model, TaintEngine.run(model, TaintModels.defaults()), Map.of(key, rule));
    List<String> problems = new ArrayList<>();
    for (Module m : model.modules()) {
      compare(m.path(), marks.getOrDefault(m.path(), List.of()), analyzer.analyze(m), problems);
    }
    assertThat(problems).as(key).isEmpty();
    return model;
  }

  private static void compare(String path, List<Token> marks, List<Analyzer.Issue> issues, List<String> problems) {
    Map<Integer, Integer> expected = new TreeMap<>();
    Map<Integer, String> messages = new TreeMap<>();
    Map<Integer, Integer> secondaries = new TreeMap<>();
    for (Token c : marks) {
      Matcher m = MARK.matcher(c.text());
      if (m.find()) {
        expected.merge(c.line(), m.group(1) == null ? 1 : Integer.parseInt(m.group(1)), Integer::sum);
        if (m.group(2) != null) {
          messages.put(c.line(), m.group(2));
        }
        if (m.group(3) != null) {
          secondaries.put(c.line(), Integer.parseInt(m.group(3)));
        }
      }
    }
    Map<Integer, List<Analyzer.Issue>> actual = new TreeMap<>();
    for (Analyzer.Issue i : issues) {
      actual.computeIfAbsent(i.line(), l -> new ArrayList<>()).add(i);
    }
    Set<Integer> lines = new TreeSet<>(expected.keySet());
    lines.addAll(actual.keySet());
    for (int line : lines) {
      int want = expected.getOrDefault(line, 0);
      List<Analyzer.Issue> got = actual.getOrDefault(line, List.of());
      List<String> texts = got.stream().map(Analyzer.Issue::message).toList();
      if (want != got.size()) {
        problems.add(path + ":" + line + " expected " + want + " issue(s), got " + got.size() + " " + texts);
      } else if (messages.containsKey(line) && texts.stream().noneMatch(g -> g.contains(messages.get(line)))) {
        problems.add(path + ":" + line + " message should contain \"" + messages.get(line) + "\", got " + texts);
      } else if (secondaries.containsKey(line) && got.stream().noneMatch(i -> i.secondaries().size() == secondaries.get(line))) {
        problems.add(path + ":" + line + " expected " + secondaries.get(line) + " secondary location(s), got "
          + got.stream().map(i -> i.secondaries().size()).toList());
      }
    }
  }

  /** The source with each comment replaced by spaces, lines and columns kept. */
  private static String blank(String source, List<Token> comments) {
    String[] lines = source.split("\n", -1);
    for (Token c : comments) {
      String s = lines[c.line() - 1];
      int to = Math.min(c.endColumn(), s.length());
      lines[c.line() - 1] = s.substring(0, c.column()) + " ".repeat(Math.max(0, to - c.column())) + s.substring(to);
    }
    return String.join("\n", lines);
  }
}
