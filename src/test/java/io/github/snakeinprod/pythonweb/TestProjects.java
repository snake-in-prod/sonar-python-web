package io.github.snakeinprod.pythonweb;

import io.github.snakeinprod.pythonweb.model.Project;
import io.github.snakeinprod.pythonweb.model.WebModel;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Stream;

/** Projects for tests: a fixture directory, or files in memory. */
public final class TestProjects {

  private TestProjects() {
  }

  /** Every file under the directory, by path relative to it. */
  public static Map<String, String> files(Path dir) {
    Map<String, String> out = new TreeMap<>();
    try (Stream<Path> s = Files.walk(dir)) {
      for (Path p : s.filter(Files::isRegularFile).toList()) {
        out.put(dir.relativize(p).toString().replace('\\', '/'), Files.readString(p, StandardCharsets.UTF_8));
      }
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
    return out;
  }

  public static Project of(Map<String, String> files) {
    return new Project() {
      @Override
      public Set<String> paths() {
        return files.keySet();
      }

      @Override
      public String read(String path) {
        return files.get(path);
      }
    };
  }

  /** The model of a directory under src/test/resources/model. */
  public static WebModel model(String name) {
    return WebModel.build(of(files(Path.of("src/test/resources/model", name))));
  }

  /** The model of files given as path, content, path, content... */
  public static WebModel model(String... pathsAndContents) {
    Map<String, String> files = new LinkedHashMap<>();
    for (int i = 0; i + 1 < pathsAndContents.length; i += 2) {
      files.put(pathsAndContents[i], pathsAndContents[i + 1]);
    }
    return WebModel.build(of(files));
  }
}
