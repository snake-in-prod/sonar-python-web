package io.github.snakeinprod.pythonweb.model;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Import resolution: a dotted path resolves to the longest prefix that is a project module ({@code a/b.py}) or package
 * ({@code a/b/__init__.py}), the rest is a name inside it. A relative path ({@code .views.index}) starts from the
 * importing file's package; an absolute one from each directory above the file (deepest first) and that directory's
 * {@code src/}, so a Django app beside manage.py and a src layout both resolve.
 */
public final class Imports {

  /** A project module and the dotted name inside it ("" for the module itself). */
  public record Target(String path, String rest) {
  }

  private Imports() {
  }

  /** The module of a dotted path and the rest, or null when no prefix is a project module. */
  public static Target split(String dotted, String from, Set<String> paths) {
    int dots = 0;
    while (dots < dotted.length() && dotted.charAt(dots) == '.') {
      dots++;
    }
    List<String> roots = new ArrayList<>();
    if (dots > 0) {
      String base = join(dir(from), "../".repeat(dots - 1));
      if (base == null) {
        return null;
      }
      roots.add(base.isEmpty() ? "" : base + "/");
    } else {
      for (String d = dir(from); ; d = dir(d.substring(0, d.length() - 1))) {
        roots.add(d);
        roots.add(d + "src/");
        if (d.isEmpty()) {
          break;
        }
      }
    }
    String name = dotted.substring(dots);
    String rest = "";
    while (true) {
      String rel = name.replace('.', '/');
      for (String root : roots) {
        for (String c : name.isEmpty() ? List.of(root + "__init__.py") : List.of(root + rel + ".py", root + rel + "/__init__.py")) {
          if (paths.contains(c)) {
            return new Target(c, rest);
          }
        }
      }
      if (name.isEmpty() || dots == 0 && !name.contains(".")) {
        return null;
      }
      int cut = name.lastIndexOf('.');
      String last = cut < 0 ? name : name.substring(cut + 1);
      rest = rest.isEmpty() ? last : last + "." + rest;
      name = cut < 0 ? "" : name.substring(0, cut);
    }
  }

  /** The directory part of a path, with its trailing "/" ("" at the root). */
  public static String dir(String path) {
    return path.substring(0, path.lastIndexOf('/') + 1);
  }

  /** {@code dir} + {@code relative} with "." and ".." resolved, or null when it leaves the base directory. */
  public static String join(String dir, String relative) {
    List<String> parts = new ArrayList<>();
    for (String s : (dir + relative).split("/")) {
      if (s.equals("..")) {
        if (parts.isEmpty()) {
          return null;
        }
        parts.remove(parts.size() - 1);
      } else if (!s.isEmpty() && !s.equals(".")) {
        parts.add(s);
      }
    }
    return String.join("/", parts);
  }
}
