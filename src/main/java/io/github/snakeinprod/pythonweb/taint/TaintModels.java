package io.github.snakeinprod.pythonweb.taint;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Sources, sinks, sanitizers, guards and propagators of {@code models/taint.json}. A call pattern is a resolved
 * dotted name ("subprocess.run"), or "*.name" for a method of that name on any receiver; "a.b.c|d" stands for a.b.c
 * and a.b.d. A rule never matches calls itself: it reads the engine's findings of its sink kind.
 */
public final class TaintModels {

  /**
   * A sink: the {@code args} (indexes, -1 the receiver) and {@code kwargs} of a {@code call} that must not get tainted
   * data; only when every {@code when} keyword is given one of its values, never when an {@code unless} keyword is.
   */
  public record Sink(String kind, String call, List<Integer> args, List<String> kwargs, Map<String, List<String>> when,
    Map<String, List<String>> unless) {
  }

  /** A sanitizer (its result is clean for {@code kinds}) or a guard (a check on a value in a condition clears it). */
  public record Clearing(String call, Set<String> kinds) {
  }

  private static TaintModels defaults;

  final Set<String> requestAttributes;
  final Set<String> globalRequests;
  final Set<String> requestTypes;
  final Set<String> notInputs;
  final List<Sink> sinks = new ArrayList<>();
  final List<Clearing> sanitizers = new ArrayList<>();
  final List<Clearing> guards = new ArrayList<>();
  final Set<String> propagators = new HashSet<>();
  final Set<String> mutators;
  final Set<String> cleanMethods;

  private TaintModels(JsonObject o) {
    JsonObject src = o.getAsJsonObject("sources");
    requestAttributes = strings(src.getAsJsonArray("requestAttributes"));
    globalRequests = strings(src.getAsJsonArray("globalRequests"));
    requestTypes = strings(src.getAsJsonArray("requestTypes"));
    notInputs = strings(src.getAsJsonArray("notInputs"));
    for (JsonElement e : o.getAsJsonArray("sinks")) {
      JsonObject s = e.getAsJsonObject();
      List<Integer> args = new ArrayList<>();
      if (s.has("args")) {
        s.getAsJsonArray("args").forEach(a -> args.add(a.getAsInt()));
      }
      List<String> kwargs = s.has("kwargs") ? List.copyOf(strings(s.getAsJsonArray("kwargs"))) : List.of();
      for (String call : expand(s.get("call").getAsString())) {
        sinks.add(new Sink(s.get("kind").getAsString(), call, List.copyOf(args), kwargs, map(s.getAsJsonObject("when")),
          map(s.getAsJsonObject("unless"))));
      }
    }
    clearings(o.getAsJsonArray("sanitizers"), sanitizers);
    clearings(o.getAsJsonArray("guards"), guards);
    for (JsonElement e : o.getAsJsonArray("propagators")) {
      propagators.addAll(expand(e.getAsString()));
    }
    mutators = strings(o.getAsJsonArray("mutators"));
    cleanMethods = strings(o.getAsJsonArray("cleanMethods"));
  }

  /** The bundled models. */
  public static synchronized TaintModels defaults() {
    if (defaults == null) {
      try (InputStream in = TaintModels.class.getResourceAsStream("/models/taint.json");
        Reader r = new InputStreamReader(in, StandardCharsets.UTF_8)) {
        defaults = new TaintModels(JsonParser.parseReader(r).getAsJsonObject());
      } catch (IOException e) {
        throw new UncheckedIOException(e);
      }
    }
    return defaults;
  }

  public List<Sink> sinks() {
    return sinks;
  }

  /** Whether a pattern matches a call: {@code callee} resolved, {@code method} the last name, {@code receiver} whether it has one. */
  static boolean matches(String pattern, String callee, String method, boolean receiver) {
    return pattern.startsWith("*.") ? receiver && pattern.substring(2).equals(method) : pattern.equals(callee);
  }

  /** The kinds a sanitizer of this call clears, or null. */
  Set<String> sanitizer(String callee, String method, boolean receiver) {
    return clearing(sanitizers, callee, method, receiver);
  }

  Set<String> guard(String callee, String method, boolean receiver) {
    return clearing(guards, callee, method, receiver);
  }

  boolean propagator(String callee, String method, boolean receiver) {
    return propagators.contains(callee) || receiver && propagators.contains("*." + method);
  }

  private static Set<String> clearing(List<Clearing> list, String callee, String method, boolean receiver) {
    Set<String> out = null;
    for (Clearing c : list) {
      if (matches(c.call(), callee, method, receiver)) {
        out = out == null ? new HashSet<>() : out;
        out.addAll(c.kinds());
      }
    }
    return out;
  }

  private static void clearings(JsonArray a, List<Clearing> out) {
    for (JsonElement e : a) {
      JsonObject c = e.getAsJsonObject();
      for (String call : expand(c.get("call").getAsString())) {
        out.add(new Clearing(call, strings(c.getAsJsonArray("kinds"))));
      }
    }
  }

  /** "a.b.c|d" gives a.b.c and a.b.d. */
  static List<String> expand(String pattern) {
    int dot = pattern.lastIndexOf('.');
    String prefix = pattern.substring(0, dot + 1);
    List<String> out = new ArrayList<>();
    for (String last : pattern.substring(dot + 1).split("\\|")) {
      out.add(prefix + last);
    }
    return out;
  }

  private static Set<String> strings(JsonArray a) {
    Set<String> out = new HashSet<>();
    if (a != null) {
      a.forEach(e -> out.add(e.getAsString()));
    }
    return Set.copyOf(out);
  }

  private static Map<String, List<String>> map(JsonObject o) {
    Map<String, List<String>> out = new LinkedHashMap<>();
    if (o != null) {
      for (Map.Entry<String, JsonElement> e : o.entrySet()) {
        out.put(e.getKey(), List.copyOf(strings(e.getValue().getAsJsonArray())));
      }
    }
    return out;
  }
}
