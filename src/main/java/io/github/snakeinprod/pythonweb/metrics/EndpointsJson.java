package io.github.snakeinprod.pythonweb.metrics;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import io.github.snakeinprod.pythonweb.model.Endpoint;
import io.github.snakeinprod.pythonweb.model.WebModel;
import io.github.snakeinprod.pythonweb.sensor.Analyzer;
import java.util.List;
import java.util.Map;

/**
 * pw_endpoints_json: an array with one object per endpoint: {@code path}, {@code methods}, {@code framework} (django,
 * drf, fastapi, flask), {@code function} ("create_item", "ItemViewSet.create"), {@code file}, {@code line}, {@code auth}
 * (the evidence, or null), {@code protected}, {@code unprotected} (reported by EndpointWithoutAuth, see
 * {@link PwMetrics#unprotected}), {@code async}, {@code mutating} and {@code issues} (issues shown within the handler's
 * lines, or the view class's when the handler is inherited).
 */
public final class EndpointsJson {

  private EndpointsJson() {
  }

  /** {@code shown}: the saved issues by file, for the counts; {@code all}: every rule's issues, for the unprotected flag. */
  public static String build(WebModel model, Map<String, List<Analyzer.Issue>> shown, Map<String, List<Analyzer.Issue>> all) {
    JsonArray out = new JsonArray();
    for (Endpoint e : model.endpoints()) {
      JsonObject o = new JsonObject();
      o.addProperty("path", e.path());
      JsonArray methods = new JsonArray();
      e.methods().forEach(methods::add);
      o.add("methods", methods);
      o.addProperty("framework", e.framework().key());
      o.addProperty("function", e.label());
      o.addProperty("file", e.module().path());
      o.addProperty("line", e.token().line());
      o.addProperty("auth", e.auth().evidence());
      o.addProperty("protected", e.auth().present());
      o.addProperty("unprotected", PwMetrics.unprotected(e, all.getOrDefault(e.module().path(), List.of())));
      o.addProperty("async", e.async());
      o.addProperty("mutating", e.mutating());
      o.addProperty("issues", shown.getOrDefault(e.module().path(), List.of()).stream()
        .filter(i -> i.line() >= e.firstLine() && i.line() <= e.lastLine()).count());
      out.add(o);
    }
    return out.toString();
  }
}
