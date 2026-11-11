package io.github.snakeinprod.pythonweb.metrics;

import com.google.gson.JsonObject;
import io.github.snakeinprod.pythonweb.model.Endpoint;
import io.github.snakeinprod.pythonweb.model.Module;
import io.github.snakeinprod.pythonweb.rules.RuleCatalog;
import io.github.snakeinprod.pythonweb.sensor.Analyzer;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.sonar.api.measures.Metric;
import org.sonar.api.measures.Metrics;

/**
 * The pw_* measures. Integer ones are saved on files and summed to directories and the project by
 * {@link PwAggregator}; pw_endpoints_json and pw_app_json are saved on the project only. The issue counts include the
 * issues of rules that are not active in the quality profile.
 */
public class PwMetrics implements Metrics {

  public static final String DOMAIN = "Python Web";

  public static final Metric<Integer> ENDPOINTS = intMetric("pw_endpoints", "Endpoints",
    "FastAPI routes, Django views (class-based view handlers and ViewSet actions each) and Flask routes", Metric.DIRECTION_NONE,
    false);
  public static final Metric<Integer> MUTATING_ENDPOINTS = intMetric("pw_mutating_endpoints", "Mutating endpoints",
    "Endpoints for POST, PUT, PATCH or DELETE, and Django views open to any method that write", Metric.DIRECTION_NONE, false);
  public static final Metric<Integer> UNPROTECTED_ENDPOINTS = intMetric("pw_unprotected_endpoints", "Endpoints without auth",
    "Endpoints that change data, check no caller and do not look public: those EndpointWithoutAuth reports", Metric.DIRECTION_WORST, true);
  public static final Metric<Integer> ASYNC_ENDPOINTS = intMetric("pw_async_endpoints", "Async endpoints",
    "Endpoints whose handler is an async def", Metric.DIRECTION_NONE, false);
  public static final Metric<Integer> BLOCKING_CALLS = intMetric("pw_blocking_calls", "Blocking calls in async code",
    "Blocking calls reached from async endpoints (issues of BlockingCallInAsync)", Metric.DIRECTION_WORST, true);
  public static final Metric<Integer> TAINT_FINDINGS = intMetric("pw_taint_findings", "Taint findings",
    "Request data reaching a sink (issues of the taint rules)", Metric.DIRECTION_WORST, true);
  public static final Metric<String> ENDPOINTS_JSON = new Metric.Builder("pw_endpoints_json", "Endpoints (JSON)",
    Metric.ValueType.DATA).setDescription("JSON: every endpoint with its path, methods, framework, function, auth, async flag and "
      + "issues").setDomain(DOMAIN).setQualitative(false).setHidden(true).create();
  public static final Metric<String> APP_JSON = new Metric.Builder("pw_app_json", "Whole app (JSON)", Metric.ValueType.DATA)
    .setDescription("JSON: the project measures counted on every file, for a pull request where the others count its changed files")
    .setDomain(DOMAIN).setQualitative(false).setHidden(true).create();

  /** Integer measures saved on files and summed up. */
  public static final List<Metric<Integer>> SUMMED = List.of(ENDPOINTS, MUTATING_ENDPOINTS, UNPROTECTED_ENDPOINTS, ASYNC_ENDPOINTS,
    BLOCKING_CALLS, TAINT_FINDINGS);

  /** The rules whose issues count as taint findings: those with a sink kind. */
  public static final Set<String> TAINT_RULES = RuleCatalog.ALL.stream().filter(s -> s.sinkKind() != null)
    .map(RuleCatalog.Spec::key).collect(Collectors.toUnmodifiableSet());

  private static Metric<Integer> intMetric(String key, String name, String description, int direction, boolean qualitative) {
    Metric.Builder b = new Metric.Builder(key, name, Metric.ValueType.INT).setDescription(description).setDomain(DOMAIN)
      .setDirection(direction).setQualitative(qualitative);
    return (qualitative ? b.setBestValue(0.0) : b).create();
  }

  /** The file measures of a module: its endpoints, and all its issues (every rule included). */
  public static Map<Metric<Integer>, Integer> fileValues(Module m, List<Endpoint> endpoints, List<Analyzer.Issue> issues) {
    Map<Metric<Integer>, Integer> out = new LinkedHashMap<>();
    if (m.isTest()) {
      SUMMED.forEach(k -> out.put(k, 0));
      return out;
    }
    out.put(ENDPOINTS, endpoints.size());
    out.put(MUTATING_ENDPOINTS, (int) endpoints.stream().filter(Endpoint::mutating).count());
    out.put(UNPROTECTED_ENDPOINTS, (int) endpoints.stream().filter(e -> unprotected(e, issues)).count());
    out.put(ASYNC_ENDPOINTS, (int) endpoints.stream().filter(Endpoint::async).count());
    out.put(BLOCKING_CALLS, count(issues, Set.of("BlockingCallInAsync")));
    out.put(TAINT_FINDINGS, count(issues, TAINT_RULES));
    return out;
  }

  /**
   * The endpoint is one EndpointWithoutAuth reports (an issue of that rule on its handler, among the issues of its file):
   * the one definition behind pw_unprotected_endpoints and the {@code unprotected} flag of pw_endpoints_json.
   */
  public static boolean unprotected(Endpoint e, List<Analyzer.Issue> issues) {
    return issues.stream().anyMatch(i -> i.rule().equals("EndpointWithoutAuth") && i.line() == e.token().line());
  }

  private static int count(List<Analyzer.Issue> issues, Set<String> rules) {
    return (int) issues.stream().filter(i -> rules.contains(i.rule())).count();
  }

  /** pw_app_json: the file values summed over every file, by metric key. */
  public static String appJson(Map<String, Integer> totals) {
    JsonObject o = new JsonObject();
    SUMMED.forEach(k -> o.addProperty(k.getKey(), totals.getOrDefault(k.getKey(), 0)));
    return o.toString();
  }

  @Override
  @SuppressWarnings("rawtypes")
  public List<Metric> getMetrics() {
    return List.of(ENDPOINTS, MUTATING_ENDPOINTS, UNPROTECTED_ENDPOINTS, ASYNC_ENDPOINTS, BLOCKING_CALLS, TAINT_FINDINGS,
      ENDPOINTS_JSON, APP_JSON);
  }
}
