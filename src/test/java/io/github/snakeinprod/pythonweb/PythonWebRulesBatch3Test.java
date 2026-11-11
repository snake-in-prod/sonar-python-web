package io.github.snakeinprod.pythonweb;

import static org.assertj.core.api.Assertions.assertThat;

import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import io.github.snakeinprod.pythonweb.metrics.EndpointsJson;
import io.github.snakeinprod.pythonweb.metrics.PwMetrics;
import io.github.snakeinprod.pythonweb.model.Endpoint;
import io.github.snakeinprod.pythonweb.model.Module;
import io.github.snakeinprod.pythonweb.model.WebModel;
import io.github.snakeinprod.pythonweb.rules.EndpointWithoutAuth;
import io.github.snakeinprod.pythonweb.sensor.Analyzer;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** EndpointWithoutAuth, CsrfExemptMutation and ResponseModelLeak against their fixtures. */
class PythonWebRulesBatch3Test {

  @Test
  void endpoint_without_auth() {
    WebModel model = RuleVerifier.verify("EndpointWithoutAuth");
    // model: an auth decorator on dispatch protects every handler of the class
    Endpoint move = model.endpoints().stream().filter(e -> e.label().equals("NoteMove.post")).findFirst().orElseThrow();
    assertThat(move.auth().present()).isTrue();
    assertThat(move.auth().evidence()).isEqualTo("NoteMove.dispatch");
  }

  @Test
  void unprotected_tile_and_framework_table_count_the_same_endpoints() {
    WebModel model = RuleVerifier.verify("EndpointWithoutAuth");
    Analyzer analyzer = Analyzer.all(model);
    Map<String, List<Analyzer.Issue>> issues = new HashMap<>();
    int tile = 0;
    for (Module m : model.modules()) {
      issues.put(m.path(), analyzer.analyze(m));
      tile += PwMetrics.fileValues(m, model.endpoints().stream().filter(e -> e.module() == m).toList(), issues.get(m.path()))
        .get(PwMetrics.UNPROTECTED_ENDPOINTS);
    }
    // the page's "without auth" column sums the unprotected flags of pw_endpoints_json over the frameworks
    int table = 0;
    for (JsonElement e : JsonParser.parseString(EndpointsJson.build(model, issues, issues)).getAsJsonArray()) {
      table += e.getAsJsonObject().get("unprotected").getAsBoolean() ? 1 : 0;
    }
    long reported = issues.values().stream().flatMap(List::stream).filter(i -> i.rule().equals("EndpointWithoutAuth")).count();
    // grouped issues ("and 3 more endpoints of NoteViewSet") stand for several endpoints
    assertThat(tile).isEqualTo(table).isGreaterThan((int) reported);
  }

  @Test
  void endpoint_without_auth_is_silent_in_an_app_without_any_auth() {
    RuleVerifier.verify("EndpointWithoutAuthOpenApp", new EndpointWithoutAuth());
  }

  @Test
  void csrf_exempt_mutation() {
    RuleVerifier.verify("CsrfExemptMutation");
  }

  @Test
  void response_model_leak() {
    RuleVerifier.verify("ResponseModelLeak");
  }
}
