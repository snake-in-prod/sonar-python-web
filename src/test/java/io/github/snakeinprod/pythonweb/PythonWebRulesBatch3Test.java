package io.github.snakeinprod.pythonweb;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.snakeinprod.pythonweb.model.Endpoint;
import io.github.snakeinprod.pythonweb.model.WebModel;
import io.github.snakeinprod.pythonweb.rules.EndpointWithoutAuth;
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
