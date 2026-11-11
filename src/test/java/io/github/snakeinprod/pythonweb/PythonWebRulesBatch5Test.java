package io.github.snakeinprod.pythonweb;

import org.junit.jupiter.api.Test;

/** MutableDefaultInModel and NPlusOneQuery against their fixtures. */
class PythonWebRulesBatch5Test {

  @Test
  void mutable_default_in_model() {
    RuleVerifier.verify("MutableDefaultInModel");
  }

  @Test
  void n_plus_one_query() {
    RuleVerifier.verify("NPlusOneQuery");
  }
}
