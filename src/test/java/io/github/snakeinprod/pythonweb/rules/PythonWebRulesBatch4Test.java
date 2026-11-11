package io.github.snakeinprod.pythonweb.rules;

import io.github.snakeinprod.pythonweb.RuleVerifier;
import org.junit.jupiter.api.Test;

class PythonWebRulesBatch4Test {

  @Test
  void blocking_call_in_async() {
    RuleVerifier.verify("BlockingCallInAsync");
  }

  @Test
  void missing_await() {
    RuleVerifier.verify("MissingAwait");
  }
}
