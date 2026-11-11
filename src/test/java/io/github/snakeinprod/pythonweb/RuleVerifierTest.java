package io.github.snakeinprod.pythonweb;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.snakeinprod.pythonweb.model.Endpoint;
import io.github.snakeinprod.pythonweb.parse.Token;
import io.github.snakeinprod.pythonweb.rules.PwRule;
import io.github.snakeinprod.pythonweb.rules.RuleContext;
import io.github.snakeinprod.pythonweb.taint.Finding;
import org.junit.jupiter.api.Test;

/** The verifier itself, with three small rules written the way real rules are. */
class RuleVerifierTest {

  /** Reports every eval() call: a single file fixture, tokens only. */
  static final class DemoEval implements PwRule {
    @Override
    public void check(RuleContext ctx) {
      for (Token t : ctx.file().tokens()) {
        if (t.isIdent("eval")) {
          ctx.report(t, "Remove this eval() call.");
        }
      }
    }
  }

  /** Reports mutating endpoints without auth: a directory fixture that needs the model. */
  static final class DemoMutatingWithoutAuth implements PwRule {
    @Override
    public void check(RuleContext ctx) {
      for (Endpoint e : ctx.model().endpoints()) {
        if (e.module() == ctx.module() && e.mutating() && !e.auth().present() && ctx.model().usesAuth()) {
          ctx.report(e.token(), "Check the caller of " + String.join("|", e.methods()) + " " + e.path() + ".");
        }
      }
    }
  }

  /** Reports SQL taint findings at their sink, the path as secondary locations: a fixture across two modules. */
  static final class DemoTaintedSql implements PwRule {
    @Override
    public void check(RuleContext ctx) {
      for (Finding f : ctx.taint().findingsIn(ctx.module())) {
        if (f.kind().equals("sql")) {
          ctx.report(f, "Pass " + f.label() + " of " + f.where() + " as a query parameter.");
        }
      }
    }
  }

  @Test
  void single_file_fixture() {
    RuleVerifier.verify("DemoEval", new DemoEval());
  }

  @Test
  void directory_fixture_with_the_model() {
    RuleVerifier.verify("DemoMutatingWithoutAuth", new DemoMutatingWithoutAuth());
  }

  @Test
  void taint_fixture_with_secondary_locations() {
    RuleVerifier.verify("DemoTaintedSql", new DemoTaintedSql());
  }

  @Test
  void a_missing_issue_fails() {
    assertThatThrownBy(() -> RuleVerifier.verify("DemoEval", ctx -> { }))
      .hasMessageContaining("DemoEval.py:5 expected 1 issue(s), got 0");
  }
}
