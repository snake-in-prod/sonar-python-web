package io.github.snakeinprod.pythonweb;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.snakeinprod.pythonweb.model.Framework;
import io.github.snakeinprod.pythonweb.model.WebModel;
import io.github.snakeinprod.pythonweb.rules.RuleCatalog;
import io.github.snakeinprod.pythonweb.taint.Finding;
import io.github.snakeinprod.pythonweb.taint.TaintEngine;
import io.github.snakeinprod.pythonweb.taint.TaintModels;
import org.junit.jupiter.api.Test;

/** TaintedSql, TaintedCommand and UnsafeDeserialization against their fixtures: one Django, FastAPI and Flask app each. */
class PythonWebRulesBatch1Test {

  @Test
  void tainted_sql() {
    assertAllFrameworks(RuleVerifier.verify("TaintedSql"));
  }

  @Test
  void tainted_command() {
    assertAllFrameworks(RuleVerifier.verify("TaintedCommand"));
  }

  @Test
  void unsafe_deserialization() {
    assertAllFrameworks(RuleVerifier.verify("UnsafeDeserialization"));
  }

  /** Engine: FastAPI parameters typed int, UUID, Literal, an Enum... (through Annotated, Optional, | None) are no inputs. */
  @Test
  void fastapi_validated_parameters_are_not_inputs() {
    WebModel model = TestProjects.model("main.py", """
      import os
      from enum import Enum
      from typing import Annotated, Literal, Optional
      from uuid import UUID
      from fastapi import FastAPI, Query

      app = FastAPI()

      class Color(str, Enum):
          red = "red"

      @app.get("/a")
      def a(n: int, u: UUID, c: Color, l: Literal["x", "y"], q: Annotated[Optional[int], Query()] = None, f: float | None = None):
          os.system(f"echo {n} {u} {c} {l} {q} {f}")

      @app.get("/b")
      def b(s: str, t: Annotated[str, Query()], o: Optional[str] = None, plain=None):
          os.system(f"echo {s} {t} {o} {plain}")
      """);
    assertThat(TaintEngine.run(model, TaintModels.defaults()).findings()).extracting(Finding::label)
      .containsExactlyInAnyOrder("parameter s", "parameter t", "parameter o", "parameter plain");
  }

  @Test
  void long_descriptions() {
    for (String key : new String[] {"TaintedSql", "TaintedCommand", "UnsafeDeserialization"}) {
      assertThat(RuleCatalog.spec(key).html()).as(key).contains("<h2>Noncompliant code example</h2>", "<h2>Compliant solution</h2>");
    }
  }

  /** The fixture really has endpoints of the three frameworks, so its silent lines are silent with routes known. */
  private static void assertAllFrameworks(WebModel model) {
    assertThat(model.endpoints()).extracting(e -> e.framework() == Framework.DRF ? "django" : e.framework().key())
      .contains("django", "fastapi", "flask");
  }
}
