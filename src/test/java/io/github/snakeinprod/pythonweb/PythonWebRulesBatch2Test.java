package io.github.snakeinprod.pythonweb;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.snakeinprod.pythonweb.taint.Finding;
import io.github.snakeinprod.pythonweb.taint.TaintEngine;
import io.github.snakeinprod.pythonweb.taint.TaintModels;
import java.util.List;
import org.junit.jupiter.api.Test;

/** TaintedPath, TaintedUrlFetch, OpenRedirect and UnsafeTemplate on their fixtures, and the engine parts they need. */
class PythonWebRulesBatch2Test {

  @Test
  void tainted_path() {
    RuleVerifier.verify("TaintedPath");
  }

  @Test
  void tainted_url_fetch() {
    RuleVerifier.verify("TaintedUrlFetch");
  }

  @Test
  void open_redirect() {
    RuleVerifier.verify("OpenRedirect");
  }

  @Test
  void unsafe_template() {
    RuleVerifier.verify("UnsafeTemplate");
  }

  private static List<String> kinds(String... files) {
    return TaintEngine.run(TestProjects.model(files), TaintModels.defaults()).findings().stream()
      .map(f -> f.kind() + ":" + f.sink().token().line()).toList();
  }

  @Test
  void a_literal_start_that_fixes_the_host_clears_urls_only() {
    List<String> found = kinds("app/main.py", """
      import httpx
      from fastapi import FastAPI
      from fastapi.responses import RedirectResponse

      app = FastAPI()

      @app.get("/a")
      def a(x: str):
          httpx.get(f"https://api.example/items/{x}")
          httpx.get("https://api.example/" + x)
          httpx.get("https://api.example/%s" % x)
          RedirectResponse("/items/" + x)
          httpx.get(f"https://{x}/items")
          httpx.get("https://api.example" + x)
          RedirectResponse("/" + x)
          open(f"/srv/{x}")
          httpx.get(f"https://keys.{REGION}.example/{x}")
          httpx.get(f"https://{REGION}{x}/")
          RedirectResponse("/home?from=a" + f"&next={x}")
      """);
    assertThat(found).containsExactly("ssrf:13", "ssrf:14", "redirect:15", "path:16", "ssrf:18");
  }

  @Test
  void fastapi_scalar_parameters_are_not_inputs() {
    List<Finding> found = TaintEngine.run(TestProjects.model("app/main.py", """
      from typing import Annotated, Optional
      from uuid import UUID
      from fastapi import FastAPI, Query

      app = FastAPI()

      @app.get("/a")
      def a(n: int, m: Optional[float], k: Annotated[int, Query(gt=0)], u: UUID, b: int | None, s: str):
          open(f"/srv/{n}{m}{k}{u}{b}")
          open(f"/srv/{s}")
      """), TaintModels.defaults()).findings();
    assertThat(found).extracting(Finding::label).containsExactly("parameter s");
  }
}
