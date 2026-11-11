package io.github.snakeinprod.pythonweb;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.snakeinprod.pythonweb.metrics.PwMetrics;
import io.github.snakeinprod.pythonweb.rules.PwProfiles;
import io.github.snakeinprod.pythonweb.rules.PwRulesDefinition;
import io.github.snakeinprod.pythonweb.rules.RuleCatalog;
import io.github.snakeinprod.pythonweb.taint.TaintModels;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.sonar.api.issue.impact.Severity;
import org.sonar.api.issue.impact.SoftwareQuality;
import org.sonar.api.rules.RuleType;
import org.sonar.api.server.profile.BuiltInQualityProfilesDefinition;
import org.sonar.api.server.rule.RulesDefinition;
import org.sonar.api.web.page.Context;
import org.sonar.api.web.page.Page;

class PluginTest {

  @Test
  void catalog() {
    List<String> keys = RuleCatalog.ALL.stream().map(RuleCatalog.Spec::key).toList();
    assertThat(keys).hasSize(14);
    assertThat(new HashSet<>(keys)).hasSameSizeAs(keys);
    assertThat(RuleCatalog.ALL).allSatisfy(s -> assertThat(s.factory().get()).isNotNull());
    assertThat(RuleCatalog.ALL.stream().filter(s -> !s.active()).map(RuleCatalog.Spec::key))
      .containsExactlyInAnyOrder("ResponseModelLeak", "NPlusOneQuery");
    // every taint rule reads a sink kind the models define
    List<String> kinds = TaintModels.defaults().sinks().stream().map(TaintModels.Sink::kind).distinct().toList();
    assertThat(RuleCatalog.ALL.stream().map(RuleCatalog.Spec::sinkKind).filter(k -> k != null))
      .hasSize(7).allMatch(kinds::contains);
    assertThat(PwMetrics.TAINT_RULES).hasSize(7).contains("TaintedSql", "UnsafeDeserialization");
  }

  @Test
  void repository_with_types_and_impacts() {
    RulesDefinition.Context context = new RulesDefinition.Context();
    new PwRulesDefinition().define(context);
    RulesDefinition.Repository repo = context.repository("pythonweb-python");
    assertThat(repo.language()).isEqualTo("py");
    assertThat(repo.rules()).hasSize(14);
    RulesDefinition.Rule sql = repo.rule("TaintedSql");
    assertThat(sql.type()).isEqualTo(RuleType.VULNERABILITY);
    assertThat(sql.defaultImpacts()).containsEntry(SoftwareQuality.SECURITY, Severity.HIGH);
    assertThat(sql.tags()).contains("python-web");
    assertThat(sql.htmlDescription()).contains("<h2>Noncompliant code example</h2>");
    assertThat(repo.rule("BlockingCallInAsync").defaultImpacts()).containsEntry(SoftwareQuality.RELIABILITY, Severity.MEDIUM);
    assertThat(repo.rule("NPlusOneQuery").defaultImpacts()).containsEntry(SoftwareQuality.MAINTAINABILITY, Severity.LOW);
  }

  @Test
  void built_in_profile() {
    BuiltInQualityProfilesDefinition.Context context = new BuiltInQualityProfilesDefinition.Context();
    new PwProfiles().define(context);
    BuiltInQualityProfilesDefinition.BuiltInQualityProfile p = context.profile("py", "Python Web");
    assertThat(p.isDefault()).isFalse();
    assertThat(p.rules()).hasSize(12).allMatch(r -> r.repoKey().equals("pythonweb-python"));
  }

  @Test
  void page_script_registers_the_page_key() throws IOException {
    Context context = new Context();
    new PythonWebPage().define(context);
    String key = context.getPages().stream().map(Page::getKey).findFirst().orElseThrow();
    // SonarQube serves the page from static/<plugin key>/<page>.js -> static/<page>.js in the jar
    try (InputStream in = getClass().getResourceAsStream("/static/" + key.substring(key.indexOf('/') + 1) + ".js")) {
      assertThat(in).isNotNull();
      String js = new String(in.readAllBytes(), StandardCharsets.UTF_8);
      assertThat(js).contains("window.registerExtension('" + key + "'");
      // SonarQube places extension pages in a two-column grid
      assertThat(js).contains("options.el.style.gridColumn = '1 / -1'", "options.el.style.width = '100%'", "aria-label")
        .doesNotContain("container-type", "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(");
    }
  }
}
