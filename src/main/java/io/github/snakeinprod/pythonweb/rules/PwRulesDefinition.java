package io.github.snakeinprod.pythonweb.rules;

import org.sonar.api.issue.impact.Severity;
import org.sonar.api.issue.impact.SoftwareQuality;
import org.sonar.api.rules.CleanCodeAttribute;
import org.sonar.api.rules.RuleType;
import org.sonar.api.server.rule.RulesDefinition;

/** The repository pythonweb-python for language py. */
public class PwRulesDefinition implements RulesDefinition {

  @Override
  public void define(Context context) {
    NewRepository repo = context.createRepository(RuleCatalog.REPOSITORY, RuleCatalog.LANGUAGE).setName("Python Web");
    for (RuleCatalog.Spec spec : RuleCatalog.ALL) {
      NewRule rule = repo.createRule(spec.key())
        .setName(spec.name())
        .setHtmlDescription(spec.html())
        .setSeverity(spec.severity())
        .setTags("python-web");
      Severity impact = switch (spec.severity()) {
        case "BLOCKER", "CRITICAL" -> Severity.HIGH;
        case "MINOR", "INFO" -> Severity.LOW;
        default -> Severity.MEDIUM;
      };
      switch (spec.type()) {
        case VULNERABILITY -> rule.setType(RuleType.VULNERABILITY).addDefaultImpact(SoftwareQuality.SECURITY, impact)
          .setCleanCodeAttribute(CleanCodeAttribute.TRUSTWORTHY);
        case BUG -> rule.setType(RuleType.BUG).addDefaultImpact(SoftwareQuality.RELIABILITY, impact)
          .setCleanCodeAttribute(CleanCodeAttribute.LOGICAL);
        case CODE_SMELL -> rule.setType(RuleType.CODE_SMELL).addDefaultImpact(SoftwareQuality.MAINTAINABILITY, impact)
          .setCleanCodeAttribute(CleanCodeAttribute.EFFICIENT);
      }
    }
    repo.done();
  }
}
