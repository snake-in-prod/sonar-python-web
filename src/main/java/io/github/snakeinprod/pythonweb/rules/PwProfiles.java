package io.github.snakeinprod.pythonweb.rules;

import org.sonar.api.server.profile.BuiltInQualityProfilesDefinition;

/**
 * The built-in "Python Web" profile for py with the active rules. SonarQube refuses a second built-in "Sonar way" for
 * a language, so the rules cannot join the Python analyzer's; activate them in your own profile, or extend this one.
 */
public class PwProfiles implements BuiltInQualityProfilesDefinition {

  public static final String NAME = "Python Web";

  @Override
  public void define(Context context) {
    NewBuiltInQualityProfile profile = context.createBuiltInQualityProfile(NAME, RuleCatalog.LANGUAGE);
    for (RuleCatalog.Spec spec : RuleCatalog.ALL) {
      if (spec.active()) {
        profile.activateRule(RuleCatalog.REPOSITORY, spec.key());
      }
    }
    profile.done();
  }
}
