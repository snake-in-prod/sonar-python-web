package io.github.snakeinprod.pythonweb;

import io.github.snakeinprod.pythonweb.metrics.PwAggregator;
import io.github.snakeinprod.pythonweb.metrics.PwMetrics;
import io.github.snakeinprod.pythonweb.rules.PwProfiles;
import io.github.snakeinprod.pythonweb.rules.PwRulesDefinition;
import io.github.snakeinprod.pythonweb.sensor.PythonWebSensor;
import org.sonar.api.Plugin;

/** Entry point: rules, the built-in profile, the sensor, the metrics and the page. No settings. */
public class PythonWebPlugin implements Plugin {

  @Override
  public void define(Context context) {
    context.addExtensions(PwRulesDefinition.class, PwProfiles.class, PwMetrics.class, PythonWebSensor.class, PwAggregator.class,
      PythonWebPage.class);
  }
}
