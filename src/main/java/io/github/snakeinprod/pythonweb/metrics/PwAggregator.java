package io.github.snakeinprod.pythonweb.metrics;

import org.sonar.api.ce.measure.Component;
import org.sonar.api.ce.measure.Measure;
import org.sonar.api.ce.measure.MeasureComputer;
import org.sonar.api.measures.Metric;

/** Sums the integer pw_* measures from files to directories and the project. */
public class PwAggregator implements MeasureComputer {

  @Override
  public MeasureComputerDefinition define(MeasureComputerDefinitionContext def) {
    return def.newDefinitionBuilder().setOutputMetrics(PwMetrics.SUMMED.stream().map(Metric::getKey).toArray(String[]::new)).build();
  }

  @Override
  public void compute(MeasureComputerContext ctx) {
    if (ctx.getComponent().getType() == Component.Type.FILE) {
      return;
    }
    for (Metric<Integer> m : PwMetrics.SUMMED) {
      int sum = 0;
      boolean any = false;
      for (Measure child : ctx.getChildrenMeasures(m.getKey())) {
        sum += child.getIntValue();
        any = true;
      }
      if (any && ctx.getMeasure(m.getKey()) == null) {
        ctx.addMeasure(m.getKey(), sum);
      }
    }
  }
}
