package io.github.snakeinprod.pythonweb.rules;

import io.github.snakeinprod.pythonweb.taint.Finding;
import java.util.regex.Pattern;

/**
 * Request data reaching open(), pathlib reads and writes, send_file, FileResponse or os.remove. Silent for a URL path
 * parameter that cannot hold "/", for a model parameter whose class validates its fields, and when a condition on the
 * way resolves or compares the path or tests for "..".
 */
public final class TaintedPath implements PwRule {

  private static final Pattern CHECKS = Pattern.compile("safe|realpath|abspath|commonpath|commonprefix|is_relative_to|parents|resolve");

  @Override
  public void check(RuleContext ctx) {
    for (Finding f : TaintChecks.bySink(ctx, "path")) {
      if (!TaintChecks.slashFreePathParam(ctx, f) && !TaintChecks.validatedModel(ctx, f)
        && !TaintChecks.checkedOnPath(f, t -> TaintChecks.ident(t, CHECKS) || TaintChecks.literal(t, s -> s.contains("..")))) {
        ctx.report(f, "Make sure " + f.label() + " of " + f.where() + " stays in its directory before it reaches " + f.sinkName() + "().");
      }
    }
  }
}
