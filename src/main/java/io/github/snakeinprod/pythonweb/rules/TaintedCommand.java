package io.github.snakeinprod.pythonweb.rules;

import io.github.snakeinprod.pythonweb.model.Exprs;
import io.github.snakeinprod.pythonweb.parse.Node;
import io.github.snakeinprod.pythonweb.taint.Finding;
import java.util.List;

/**
 * Request data reaching a shell: os.system, os.popen, subprocess.getoutput, asyncio.create_subprocess_shell, and
 * subprocess with shell=True. With shell=True and an argument list that starts with a literal program, the other items
 * are only the shell's positional parameters, never run: silent.
 */
public class TaintedCommand implements PwRule {

  @Override
  public void check(RuleContext ctx) {
    for (Finding f : ctx.taint().findingsIn(ctx.module())) {
      if (f.kind().equals("command") && !literalProgram(f)) {
        ctx.report(f, "Do not pass " + f.label() + " of " + f.where() + " to " + f.sinkName()
          + "() through a shell: use an argument list without shell=True, or shlex.quote().");
      }
    }
  }

  private static boolean literalProgram(Finding f) {
    Node.Group args = SinkCalls.args(f.sink());
    if (args == null || args.items().isEmpty()) {
      return false;
    }
    List<Node> first = args.items().get(0);
    return first.size() == 1 && first.get(0) instanceof Node.Group g && (g.is("[") || g.is("(")) && !g.items().isEmpty()
      && Exprs.string(g.items().get(0)) != null;
  }
}
