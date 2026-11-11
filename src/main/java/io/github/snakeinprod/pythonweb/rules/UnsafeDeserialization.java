package io.github.snakeinprod.pythonweb.rules;

import io.github.snakeinprod.pythonweb.model.Exprs;
import io.github.snakeinprod.pythonweb.parse.Node;
import io.github.snakeinprod.pythonweb.taint.Finding;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Request data or uploaded files reaching pickle, dill, marshal, jsonpickle, joblib, numpy.load(allow_pickle=True),
 * pandas.read_pickle or yaml.load without a safe loader. A loader named like a safe, base or full loader (a project
 * subclass of SafeLoader, {@code yaml.CSafeLoader}, FullLoader, which no longer builds arbitrary objects) is accepted.
 */
public class UnsafeDeserialization implements PwRule {

  private static final Pattern SAFE_LOADER = Pattern.compile("(Safe|Base|Full)Loader$");

  @Override
  public void check(RuleContext ctx) {
    for (Finding f : ctx.taint().findingsIn(ctx.module())) {
      if (f.kind().equals("deserialization") && !safeLoader(f)) {
        ctx.report(f, "Do not deserialize " + f.label() + " of " + f.where() + " with " + f.sinkName()
          + "(): use JSON, or yaml.safe_load() for YAML.");
      }
    }
  }

  private static boolean safeLoader(Finding f) {
    Node.Group args = SinkCalls.args(f.sink());
    if (args == null) {
      return false;
    }
    List<List<Node>> items = args.items();
    for (int i = 0; i < items.size(); i++) {
      List<Node> item = items.get(i);
      String kw = Exprs.keyword(item);
      if ("Loader".equals(kw) && SAFE_LOADER.matcher(Exprs.text(item.subList(2, item.size()))).find()
        || kw == null && i == 1 && SAFE_LOADER.matcher(Exprs.text(item)).find()) {
        return true;
      }
    }
    return false;
  }
}
