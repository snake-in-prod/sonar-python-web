package io.github.snakeinprod.pythonweb.rules;

import io.github.snakeinprod.pythonweb.lang.python.PyStatement;
import io.github.snakeinprod.pythonweb.model.Exprs;
import io.github.snakeinprod.pythonweb.model.Function;
import io.github.snakeinprod.pythonweb.parse.Node;
import io.github.snakeinprod.pythonweb.parse.Nodes;
import io.github.snakeinprod.pythonweb.parse.Token;
import io.github.snakeinprod.pythonweb.parse.TokenKind;
import io.github.snakeinprod.pythonweb.taint.Finding;
import io.github.snakeinprod.pythonweb.taint.Step;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Request data reaching raw SQL through a query string built on the way: an f-string field, {@code %}, {@code +} or
 * {@code .format()} next to a string literal on a line of the path. For the method sinks of any receiver (execute,
 * raw, extra, fetch...) one of the path's literals, or a literal assigned to a name on the sink's line, must also read
 * as SQL, so that GraphQL {@code schema.execute(query)} and the like stay silent. A value passed whole, never built, is
 * left alone (a query console is a feature), and so is one wrapped as a subquery ({@code SELECT * FROM ({q}) _t}). A
 * SET clause built from a typed body's field names with bound values ({@code f"{k} = :{k}"}) is silent too.
 */
public class TaintedSql implements PwRule {

  /** Sinks that only take SQL, whatever the literal looks like. */
  private static final Set<String> SQL_ONLY = Set.of("text", "RawSQL", "read_sql", "read_sql_query");
  private static final Pattern SQL = Pattern.compile("\\b(select\\s.*\\sfrom|insert\\s+into|update\\s+\\S+\\s+set|delete\\s+from"
    + "|where\\s|order\\s+by|group\\s+by|having\\s|values\\s*\\(|(create|drop)\\s+(table|index|view)|alter\\s+table|truncate\\s"
    + "|pragma\\s)|=\\s*'|\\b(and|or)\\s+\\w+\\s*(=|<|>|!=|like\\b|in\\b)", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
  /** f"{k} = :{k}": a column named by a key of the model's fields, its value bound as a parameter. */
  private static final Pattern BOUND_COLUMN = Pattern.compile("\\{(\\w+)}\\s*=\\s*:\\{\\1}");
  private static final Pattern SUBQUERY =Pattern.compile("(?i)\\bfrom\\s*\\(\\s*(\\{[^}]*}|%s)\\s*\\)");
  private static final Pattern FIELD =Pattern.compile("(?<!\\{)\\{(?!\\{)");

  @Override
  public void check(RuleContext ctx) {
    for (Finding f : ctx.taint().findingsIn(ctx.module())) {
      if (f.kind().equals("sql") && built(f) && !dumpedModel(f)) {
        ctx.report(f, "Pass " + f.label() + " of " + f.where() + " to " + f.sinkName()
          + "() as a query parameter instead of building the SQL string.");
      }
    }
  }

  private static boolean built(Finding f) {
    String sink = f.sinkName().substring(f.sinkName().lastIndexOf('.') + 1);
    boolean built = false;
    boolean console = false;
    boolean sql = SQL_ONLY.contains(sink);
    for (Step s : f.path()) {
      List<Token> ts = SinkCalls.statement(s);
      for (int i = 0; i < ts.size(); i++) {
        Token t = ts.get(i);
        if (t.kind() == TokenKind.STRING) {
          built |= isFString(t) && FIELD.matcher(t.text()).find() || op(ts, i - 1) || op(ts, i + 1)
            || i + 2 < ts.size() && ts.get(i + 1).is(".") && (ts.get(i + 2).is("format") || ts.get(i + 2).is("format_map"));
          sql |= SQL.matcher(t.text()).find();
          // SELECT * FROM ({query}) _t: the caller's whole query wrapped as a subquery, a query console
          console |= SUBQUERY.matcher(t.text()).find();
        }
      }
    }
    return built && !console && (sql || sqlConstant(f));
  }

  /**
   * A name on the sink's line holds an SQL literal: {@code prefix = "SELECT ... like '%"} assigned in the sink's function
   * or at module level, then {@code execute(prefix + q + "%'")}.
   */
  private static boolean sqlConstant(Finding f) {
    Step sink = f.path().get(f.path().size() - 1);
    Set<String> names = new HashSet<>();
    SinkCalls.statement(sink).stream().filter(t -> t.kind() == TokenKind.IDENT).forEach(t -> names.add(t.text()));
    List<List<Node>> values = new ArrayList<>();
    names.forEach(n -> values.addAll(sink.module().assignments().getOrDefault(n, List.of())));
    Function fn = sink.module().functionAt(sink.token().line());
    for (PyStatement top : fn == null ? List.<PyStatement>of() : fn.body()) {
      for (PyStatement s : top.walk()) {
        List<List<Node>> parts = Exprs.assignment(s.nodes());
        String target = parts.size() == 2 ? Exprs.dotted(Exprs.unannotated(parts.get(0))) : null;
        if (target != null && names.contains(target)) {
          values.add(parts.get(1));
        }
      }
    }
    for (List<Node> v : values) {
      for (Token t : Nodes.tokens(v)) {
        if (t.kind() == TokenKind.STRING && SQL.matcher(t.text()).find()) {
          return true;
        }
      }
    }
    return false;
  }

  /**
   * A typed body parameter dumped on the way ({@code data.model_dump(exclude_unset=True)}), or a SET clause of
   * {@code f"{k} = :{k}"} pairs: the SQL is built from field names, which the model fixes, while the values go as
   * parameters. Only for parameters (FastAPI bodies); a Flask request.json dict has the caller's keys.
   */
  private static boolean dumpedModel(Finding f) {
    if (!f.label().startsWith("parameter ")) {
      return false;
    }
    for (Step s : f.path()) {
      List<Token> ts = SinkCalls.statement(s);
      for (int i = 1; i < ts.size(); i++) {
        if (ts.get(i - 1).is(".") && (ts.get(i).isIdent("model_dump") || ts.get(i).isIdent("dict"))
          || ts.get(i).kind() == TokenKind.STRING && BOUND_COLUMN.matcher(ts.get(i).text()).find()) {
          return true;
        }
      }
    }
    return false;
  }

  private static boolean op(List<Token> ts, int i) {
    return i >= 0 && i < ts.size() && ts.get(i).kind() == TokenKind.OP && (ts.get(i).is("%") || ts.get(i).is("+"));
  }

  private static boolean isFString(Token t) {
    String s = t.text();
    int q = 0;
    while (q < s.length() && s.charAt(q) != '\'' && s.charAt(q) != '"') {
      q++;
    }
    return s.substring(0, q).toLowerCase(Locale.ROOT).contains("f");
  }
}
