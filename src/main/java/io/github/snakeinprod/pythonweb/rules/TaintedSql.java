package io.github.snakeinprod.pythonweb.rules;

import io.github.snakeinprod.pythonweb.parse.Token;
import io.github.snakeinprod.pythonweb.parse.TokenKind;
import io.github.snakeinprod.pythonweb.taint.Finding;
import io.github.snakeinprod.pythonweb.taint.Step;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Request data reaching raw SQL through a query string built on the way: an f-string field, {@code %}, {@code +} or
 * {@code .format()} next to a string literal on a line of the path. For the method sinks of any receiver (execute,
 * raw, extra, fetch...) one of the path's literals must also read as SQL, so that GraphQL {@code schema.execute(query)}
 * and the like stay silent. A value passed whole, never built, is left alone (a query console is a feature).
 */
public class TaintedSql implements PwRule {

  /** Sinks that only take SQL, whatever the literal looks like. */
  private static final Set<String> SQL_ONLY = Set.of("text", "RawSQL", "read_sql", "read_sql_query");
  private static final Pattern SQL = Pattern.compile("\\b(select\\s.*\\sfrom|insert\\s+into|update\\s+\\S+\\s+set|delete\\s+from"
    + "|where\\s|order\\s+by|group\\s+by|having\\s|values\\s*\\(|(create|drop)\\s+(table|index|view)|alter\\s+table|truncate\\s"
    + "|pragma\\s)|=\\s*'|\\b(and|or)\\s+\\w+\\s*(=|<|>|!=|like\\b|in\\b)", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
  private static final Pattern FIELD = Pattern.compile("(?<!\\{)\\{(?!\\{)");

  @Override
  public void check(RuleContext ctx) {
    for (Finding f : ctx.taint().findingsIn(ctx.module())) {
      if (f.kind().equals("sql") && built(f)) {
        ctx.report(f, "Pass " + f.label() + " of " + f.where() + " to " + f.sinkName()
          + "() as a query parameter instead of building the SQL string.");
      }
    }
  }

  private static boolean built(Finding f) {
    String sink = f.sinkName().substring(f.sinkName().lastIndexOf('.') + 1);
    boolean built = false;
    boolean sql = SQL_ONLY.contains(sink);
    for (Step s : f.path()) {
      List<Token> ts = SinkCalls.statement(s);
      for (int i = 0; i < ts.size(); i++) {
        Token t = ts.get(i);
        if (t.kind() == TokenKind.STRING) {
          built |= isFString(t) && FIELD.matcher(t.text()).find() || op(ts, i - 1) || op(ts, i + 1)
            || i + 2 < ts.size() && ts.get(i + 1).is(".") && (ts.get(i + 2).is("format") || ts.get(i + 2).is("format_map"));
          sql |= SQL.matcher(t.text()).find();
        }
      }
    }
    return built && sql;
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
