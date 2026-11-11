package io.github.snakeinprod.pythonweb.rules;

import io.github.snakeinprod.pythonweb.lang.python.PyStatement;
import io.github.snakeinprod.pythonweb.model.Endpoint;
import io.github.snakeinprod.pythonweb.model.Exprs;
import io.github.snakeinprod.pythonweb.model.Function;
import io.github.snakeinprod.pythonweb.model.PyClass;
import io.github.snakeinprod.pythonweb.parse.Nodes;
import io.github.snakeinprod.pythonweb.parse.Token;
import io.github.snakeinprod.pythonweb.parse.TokenKind;
import io.github.snakeinprod.pythonweb.taint.Finding;
import io.github.snakeinprod.pythonweb.taint.Step;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * What the path, URL, redirect and markup rules share: one issue per sink, and the checks on a value the engine cannot
 * follow (a parsed URL's host compared, a ".." test), after which a rule stays silent.
 */
final class TaintChecks {

  private static final Set<String> CONDITIONS = Set.of("if", "elif", "while", "assert");
  private static final Pattern ORIGIN = Pattern.compile("^[A-Za-z][A-Za-z0-9+.-]*://[^/?#\\\\@\\s]+");
  /** Names that show a URL's host being checked. */
  static final Pattern HOST_CHECKS = Pattern.compile("(?i)safe|allowed|trusted|whitelist|allowlist|netloc|hostname");
  private static final Pattern URL_VALIDATORS = Pattern.compile("(?i)^_?(validate|check|verify|ensure|is_valid|is_allowed)\\w*(url|uri|host|domain)|ssrf");
  private static final Pattern ADMIN = Pattern.compile("(?i)admin|superuser|staff");
  private static final Set<String> VALIDATORS = Set.of("field_validator", "validator", "model_validator", "root_validator");

  private TaintChecks() {
  }

  /** The findings of this kind whose sink is in the checked module, the first one of each sink. */
  static List<Finding> bySink(RuleContext ctx, String kind) {
    Map<String, Finding> out = new LinkedHashMap<>();
    for (Finding f : ctx.taint().findingsIn(ctx.module())) {
      if (f.kind().equals(kind)) {
        out.putIfAbsent(f.sink().token().line() + ":" + f.sink().token().column(), f);
      }
    }
    return List.copyOf(out.values());
  }

  /**
   * Whether a condition (if, elif, while, assert, or the condition of a conditional expression or comprehension) in a
   * function along the path holds a token that passes the test.
   */
  static boolean checkedOnPath(Finding f, Predicate<Token> test) {
    return onPath(f, test, true);
  }

  /** Whether a URL check helper runs in a function along the path: validate_url(url), check_host(...), ensure_safe_uri(...). */
  static boolean validatedOnPath(Finding f) {
    return onPath(f, t -> ident(t, URL_VALIDATORS), false);
  }

  /** The endpoint is for administrators only (Depends(get_admin_user), staff_member_required...): they configure URLs. */
  static boolean adminOnly(Finding f) {
    Endpoint e = f.endpoint();
    return e != null && e.auth().present() && e.auth().evidence() != null && ADMIN.matcher(e.auth().evidence()).find();
  }

  private static boolean onPath(Finding f, Predicate<Token> test, boolean conditionsOnly) {
    Set<Function> seen = new HashSet<>();
    for (Step s : f.path()) {
      Function fn = s.module().functionAt(s.token().line());
      if (fn == null || !seen.add(fn)) {
        continue;
      }
      for (PyStatement top : fn.body()) {
        for (PyStatement st : top.walk()) {
          List<Token> ts = Nodes.tokens(st.nodes());
          int from = !conditionsOnly || CONDITIONS.contains(st.keyword()) ? 0 : firstIf(ts);
          for (int i = from; i >= 0 && i < ts.size(); i++) {
            if (test.test(ts.get(i))) {
              return true;
            }
          }
        }
      }
    }
    return false;
  }

  static boolean ident(Token t, Pattern p) {
    return t.kind() == TokenKind.IDENT && p.matcher(t.text()).find();
  }

  /** A plain string literal whose value passes the test. */
  static boolean literal(Token t, Predicate<String> test) {
    String v = t.kind() == TokenKind.STRING ? Exprs.literal(t) : null;
    return v != null && test.test(v);
  }

  /** "https://partner.example...": a literal naming a host, as an allow-list prefix does. */
  static boolean origin(String s) {
    return ORIGIN.matcher(s).find();
  }

  /** The input is read from a header or a cookie: request.META, request.headers, a FastAPI Header() or Cookie() parameter. */
  static boolean fromHeaderOrCookie(Finding f) {
    if (Set.of("request.META", "request.headers", "request.COOKIES", "request.cookies").contains(f.label())) {
      return true;
    }
    Function.Param p = param(f);
    if (p == null) {
      return false;
    }
    String text = p.annotationText() + "=" + Exprs.text(p.defaultValue());
    return text.contains("Header(") || text.contains("Cookie(");
  }

  /**
   * The input is a URL path parameter whose converter never matches "/" (Django and Flask str, FastAPI without :path)
   * on every route of its function: it cannot name another directory.
   */
  static boolean slashFreePathParam(RuleContext ctx, Finding f) {
    Function.Param p = param(f);
    List<Endpoint> es = p == null ? List.of() : ctx.model().endpointsOf(f.function());
    if (es.isEmpty()) {
      return false;
    }
    String q = Pattern.quote(p.name());
    Pattern placeholder = Pattern.compile("(?<!\\?P)<(?:(\\w+)(?:\\([^>]*\\))?:)?" + q + ">|\\{" + q + "(?::(\\w+))?}");
    for (Endpoint e : es) {
      Matcher m = placeholder.matcher(e.path());
      if (!m.find()) {
        return false;
      }
      String conv = m.group(1) != null ? m.group(1) : m.group(2);
      if (conv != null && !conv.equals("str") && !conv.equals("string")) {
        return false;
      }
    }
    return true;
  }

  /**
   * The input is a parameter typed with a project model class that validates its fields (Pydantic field_validator,
   * validator, model_validator, root_validator): the engine cannot see what the validators allow.
   */
  static boolean validatedModel(RuleContext ctx, Finding f) {
    Function.Param p = param(f);
    String type = p == null ? null : Exprs.dotted(p.annotation());
    PyClass c = type == null ? null : ctx.model().cls(f.function().module(), type);
    if (c == null) {
      return false;
    }
    for (PyClass k : ctx.model().hierarchy(c)) {
      for (Function m : k.methods()) {
        if (m.decorators().stream().anyMatch(d -> VALIDATORS.contains(d.last()))) {
          return true;
        }
      }
    }
    return false;
  }

  /** The parameter a "parameter x" input is, or null. */
  private static Function.Param param(Finding f) {
    return f.label().startsWith("parameter ") && f.function() != null ? f.function().param(f.label().substring(10)) : null;
  }

  private static int firstIf(List<Token> ts) {
    for (int i = 0; i < ts.size(); i++) {
      if (ts.get(i).isIdent("if")) {
        return i;
      }
    }
    return -1;
  }
}
