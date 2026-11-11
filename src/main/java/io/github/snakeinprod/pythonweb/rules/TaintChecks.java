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
import java.util.List;
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
  private static final Pattern LOOKUP = Pattern.compile("\\b(filter_by|get_or_404|first_or_404|get_object_or_404|objects\\.get|query\\.get)\\(");
  private static final Pattern REGEX_GROUP =Pattern.compile("\\((?!\\?[:=!<])(?:\\?P<(\\w+)>)?((?:[^()\\\\]|\\\\.)*)\\)");
  private static final Pattern SLASH_FREE = Pattern.compile("(\\\\w|\\\\d|\\[[^\\]/^]*]|\\[\\^/])(\\+|\\*|\\{\\d+(,\\d*)?})?");
  private static final Pattern ADMIN =Pattern.compile("(?i)admin|superuser|staff");
  private static final Set<String> VALIDATORS = Set.of("field_validator", "validator", "model_validator", "root_validator");

  private TaintChecks() {
  }

  /**
   * The findings of this kind whose sink is in the checked module. A rule tests each one, so that one input it trusts
   * does not hide another; the analyzer keeps one issue per sink.
   */
  static List<Finding> bySink(RuleContext ctx, String kind) {
    return ctx.taint().findingsIn(ctx.module()).stream().filter(f -> f.kind().equals(kind)).toList();
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

  /**
   * A value of the path is looked up as a database key before the sink: {@code Image.query.filter_by(image_id=x)},
   * {@code get_object_or_404(Video, pk=x)}, {@code Video.objects.get(slug=x)}, {@code Project.query.filter(Project.name
   * == x)}. It then names an existing row, not a path the caller made up.
   */
  static boolean lookedUpOnPath(Finding f) {
    Set<String> names = new HashSet<>();
    for (Step s : f.path()) {
      for (String prefix : List.of("assigned to ", "request input ")) {
        if (s.message().startsWith(prefix)) {
          names.add(s.message().substring(prefix.length()));
        }
      }
    }
    Step sink = f.path().get(f.path().size() - 1);
    Set<Function> seen = new HashSet<>();
    for (Step s : f.path()) {
      Function fn = s.module().functionAt(s.token().line());
      if (fn == null || !seen.add(fn)) {
        continue;
      }
      if (fn != f.function()) {
        // a helper the value is passed to: get_video_path(id) looks up its parameter
        fn.params().forEach(p -> names.add(p.name()));
      }
      boolean holdsSink = s.module() == sink.module() && fn.firstLine() <= sink.token().line() && sink.token().line() <= fn.lastLine();
      for (PyStatement top : fn.body()) {
        for (PyStatement st : top.walk()) {
          if (holdsSink && st.first().line() >= sink.token().line()) {
            continue;
          }
          String text = Exprs.text(st.nodes());
          for (String n : names) {
            String q = Pattern.quote(n);
            if (LOOKUP.matcher(text).find() && Pattern.compile(LOOKUP.pattern() + "[^)]*(?<![\\w.])" + q + "\\b").matcher(text).find()
              || text.contains("query.filter(") && Pattern.compile("query\\.filter\\([^)]*==\\s*" + q + "\\b").matcher(text).find()) {
              return true;
            }
          }
        }
      }
    }
    return false;
  }

  /**
   * A condition on the way calls a project function whose body checks a URL's host: {@code if _allow_redirect(url):}
   * where the helper reads {@code urlparse(url).netloc}.
   */
  static boolean hostHelperOnPath(RuleContext ctx, Finding f) {
    Set<Function> seen = new HashSet<>();
    for (Step s : f.path()) {
      Function fn = s.module().functionAt(s.token().line());
      if (fn == null || !seen.add(fn)) {
        continue;
      }
      for (PyStatement top : fn.body()) {
        for (PyStatement st : top.walk()) {
          List<Token> ts = Nodes.tokens(st.nodes());
          int from = CONDITIONS.contains(st.keyword()) ? 0 : firstIf(ts);
          for (int i = from; i >= 0 && i + 1 < ts.size(); i++) {
            Function helper = ts.get(i).kind() == TokenKind.IDENT && ts.get(i + 1).is("(")
              ? ctx.model().function(fn.module(), ts.get(i).text()) : null;
            if (helper != null && helper != fn && HOST_CHECKS.matcher(EndpointWithoutAuth.bodyText(helper)).find()) {
              return true;
            }
          }
        }
      }
    }
    return false;
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

  /** The input is the request's own URL or path (request.url, request.path...): it names this server, not another one. */
  static boolean ownUrl(Finding f) {
    return Set.of("request.url", "request.path", "request.full_path", "request.get_full_path").contains(f.label());
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
        if (!slashFreeGroup(e.path(), f.function(), p)) {
          return false;
        }
        continue;
      }
      String conv = m.group(1) != null ? m.group(1) : m.group(2);
      if (conv != null && !conv.equals("str") && !conv.equals("string")) {
        return false;
      }
    }
    return true;
  }

  /**
   * A Django regex route's group for the parameter, by name ({@code (?P<key>\w+)}) or by position after the request
   * ({@code (\w+)}), matches no "/": \w, \d, a class without "/", or [^/].
   */
  private static boolean slashFreeGroup(String path, Function fn, Function.Param p) {
    List<String> positional = new java.util.ArrayList<>();
    Matcher g = REGEX_GROUP.matcher(path);
    while (g.find()) {
      if (g.group(1) != null && g.group(1).equals(p.name())) {
        return SLASH_FREE.matcher(g.group(2)).matches();
      }
      if (g.group(1) == null) {
        positional.add(g.group(2));
      }
    }
    int i = fn.params().indexOf(p) - (fn.takesSelf() ? 2 : 1);
    return i >= 0 && i < positional.size() && SLASH_FREE.matcher(positional.get(i)).matches();
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
