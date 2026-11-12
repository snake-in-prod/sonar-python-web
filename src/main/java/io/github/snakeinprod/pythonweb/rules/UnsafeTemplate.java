package io.github.snakeinprod.pythonweb.rules;

import io.github.snakeinprod.pythonweb.lang.python.PyStatement;
import io.github.snakeinprod.pythonweb.model.Decorator;
import io.github.snakeinprod.pythonweb.model.Endpoint;
import io.github.snakeinprod.pythonweb.model.Exprs;
import io.github.snakeinprod.pythonweb.model.Framework;
import io.github.snakeinprod.pythonweb.model.Function;
import io.github.snakeinprod.pythonweb.parse.Chain;
import io.github.snakeinprod.pythonweb.parse.Node;
import io.github.snakeinprod.pythonweb.parse.Nodes;
import io.github.snakeinprod.pythonweb.parse.Token;
import io.github.snakeinprod.pythonweb.parse.TokenKind;
import io.github.snakeinprod.pythonweb.taint.Finding;
import io.github.snakeinprod.pythonweb.taint.Step;
import io.github.snakeinprod.pythonweb.taint.Taint;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Request data reaching mark_safe, Markup, render_template_string, a template built from it, or HTMLResponse; and
 * request data returned in a string by a FastAPI endpoint declared with response_class=HTMLResponse, or in a string
 * with an HTML tag by a Flask view or in a Django HttpResponse.
 */
public final class UnsafeTemplate implements PwRule {

  private static final Pattern TAG = Pattern.compile("</?[A-Za-z][A-Za-z0-9]*(\\s[^<>]*)?/?>");
  private static final Pattern CUSTOM_HEADER = Pattern.compile("^\\s*(\\.get\\(|\\[)\\s*['\"](HTTP_X_|X-)",
    Pattern.CASE_INSENSITIVE);
  private static final Set<String> HTML_RESPONSES = Set.of("fastapi.responses.HTMLResponse", "starlette.responses.HTMLResponse");
  private static final Pattern DJANGO_RESPONSE = Pattern.compile(
    "django\\.http\\.(response\\.)?HttpResponse(BadRequest|NotFound|Forbidden|ServerError)?");

  @Override
  public void check(RuleContext ctx) {
    for (Finding f : TaintChecks.bySink(ctx, "template")) {
      if (TaintChecks.markupFreePathParam(ctx, f) || customHeader(f.source())) {
        continue;
      }
      if (!DJANGO_RESPONSE.matcher(ctx.module().resolve(f.sinkName())).matches()) {
        ctx.report(f, "Let the template engine escape " + f.label() + " of " + f.where() + " instead of passing it to "
          + f.sinkName() + "().");
      } else if (htmlResponse(ctx, f)) {
        ctx.report(f, "Let the template engine escape " + f.label() + " of " + f.where() + " instead of writing it in the HTML of "
          + f.sinkName() + "().");
      }
    }
    Set<Function> seen = new HashSet<>();
    for (Endpoint e : ctx.model().endpoints()) {
      Function fn = e.function();
      boolean flask = e.framework() == Framework.FLASK;
      if (e.module() == ctx.module() && fn != null && (flask || e.framework() == Framework.FASTAPI && returnsHtml(fn)) && seen.add(fn)) {
        returned(ctx, e, fn, flask);
      }
    }
  }

  /**
   * Request data returned in a string (an f-string, a concatenation, a variable) as the HTML page: once per return. A
   * Flask view's string is HTML too; there the string must hold a tag ({@link #htmlValue}).
   */
  private static void returned(RuleContext ctx, Endpoint e, Function fn, boolean flask) {
    Set<Token> done = new HashSet<>();
    for (Map.Entry<Taint.Origin, Taint.Flow> en : ctx.taint().summary(fn).returnSources().flows().entrySet()) {
      Taint.Flow flow = en.getValue();
      if (flow.cleared().contains("template") || flow.cleared().contains("*") || flow.path().isEmpty()
        || customHeader(en.getKey().source())) {
        continue;
      }
      Step last = flow.path().get(flow.path().size() - 1);
      PyStatement ret = returnAt(fn, last.token());
      if (ret == null || !done.add(last.token())) {
        continue;
      }
      List<Node> value = ret.nodes().subList(1, ret.nodes().size());
      Token lead = value.isEmpty() ? null : Nodes.leaf(value.get(0));
      boolean html = flask ? htmlValue(fn, value)
        : lead != null && (lead.kind() == TokenKind.STRING || lead.kind() == TokenKind.IDENT && value.size() == 1);
      if (html) {
        ctx.report(value.get(0).first(), ret.last(), "Let the template engine escape " + en.getKey().label() + " of "
          + String.join("|", e.methods()) + " " + e.path() + " instead of returning it in HTML.", flow.path().subList(0, flow.path().size() - 1));
      }
    }
  }

  /** A string written in place (literal, f-string, concatenation, % or format) whose constant part holds an HTML tag. */
  private static boolean htmlString(List<Node> value) {
    Token lead = value == null || value.isEmpty() ? null : Nodes.leaf(value.get(0));
    return lead != null && lead.kind() == TokenKind.STRING
      && Nodes.tokens(value).stream().anyMatch(t -> t.kind() == TokenKind.STRING && TAG.matcher(t.text()).find());
  }

  /**
   * The string written in place, or a variable or {@code "".join(...)} the function builds from such strings
   * ({@code html = "<ul>"}, {@code html += f"<li>{q}</li>"}, {@code parts.append(...)}): one of them holds an HTML tag.
   */
  private static boolean htmlValue(Function fn, List<Node> value) {
    return htmlValue(fn, value, new HashSet<>());
  }

  private static boolean htmlValue(Function fn, List<Node> value, Set<String> seen) {
    if (htmlString(value)) {
      return true;
    }
    if (value == null || fn == null) {
      return false;
    }
    List<List<Node>> items = Nodes.split(value, ",");
    if (items.size() > 1) {
      // return html, 404
      return htmlValue(fn, items.get(0), seen);
    }
    if (value.size() == 1 && value.get(0) instanceof Node.Group g && g.is("(")) {
      return htmlValue(fn, g.children(), seen);
    }
    Token lead = value.isEmpty() ? null : Nodes.leaf(value.get(0));
    if (value.size() == 4 && lead != null && lead.kind() == TokenKind.STRING && Nodes.isLeaf(value.get(1), ".")
      && Nodes.isIdent(value.get(2), "join") && value.get(3) instanceof Node.Group g && g.is("(")) {
      // "".join(parts), "".join(f"<li>{x}</li>" for x in xs)
      return htmlPieces(g.children()) || htmlValue(fn, g.children(), seen);
    }
    if (value.size() != 1 || lead == null || lead.kind() != TokenKind.IDENT || !seen.add(lead.text())) {
      return false;
    }
    String name = lead.text();
    for (PyStatement top : fn.body()) {
      for (PyStatement s : top.walk()) {
        List<Node> n = s.nodes();
        if (!s.body().isEmpty() || n.size() < 3 || !Nodes.isIdent(n.get(0), name)) {
          continue;
        }
        List<Node> piece = null;
        if (Nodes.isLeaf(n.get(1), "=") || Nodes.isLeaf(n.get(1), "+=")) {
          piece = n.subList(2, n.size());
        } else if (n.size() == 4 && Nodes.isLeaf(n.get(1), ".") && n.get(3) instanceof Node.Group g && g.is("(")
          && Set.of("append", "extend", "insert").contains(Nodes.text(n.get(2)))) {
          piece = g.children();
        }
        if (piece != null && (htmlPieces(piece) || htmlValue(fn, piece, seen))) {
          return true;
        }
      }
    }
    return false;
  }

  /**
   * Strings built in place: a literal, f-string, concatenation (also {@code html + "<li>"}), a list or a comprehension
   * of them, with a tag in a literal part.
   */
  private static boolean htmlPieces(List<Node> piece) {
    Token lead = piece.isEmpty() ? null : Nodes.leaf(piece.get(0));
    boolean built = lead != null && (lead.kind() == TokenKind.STRING || lead.kind() == TokenKind.IDENT && piece.size() > 2
      && Nodes.isLeaf(piece.get(1), "+")) || piece.size() == 1 && piece.get(0) instanceof Node.Group g && g.is("[");
    return built && Nodes.tokens(piece).stream().anyMatch(t -> t.kind() == TokenKind.STRING && TAG.matcher(t.text()).find());
  }

  /**
   * A Django HttpResponse whose content is a string with an HTML tag ({@link #htmlValue}), sent as HTML: no content_type, or one naming
   * html. A text/plain or JSON response, or a content type the code computes, is not a page.
   */
  private static boolean htmlResponse(RuleContext ctx, Finding f) {
    Node.Group args = SinkCalls.args(f.sink());
    if (args == null) {
      return false;
    }
    Chain.Call call = new Chain.Call(args);
    List<Node> type = Exprs.arg(call, 1, "content_type");
    String literal = type == null ? null : Exprs.string(type);
    Function fn = ctx.module().functionAt(f.sink().token().line());
    return htmlValue(fn, Exprs.arg(call, 0, "content")) && (type == null || literal != null && literal.contains("html"));
  }

  /**
   * {@code request.META["HTTP_X_FORWARDED_PROTO"]}, {@code request.headers.get("X-Theme")}: a custom header, which a
   * link or form sending the victim to the site cannot set.
   */
  private static boolean customHeader(Step source) {
    Token t = source == null ? null : source.token();
    if (t == null || !t.text().equals("META") && !t.text().equals("headers")) {
      return false;
    }
    List<String> lines = source.module().file().lines();
    String line = t.line() <= lines.size() ? lines.get(t.line() - 1) : "";
    return t.endColumn() <= line.length() && CUSTOM_HEADER.matcher(line.substring(t.endColumn())).find();
  }

  private static PyStatement returnAt(Function fn, Token t) {
    for (PyStatement top : fn.body()) {
      for (PyStatement s : top.walk()) {
        if (s.keyword().equals("return") && s.first().equals(t)) {
          return s;
        }
      }
    }
    return null;
  }

  private static boolean returnsHtml(Function fn) {
    for (Decorator d : fn.decorators()) {
      List<Node> rc = d.call() == null ? null : Exprs.kwargs(d.call()).get("response_class");
      String name = rc == null ? null : Exprs.dotted(rc);
      if (name != null && HTML_RESPONSES.contains(fn.module().resolve(name))) {
        return true;
      }
    }
    return false;
  }
}
