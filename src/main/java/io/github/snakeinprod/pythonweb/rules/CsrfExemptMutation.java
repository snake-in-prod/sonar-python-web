package io.github.snakeinprod.pythonweb.rules;

import io.github.snakeinprod.pythonweb.lang.python.PyStatement;
import io.github.snakeinprod.pythonweb.model.Decorator;
import io.github.snakeinprod.pythonweb.model.Endpoint;
import io.github.snakeinprod.pythonweb.model.Exprs;
import io.github.snakeinprod.pythonweb.model.Framework;
import io.github.snakeinprod.pythonweb.model.Function;
import io.github.snakeinprod.pythonweb.model.Module;
import io.github.snakeinprod.pythonweb.model.PyClass;
import io.github.snakeinprod.pythonweb.model.WebModel;
import io.github.snakeinprod.pythonweb.parse.Chain;
import io.github.snakeinprod.pythonweb.parse.Chains;
import io.github.snakeinprod.pythonweb.parse.Node;
import io.github.snakeinprod.pythonweb.parse.Token;
import io.github.snakeinprod.pythonweb.taint.Step;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * A CSRF-exempt view that changes data for a user authenticated by a session cookie: Django {@code @csrf_exempt}
 * (on the function, through {@code method_decorator} on the class or its dispatch, or as a wrapper in urls.py) and
 * Flask-WTF {@code @csrf.exempt}. The view must accept an unsafe method, write, and either check the user by the
 * session (login_required, an auth mixin, request.user / current_user) or act on request.user. DRF views (which apply
 * CSRF themselves for session auth) and views authenticated by a token, a key or a signature are left alone.
 */
public class CsrfExemptMutation implements PwRule {

  /** A credential that is not the session cookie. */
  private static final Pattern TOKEN = Pattern.compile("(?i)authoriz|api_?key|bearer|signature|hmac|token|jwt|basic_auth|secret");

  /** The view acts as the session user. */
  private static final Pattern SESSION_USER = Pattern.compile("request\\.user|current_user");

  private static final Set<String> UNSAFE = Set.of("POST", "PUT", "PATCH", "DELETE", "ANY");

  private Map<Object, Step> wrapped;

  @Override
  public void check(RuleContext ctx) {
    WebModel model = ctx.model();
    if (wrapped == null) {
      wrapped = wrappers(model);
    }
    Set<Token> seen = new HashSet<>();
    for (Endpoint e : model.endpoints()) {
      if (e.module() != ctx.module() || e.framework() != Framework.DJANGO && e.framework() != Framework.FLASK
        || e.methods().stream().noneMatch(UNSAFE::contains) || !EndpointWithoutAuth.changesData(model, e)) {
        continue;
      }
      Step exempt = exemption(model, e);
      if (exempt == null || e.viewClass() != null && ownApiFramework(model, e.viewClass())) {
        continue;
      }
      List<Function> code = new ArrayList<>();
      if (e.function() != null) {
        code.add(e.function());
      }
      if (e.viewClass() != null) {
        model.hierarchy(e.viewClass()).forEach(k -> code.addAll(k.methods()));
      }
      String text = String.join("\n", code.stream().map(EndpointWithoutAuth::bodyText).toList());
      String evidence = e.auth().present() ? e.auth().evidence() : null;
      if (TOKEN.matcher(text).find() || evidence != null && TOKEN.matcher(evidence).find()) {
        continue;
      }
      String why = evidence != null ? evidence : SESSION_USER.matcher(text).find() ? "uses the session user" : null;
      if (why != null && seen.add(e.token())) {
        ctx.report(e.token(), e.token(), "Remove the CSRF exemption of " + String.join("|", e.methods()) + " " + e.path()
          + ": it changes data for a user signed in by session cookie (" + why + "), so any site can trigger it.", List.of(exempt));
      }
    }
  }

  /**
   * A project copy of a DRF-style API view (its own authentication_classes or perform_authentication): like DRF, it
   * exempts dispatch and leaves CSRF to its authentication classes.
   */
  private static boolean ownApiFramework(WebModel model, PyClass cls) {
    return model.hierarchy(cls).stream().anyMatch(k -> k.attributes().containsKey("authentication_classes")
      || k.method("perform_authentication") != null || k.method("get_authenticators") != null);
  }

  /** Where CSRF protection is turned off for this endpoint, or null. */
  private Step exemption(WebModel model, Endpoint e) {
    List<Function> functions = new ArrayList<>();
    if (e.function() != null) {
      functions.add(e.function());
      Step w = wrapped.get(e.function());
      if (w != null) {
        return w;
      }
    }
    if (e.viewClass() != null) {
      for (PyClass k : model.hierarchy(e.viewClass())) {
        Step w = wrapped.get(k);
        if (w != null) {
          return w;
        }
        for (Decorator d : k.decorators()) {
          if (exempts(d)) {
            return step(k.module(), d);
          }
        }
      }
      Function dispatch = model.method(e.viewClass(), "dispatch");
      if (dispatch != null) {
        functions.add(dispatch);
      }
    }
    for (Function f : functions) {
      for (Decorator d : f.decorators()) {
        if (exempts(d)) {
          return step(f.module(), d);
        }
      }
    }
    return null;
  }

  /** {@code @csrf_exempt}, {@code @method_decorator(csrf_exempt, ...)}, {@code @csrf.exempt}. */
  private static boolean exempts(Decorator d) {
    if (d.last().equals("csrf_exempt") || d.last().equals("exempt") && d.receiver().toLowerCase(java.util.Locale.ROOT).contains("csrf")) {
      return true;
    }
    if (d.last().equals("method_decorator") && d.call() != null) {
      List<Node> arg = Exprs.arg(d.call(), 0, "decorator");
      return arg != null && Exprs.text(arg).matches("(?s).*\\bcsrf_exempt\\b.*");
    }
    return false;
  }

  private static Step step(Module m, Decorator d) {
    return new Step(m, d.statement().nodes().get(1).first(), "CSRF protection turned off here");
  }

  /** {@code csrf_exempt(views.f)} and {@code csrf_exempt(View.as_view())} anywhere: the function or class to the call. */
  private static Map<Object, Step> wrappers(WebModel model) {
    Map<Object, Step> out = new IdentityHashMap<>();
    for (Module m : model.modules()) {
      if (m.isTest()) {
        continue;
      }
      for (PyStatement s : m.py().walk()) {
        for (Chain c : Chains.in(s.group())) {
          Chain.Call call = Exprs.firstCall(c);
          if (call == null || !Exprs.head(c).endsWith("csrf_exempt")) {
            continue;
          }
          List<Node> arg = Exprs.arg(call, 0, null);
          Chain inner = arg == null ? null : Exprs.chain(arg);
          // csrf_exempt(login_required(views.f)): the innermost view
          for (int depth = 0; inner != null && depth < 4 && !Exprs.head(inner).endsWith(".as_view") && Exprs.firstCall(inner) != null
            && Exprs.headSize(inner) + 1 == inner.segments().size(); depth++) {
            List<Node> a = Exprs.arg(Exprs.firstCall(inner), 0, null);
            inner = a == null ? null : Exprs.chain(a);
          }
          if (inner == null) {
            continue;
          }
          String head = Exprs.head(inner);
          Step step = new Step(m, c.first(), "CSRF protection turned off here");
          if (head.endsWith(".as_view")) {
            PyClass cls = model.cls(m, head.substring(0, head.length() - ".as_view".length()));
            if (cls != null) {
              out.putIfAbsent(cls, step);
            }
          } else if (Exprs.headSize(inner) == inner.segments().size()) {
            Function f = model.function(m, head);
            if (f != null) {
              out.putIfAbsent(f, step);
            }
          }
        }
      }
    }
    return out;
  }
}
