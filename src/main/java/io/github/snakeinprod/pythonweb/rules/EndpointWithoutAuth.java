package io.github.snakeinprod.pythonweb.rules;

import io.github.snakeinprod.pythonweb.lang.python.PyStatement;
import io.github.snakeinprod.pythonweb.model.Decorator;
import io.github.snakeinprod.pythonweb.model.Endpoint;
import io.github.snakeinprod.pythonweb.model.Exprs;
import io.github.snakeinprod.pythonweb.model.Framework;
import io.github.snakeinprod.pythonweb.model.Function;
import io.github.snakeinprod.pythonweb.model.Imports;
import io.github.snakeinprod.pythonweb.model.Module;
import io.github.snakeinprod.pythonweb.model.PyClass;
import io.github.snakeinprod.pythonweb.model.WebModel;
import io.github.snakeinprod.pythonweb.parse.Chain;
import io.github.snakeinprod.pythonweb.parse.Chains;
import io.github.snakeinprod.pythonweb.parse.Node;
import io.github.snakeinprod.pythonweb.parse.Token;
import io.github.snakeinprod.pythonweb.taint.Step;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * A mutating endpoint (PUT, PATCH, DELETE; POST or a Django view open to any method when it writes) with no check of
 * the caller, in an app where other endpoints do check it (for Flask, FastAPI and aiohttp, the app is the set of modules imports
 * connect, so the separate apps of one repository are judged apart). Silent when the endpoint is explicitly open
 * (AllowAny), looks public by its name (login, signup, webhook...), counts visits (POST .../view), says it is open in a
 * comment just above it, checks something in its body or a helper, takes a dependency that names a user, or when the
 * app authenticates in a way the model cannot follow (auth middleware, unparsed DRF defaults, include_router
 * dependencies that were not resolved).
 */
public class EndpointWithoutAuth implements PwRule {

  /** Endpoints that are public on purpose, by a word of their path or name ("lessons" is not "sso"). */
  static final Pattern PUBLIC = Pattern.compile("(?i)(?<![a-z])(log_?in|log_?out|sign_?(in|up|out)|register|token|refresh|password|passwd|"
    + "reset|forgot|verif|confirm|activat|webhook|hook|callback|oauth|auth(?!or)|sso|saml|health|ping|contact|subscribe|feedback|"
    + "newsletter|csp|telemetry|beacon|graphql|public|cart|basket|invit|captcha|otp|magic|anonymous|guest)");

  /** A call or function name that changes data: create_item, crud.update_user, db.add, repo.delete. */
  static final Pattern WRITE = Pattern.compile("(?i)^(create|add|insert|update|delete|remove|save|commit|upsert|destroy|write|"
    + "store|upload|edit|modify|bulk|import|archive|publish|approve|reject|assign|transfer|rename|purge)(_|$)|"
    + "_(create|add|insert|update|delete|remove|save|upsert|destroy|write|store|upload|edit|modify)(_|$)");

  /** Code that checks the caller or reads a credential. */
  static final Pattern CHECK = Pattern.compile("(?i)current_user|authenticat|authoriz|permission|is_staff|is_superuser|is_admin|"
    + "request\\.user|state\\.user|g\\.user|session\\[|session\\.get\\(|jwt|api_?key|bearer|signature|hmac|status_code=40[13]|"
    + "HTTP_40[13]|abort\\(40[13]|PermissionDenied|Forbidden|Unauthorized|verify_\\w+|check_\\w*(user|auth|perm|access|owner)");

  /** A dependency parameter that stands for the caller. */
  private static final Pattern CALLER = Pattern.compile("(?i)user|account|principal|token|session|identity|auth|admin|member|"
    + "owner|caller|key|claims|subject");

  /** Auth-like text in a dependency, middleware or settings entry. */
  private static final Pattern AUTHISH = Pattern.compile("(?i)user|auth|login|token|jwt|permission|admin|key|oauth|bearer|verify|"
    + "role|scope|security|credential");

  private static final Pattern BY_IP = Pattern.compile("(?i)rate_?limit\\w*_by_ip|ratelimit\\w*\\(.*key=[\"']ip[\"']");

  private static final Set<String> MUTATING = Set.of("PUT", "PATCH", "DELETE");
  /** A path that counts what anonymous visitors do: POST /api/video/view, /items/{id}/hits. */
  private static final Pattern COUNTER = Pattern.compile("(?i)/(views?|view_?count|impressions?|hits?|plays?)/?$");
  private static final Pattern OPEN_COMMENT = Pattern.compile("(?i)\\b(public|ungated|unauthenticated|anonymous|no (app )?login|"
    + "without (a |app )?login|no auth|without auth|open to)");
  private static final Set<String> WRITE_ACTIONS = Set.of("create", "update", "partial_update", "destroy");
  private static final Pattern WRITE_BASE = Pattern.compile("(Create|Update|Delete|Destroy)\\w*|ModelViewSet");

  private Map<Framework, Boolean> opaque;
  private Map<Module, Module> apps;
  /** DEFAULT_PERMISSION_CLASSES appears somewhere: a DRF endpoint without evidence means the model could not read them. */
  private boolean drfSettings;

  @Override
  public void check(RuleContext ctx) {
    WebModel model = ctx.model();
    List<Endpoint> protectedOnes = model.endpoints().stream().filter(e -> e.auth().present()).toList();
    if (protectedOnes.isEmpty()) {
      return;
    }
    if (opaque == null) {
      opaque = opaque(model);
      apps = apps(model);
      drfSettings = model.modules().stream().anyMatch(m -> !m.isTest() && m.py().walk().stream()
        .anyMatch(s -> Exprs.text(s.nodes()).contains("DEFAULT_PERMISSION_CLASSES")));
    }
    Map<Token, List<Endpoint>> byToken = new LinkedHashMap<>();
    for (Endpoint e : model.endpoints()) {
      if (e.module() == ctx.module() && sameAppChecks(e, protectedOnes) && unprotected(model, e)) {
        byToken.computeIfAbsent(e.token(), k -> new ArrayList<>()).add(e);
      }
    }
    for (Map.Entry<Token, List<Endpoint>> g : byToken.entrySet()) {
      Endpoint e = g.getValue().get(0);
      int more = g.getValue().size() - 1;
      String where = String.join("|", e.methods()) + " " + e.path();
      String message = where + (more > 0 ? " and " + more + " more endpoint" + (more > 1 ? "s" : "") + " of " + (e.viewClass() != null ? e.viewClass().name() : e.label()) : "")
        + " " + (more > 0 ? "have" : "has") + " no authentication: add " + hint(e.framework()) + ", as other endpoints of this app do.";
      Endpoint ref = protectedOnes.stream().filter(p -> p.module() == e.module()).findFirst()
        .orElse(protectedOnes.stream().filter(p -> p.framework() == e.framework()).findFirst().orElse(null));
      List<Step> secondaries = ref == null ? List.of()
        : List.of(new Step(ref.module(), ref.token(), "this endpoint checks the caller: " + ref.auth().evidence()));
      ctx.report(e.token(), e.token(), message, secondaries);
    }
  }

  /**
   * Some endpoint of the same app checks its caller. A Flask, FastAPI or aiohttp app is the set of modules its imports connect,
   * so independent apps in one repository (lab apps, microservices) are judged apart; Django apps are tied by
   * include() strings, so a Django project counts as one app.
   */
  private boolean sameAppChecks(Endpoint e, List<Endpoint> protectedOnes) {
    if (e.framework() != Framework.FLASK && e.framework() != Framework.FASTAPI && e.framework() != Framework.AIOHTTP) {
      return true;
    }
    Module app = root(apps, e.module());
    return protectedOnes.stream().anyMatch(p -> root(apps, p.module()) == app);
  }

  /** Union of modules over project imports: each module points towards its app's representative. */
  private static Map<Module, Module> apps(WebModel model) {
    Map<Module, Module> parent = new HashMap<>();
    for (Module m : model.modules()) {
      for (String dotted : m.py().imports().values()) {
        Imports.Target t = Imports.split(dotted, m.path(), model.paths());
        Module other = t == null ? null : model.module(t.path());
        if (other != null) {
          Module a = root(parent, m);
          Module b = root(parent, other);
          if (a != b) {
            parent.put(a, b);
          }
        }
      }
    }
    return parent;
  }

  private static Module root(Map<Module, Module> parent, Module m) {
    while (parent.containsKey(m)) {
      m = parent.get(m);
    }
    return m;
  }

  private boolean unprotected(WebModel model, Endpoint e) {
    Endpoint.Auth auth = e.auth();
    boolean drfDefault = auth.evidence() != null && auth.evidence().startsWith("DEFAULT_PERMISSION_CLASSES");
    if (auth.present() || auth.evidence() != null && !drfDefault || opaque.getOrDefault(e.framework(), false)) {
      return false;
    }
    if (e.framework() == Framework.DRF && auth.evidence() == null && drfSettings) {
      return false;
    }
    boolean strong = e.methods().stream().anyMatch(MUTATING::contains);
    if (!strong && !(e.mutating() && changesData(model, e))) {
      return false;
    }
    if (PUBLIC.matcher(e.path()).find() || PUBLIC.matcher(e.label()).find() || COUNTER.matcher(e.path()).find() || openOnPurpose(e)) {
      return false;
    }
    if (e.function() != null && (PUBLIC.matcher(docstring(e.function())).find() || anonymousByDesign(e.function()))) {
      return false;
    }
    List<Function> code = new ArrayList<>();
    if (e.function() != null) {
      code.add(e.function());
    }
    if (e.viewClass() != null) {
      model.hierarchy(e.viewClass()).forEach(k -> code.addAll(k.methods()));
    }
    for (Function f : code) {
      if (CHECK.matcher(bodyText(f)).find() || callsChecker(model, f)) {
        return false;
      }
    }
    if (e.function() != null) {
      for (Function.Param p : e.function().params()) {
        String spec = Exprs.text(p.defaultValue()) + " " + p.annotationText();
        if (CALLER.matcher(p.name()).find() && spec.matches("(?s).*\\b(Depends|Security|Header|Cookie)\\(.*")) {
          return false;
        }
      }
    }
    return true;
  }

  /** A comment just above the handler says it is open: "# Deliberately ungated: shared with an external vendor". */
  private static boolean openOnPurpose(Endpoint e) {
    Function f = e.function();
    if (f == null) {
      return false;
    }
    int top = f.decorators().stream().mapToInt(d -> d.statement().first().line()).min().orElse(f.firstLine());
    return e.module().file().comments().stream()
      .anyMatch(c -> c.line() >= top - 3 && c.line() <= f.firstLine() && OPEN_COMMENT.matcher(c.text()).find());
  }

  /** A helper the handler calls checks the caller: {@code ensure_owner(request, item)}. */
  private static boolean callsChecker(WebModel model, Function f) {
    for (PyStatement s : f.body()) {
      for (PyStatement x : s.walk()) {
        for (Chain c : Chains.in(x.group())) {
          Function callee = Exprs.firstCall(c) == null ? null : model.function(f.module(), Exprs.head(c));
          if (callee != null && callee != f && CHECK.matcher(bodyText(callee)).find()) {
            return true;
          }
        }
      }
    }
    return false;
  }

  /** Frameworks whose authentication happens where the model does not look. */
  private static Map<Framework, Boolean> opaque(WebModel model) {
    Map<Framework, Boolean> out = new LinkedHashMap<>();
    boolean includeAuthFollowed = model.endpoints().stream()
      .anyMatch(e -> e.auth().evidence() != null && e.auth().evidence().endsWith(" on include_router"));
    for (Module m : model.modules()) {
      if (m.isTest()) {
        continue;
      }
      for (PyStatement s : m.py().walk()) {
        for (Chain c : Chains.in(s.group())) {
          Chain.Call call = Exprs.firstCall(c);
          String last = c.lastName();
          if (call != null && last.equals("add_middleware") && AUTHISH.matcher(Exprs.text(call.args().children())).find()) {
            out.put(Framework.FASTAPI, true);
          }
          List<Node> deps = call != null && last.equals("include_router") ? Exprs.kwargs(call).get("dependencies") : null;
          if (deps != null && !includeAuthFollowed && AUTHISH.matcher(Exprs.text(deps)).find()) {
            out.put(Framework.FASTAPI, true);
          }
        }
      }
      for (Function f : m.functions()) {
        for (Decorator d : f.decorators()) {
          if (d.last().equals("middleware") && CHECK.matcher(bodyText(f)).find()) {
            out.put(Framework.FASTAPI, true);
          }
        }
      }
      List<Node> middleware = m.assignment("MIDDLEWARE");
      if (middleware != null) {
        for (String entry : Exprs.strings(middleware)) {
          if (!entry.startsWith("django.") && AUTHISH.matcher(entry).find()) {
            out.put(Framework.DJANGO, true);
            out.put(Framework.DRF, true);
          }
        }
      }
    }
    return out;
  }

  /** The endpoint changes data: an ORM write, a handler or call named for a write, or a generic write view. */
  static boolean changesData(WebModel model, Endpoint e) {
    Function f = e.function();
    if (f == null) {
      String action = e.label().contains(".") ? e.label().substring(e.label().lastIndexOf('.') + 1) : "";
      if (WRITE_ACTIONS.contains(action)) {
        return true;
      }
      PyClass cls = e.viewClass();
      return cls != null && model.externalBases(cls).stream().anyMatch(b -> WRITE_BASE.matcher(b.substring(b.lastIndexOf('.') + 1)).matches());
    }
    if (e.writes() || WRITE.matcher(f.name()).find()) {
      return true;
    }
    for (PyStatement s : f.body()) {
      for (PyStatement x : s.walk()) {
        for (Chain c : Chains.in(x.group())) {
          if (c.endsWithCall() && (c.names().size() > 1 || c.lastName().contains("_")) && WRITE.matcher(c.lastName()).find()) {
            return true;
          }
        }
      }
    }
    return false;
  }

  /** The docstring of a function ("Handle delivery status callbacks."), or "". */
  private static String docstring(Function f) {
    List<Node> first = f.body().isEmpty() ? List.of() : f.body().get(0).nodes();
    Token t = first.size() == 1 ? io.github.snakeinprod.pythonweb.parse.Nodes.leaf(first.get(0)) : null;
    return t != null && t.kind() == io.github.snakeinprod.pythonweb.parse.TokenKind.STRING ? t.text() : "";
  }

  /** Rate limited by client IP (rate_limit_request_by_ip, @ratelimit(key="ip")): the endpoint expects anonymous callers. */
  private static boolean anonymousByDesign(Function f) {
    StringBuilder sb = new StringBuilder(bodyText(f));
    f.decorators().forEach(d -> sb.append(Exprs.text(d.statement().nodes())).append('\n'));
    return BY_IP.matcher(sb).find();
  }

  static String bodyText(Function f) {
    StringBuilder sb = new StringBuilder();
    for (PyStatement s : f.body()) {
      for (PyStatement x : s.walk()) {
        sb.append(Exprs.text(x.nodes())).append('\n');
      }
    }
    return sb.toString();
  }

  private static String hint(Framework f) {
    return switch (f) {
      case FASTAPI -> "an auth dependency (Depends(get_current_user)) on the route or its router";
      case DRF -> "permission_classes";
      case DJANGO -> "@login_required or an auth mixin";
      case FLASK -> "@login_required or a before_request guard";
      case AIOHTTP -> "await check_authorized(request) or an auth middleware";
    };
  }
}
