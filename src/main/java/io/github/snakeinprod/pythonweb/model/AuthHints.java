package io.github.snakeinprod.pythonweb.model;

import io.github.snakeinprod.pythonweb.lang.python.PyStatement;
import io.github.snakeinprod.pythonweb.parse.Chain;
import io.github.snakeinprod.pythonweb.parse.Chains;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Names and code that say the caller is checked, shared by the three frameworks. Name based on purpose: a project's
 * own {@code @admin_only} helper counts when its name says so; anything else stays unknown.
 */
final class AuthHints {

  /** Decorator names: login_required, permission_required, jwt_required, auth.login_required, roles_required... */
  static final Pattern DECORATOR = Pattern.compile("(?i)(^|\\.)((\\w+_)?(login|auth|token|jwt|admin|staff|superuser|role|roles|"
    + "permission|permissions|user|key|apikey|api_key|scope|scopes)_required|staff_member_required|user_passes_test|roles_accepted|"
    + "requires?_(auth|authentication|login|user|role|roles|permission|permissions|admin|scope|scopes)|authenticated|"
    + "login_required|verify_token|protected)$");

  /** FastAPI dependency expressions: Depends(get_current_user), Depends(oauth2_scheme), Depends(RoleChecker(["admin"])). */
  static final Pattern DEPENDENCY = Pattern.compile("(?i)(current_?user|current_?session|session_?user|get_?user\\b|active_?user|"
    + "auth|login|token|jwt|permission|"
    + "admin|staff|superuser|api_?key|oauth|bearer|verify|principal|role|credential|scope|logged|require_?(user|login|role))");

  /** Checks in a body: Django request.user tests, PermissionDenied, flask-login current_user, abort(401/403), JWT checks. */
  static final Pattern BODY = Pattern.compile("request\\.user\\.(is_authenticated|is_anonymous|is_staff|is_superuser|has_perms?)|"
    + "PermissionDenied|HttpResponseForbidden|redirect_to_login|current_user\\.is_(authenticated|anonymous|admin)|"
    + "verify_jwt_in_request|get_jwt_identity|abort\\((401|403)|HTTPException\\(status_code=(401|403)|"
    + "status\\.HTTP_40[13]_|NotAuthenticated|AuthenticationFailed");

  /** A module that holds auth code: auth.py, authn.py, authentication/, security.py, permissions.py. */
  static final Pattern AUTH_MODULE = Pattern.compile("(?i)(^|/)[^/]*(auth|security|permission)[^/]*(/|\\.py$)");

  /** A dependency parameter reading a credential: Cookie(...) or Header(...) named for a session, token or key. */
  static final Pattern CREDENTIAL_PARAM = Pattern.compile("(?i)(session|token|authorization|api_?key|jwt|bearer|credential)");

  /** Mixin bases: LoginRequiredMixin, PermissionRequiredMixin, UserPassesTestMixin, StaffRequiredMixin... */
  static final Pattern MIXIN = Pattern.compile("(Login|Permission|UserPassesTest|Staff|Superuser|Auth|Access|Admin|Group)\\w*Mixin$");

  /** Packages whose import means the app has authentication. */
  private static final List<String> PACKAGES = List.of("django.contrib.auth", "rest_framework.permissions",
    "rest_framework.authentication", "rest_framework_simplejwt", "knox", "allauth", "flask_login", "flask_jwt_extended",
    "flask_httpauth", "flask_security", "flask_praetorian", "fastapi.security", "fastapi_users", "fastapi_jwt_auth", "jose",
    "jwt", "authlib", "oauthlib");

  private static final Set<String> WRITES = Set.of("save", "delete", "create", "bulk_create", "bulk_update", "update_or_create",
    "get_or_create", "commit", "flush", "delete_many", "insert_one", "insert_many", "update_one", "update_many", "delete_one");

  private AuthHints() {
  }

  static boolean authPackage(String dotted) {
    return PACKAGES.stream().anyMatch(p -> dotted.equals(p) || dotted.startsWith(p + "."));
  }

  /** The text of a function's body, see {@link Exprs#text}. */
  static String bodyText(Function f) {
    StringBuilder sb = new StringBuilder();
    for (PyStatement s : f.body()) {
      for (PyStatement x : s.walk()) {
        sb.append(Exprs.text(x.nodes())).append('\n');
      }
    }
    return sb.toString();
  }

  /** The body calls an ORM or database write: save(), delete(), objects.create(), filter(...).update(), commit(). */
  static boolean writes(Function f) {
    if (f == null) {
      return false;
    }
    for (PyStatement s : f.body()) {
      for (PyStatement x : s.walk()) {
        for (Chain c : Chains.in(x.group())) {
          List<String> names = c.names();
          if (names.size() < 2 || !c.endsWithCall()) {
            continue;
          }
          String last = c.lastName();
          if (WRITES.contains(last) || last.equals("update") && (names.contains("objects") || c.calls().size() > 1)) {
            return true;
          }
        }
      }
    }
    return false;
  }
}
