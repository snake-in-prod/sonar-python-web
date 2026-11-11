package io.github.snakeinprod.pythonweb.rules;

import io.github.snakeinprod.pythonweb.taint.Finding;

/**
 * Request data as the target of redirect(), HttpResponseRedirect or RedirectResponse. Silent for headers and cookies
 * (a Referer sends users back where they came from), for the request's own path, when a condition on the way checks
 * the host or excludes "//", and when a URL check helper (validate_url, or a project function reading the host) runs.
 */
public final class OpenRedirect implements PwRule {

  @Override
  public void check(RuleContext ctx) {
    for (Finding f : TaintChecks.bySink(ctx, "redirect")) {
      if (!TaintChecks.fromHeaderOrCookie(f) && !TaintChecks.ownUrl(f) && !TaintChecks.validatedOnPath(f)
        && !TaintChecks.hostHelperOnPath(ctx, f)
        && !TaintChecks.checkedOnPath(f, t -> TaintChecks.ident(t, TaintChecks.HOST_CHECKS)
          || TaintChecks.literal(t, s -> s.startsWith("//") || s.contains("\\") || TaintChecks.origin(s)))) {
        ctx.report(f, "Check the redirect target taken from " + f.label() + " of " + f.where()
          + " with url_has_allowed_host_and_scheme or an allow-list.");
      }
    }
  }
}
