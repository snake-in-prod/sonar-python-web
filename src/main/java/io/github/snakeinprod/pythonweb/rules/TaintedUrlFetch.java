package io.github.snakeinprod.pythonweb.rules;

import io.github.snakeinprod.pythonweb.taint.Finding;

/**
 * Request data as the URL of requests, httpx, urllib or aiohttp. A literal start naming the host clears the URL in the
 * engine; silent too when a condition on the way checks the host (netloc, hostname, an allow-list, a "https://host"
 * prefix), a URL check helper runs on the way (validate_url(url)), or only administrators reach the endpoint (they
 * configure the URLs the server calls).
 */
public final class TaintedUrlFetch implements PwRule {

  @Override
  public void check(RuleContext ctx) {
    for (Finding f : TaintChecks.bySink(ctx, "ssrf")) {
      if (!TaintChecks.adminOnly(f) && !TaintChecks.ownUrl(f) && !TaintChecks.validatedOnPath(f) && !TaintChecks.hostHelperOnPath(ctx, f)
        && !TaintChecks.checkedOnPath(f, t -> TaintChecks.ident(t, TaintChecks.HOST_CHECKS) || TaintChecks.literal(t, TaintChecks::origin))) {
        ctx.report(f, "Check the host of the URL taken from " + f.label() + " of " + f.where() + " against an allow-list before "
          + f.sinkName() + "() fetches it.");
      }
    }
  }
}
