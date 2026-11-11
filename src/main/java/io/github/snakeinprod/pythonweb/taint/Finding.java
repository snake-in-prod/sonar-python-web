package io.github.snakeinprod.pythonweb.taint;

import io.github.snakeinprod.pythonweb.model.Endpoint;
import io.github.snakeinprod.pythonweb.model.Function;
import java.util.List;

/**
 * Request data reaching a sink.
 *
 * @param kind     the sink kind: sql, command, path, ssrf, redirect, template, deserialization
 * @param sinkName the call as written ("cursor.execute", "subprocess.run")
 * @param label    the input ("request.GET", "parameter q")
 * @param source   where the input is read
 * @param sink     the sink call: report the issue here
 * @param path     every step from the source to the sink, both included: the secondary locations
 * @param function the function reading the input
 * @param endpoint the endpoint the input comes in through: the reading function's, else the first endpoint found among
 *                 its callers; null when none is known
 */
public record Finding(String kind, String sinkName, String label, Step source, Step sink, List<Step> path, Function function,
  Endpoint endpoint) {

  /** "POST /items" or "the function load_items" when no endpoint is known: for messages. */
  public String where() {
    return endpoint != null ? String.join("|", endpoint.methods()) + " " + endpoint.path()
      : function != null ? "the function " + function.label() : "this code";
  }

  @Override
  public String toString() {
    return kind + " " + sink + " <- " + label + " @" + source + (endpoint == null ? "" : " [" + where() + "]") + " path=" + path;
  }
}
