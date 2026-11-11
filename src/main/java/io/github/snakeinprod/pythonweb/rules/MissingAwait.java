package io.github.snakeinprod.pythonweb.rules;

import io.github.snakeinprod.pythonweb.lang.python.PyStatement;
import io.github.snakeinprod.pythonweb.model.Endpoint;
import io.github.snakeinprod.pythonweb.model.Exprs;
import io.github.snakeinprod.pythonweb.model.Function;
import io.github.snakeinprod.pythonweb.model.Module;
import io.github.snakeinprod.pythonweb.model.WebModel;
import io.github.snakeinprod.pythonweb.parse.Chain;
import io.github.snakeinprod.pythonweb.parse.Node;
import io.github.snakeinprod.pythonweb.parse.Nodes;
import io.github.snakeinprod.pythonweb.parse.Token;
import io.github.snakeinprod.pythonweb.parse.TokenKind;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * A coroutine created and dropped in an async def: a call on a line of its own, or assigned to a name that is never
 * awaited (later uses only read attributes or items of it). Coroutine calls are project async functions (not
 * decorated, not generators), asyncio.sleep / wait_for / wait, and the async methods of FastAPI's Request, UploadFile
 * and WebSocket parameters.
 */
public class MissingAwait implements PwRule {

  private static final Set<String> LIBRARY = Set.of("asyncio.sleep", "asyncio.wait_for", "asyncio.wait");
  private static final Map<String, Set<String>> METHODS = Map.of(
    "fastapi.Request", Set.of("json", "body", "form"),
    "starlette.requests.Request", Set.of("json", "body", "form"),
    "fastapi.UploadFile", Set.of("read", "write", "seek", "close"),
    "starlette.datastructures.UploadFile", Set.of("read", "write", "seek", "close"),
    "fastapi.WebSocket", Set.of("accept", "close", "send", "send_text", "send_json", "send_bytes", "receive", "receive_text",
      "receive_json", "receive_bytes"),
    "starlette.websockets.WebSocket", Set.of("accept", "close", "send", "send_text", "send_json", "send_bytes", "receive",
      "receive_text", "receive_json", "receive_bytes"));

  @Override
  public void check(RuleContext ctx) {
    WebModel model = ctx.model();
    for (Function fn : ctx.module().functions()) {
      if (!fn.isAsync()) {
        continue;
      }
      List<PyStatement> body = BlockingCallInAsync.statements(fn.body());
      for (int i = 0; i < body.size(); i++) {
        PyStatement s = body.get(i);
        if (!s.body().isEmpty() || s.nodes().isEmpty()) {
          continue;
        }
        Chain c = Exprs.chain(s.nodes());
        Token target = null;
        if (c == null) {
          List<List<Node>> parts = Exprs.assignment(s.nodes());
          List<Node> t = parts.size() == 2 ? Exprs.unannotated(parts.get(0)) : List.of();
          target = t.size() == 1 && Nodes.leaf(t.get(0)) != null && Nodes.leaf(t.get(0)).kind() == TokenKind.IDENT ? Nodes.leaf(t.get(0)) : null;
          c = target == null ? null : Exprs.chain(parts.get(1));
        }
        String name = c == null ? null : coroutine(model, fn, c);
        if (name != null && (target == null || neverAwaited(target, fn, s))) {
          ctx.report(c.first(), c.last(), "Add await before " + name + ": the coroutine never runs in " + where(model, fn) + ".", List.of());
        }
      }
    }
  }

  /** The call as written when the chain is exactly one call that returns a coroutine, else null. */
  private static String coroutine(WebModel model, Function fn, Chain c) {
    Chain.Call call = Exprs.firstCall(c);
    if (call == null || c.segments().size() != Exprs.headSize(c) + 1) {
      return null;
    }
    String head = Exprs.head(c);
    Module m = fn.module();
    String resolved = BlockingCallInAsync.imported(m, head);
    if (resolved != null && LIBRARY.contains(resolved)) {
      return head + "()";
    }
    List<String> names = c.names();
    if (names.size() == 2 && fn.param(names.get(0)) != null && !names.get(0).equals("self")) {
      List<Node> annotation = fn.param(names.get(0)).annotation();
      String dotted = Exprs.dotted(annotation);
      String type = dotted == null ? null : BlockingCallInAsync.imported(m, dotted);
      return type != null && METHODS.getOrDefault(type, Set.of()).contains(names.get(1)) ? head + "()" : null;
    }
    Function callee = BlockingCallInAsync.callee(model, fn, head);
    return callee != null && callee.isAsync() && BlockingCallInAsync.plain(callee) && !generator(callee) ? head + "()" : null;
  }

  /** An async generator: calling it gives an async iterator, not a coroutine. */
  private static boolean generator(Function f) {
    return BlockingCallInAsync.statements(f.body()).stream()
      .anyMatch(s -> Nodes.tokens(s.nodes()).stream().anyMatch(t -> t.isIdent("yield")));
  }

  /** Every later use of the name in the function reads an attribute or item of it ({@code data["x"]}), or there is none. */
  private static boolean neverAwaited(Token target, Function fn, PyStatement assignment) {
    List<Token> tokens = Nodes.tokens(fn.def().body().stream().flatMap(s -> s.walk().stream()).flatMap(s -> s.nodes().stream()).toList());
    Token end = assignment.last();
    for (int i = 0; i < tokens.size(); i++) {
      Token t = tokens.get(i);
      boolean later = t.line() > end.line() || t.line() == end.line() && t.column() > end.column();
      if (later && t.isIdent(target.text()) && (i == 0 || !tokens.get(i - 1).is("."))) {
        Token next = i + 1 < tokens.size() ? tokens.get(i + 1) : null;
        if (next == null || !next.is(".") && !next.is("[") || next.line() != t.line()) {
          return false;
        }
      }
    }
    return true;
  }

  private static String where(WebModel model, Function fn) {
    List<Endpoint> es = model.endpointsOf(fn);
    return es.isEmpty() ? fn.label() + "()" : String.join("|", es.get(0).methods()) + " " + es.get(0).path();
  }
}
