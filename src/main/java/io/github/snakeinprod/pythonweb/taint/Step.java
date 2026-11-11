package io.github.snakeinprod.pythonweb.taint;

import io.github.snakeinprod.pythonweb.model.Module;
import io.github.snakeinprod.pythonweb.parse.Token;

/** One location along a taint path, with what happens there: a secondary location of an issue. */
public record Step(Module module, Token token, String message) {

  @Override
  public String toString() {
    return module.path() + ":" + token.line() + " " + message;
  }
}
