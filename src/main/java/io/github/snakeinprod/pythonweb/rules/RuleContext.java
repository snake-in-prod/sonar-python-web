package io.github.snakeinprod.pythonweb.rules;

import io.github.snakeinprod.pythonweb.model.Module;
import io.github.snakeinprod.pythonweb.model.WebModel;
import io.github.snakeinprod.pythonweb.parse.ParsedFile;
import io.github.snakeinprod.pythonweb.parse.Token;
import io.github.snakeinprod.pythonweb.taint.Finding;
import io.github.snakeinprod.pythonweb.taint.Step;
import io.github.snakeinprod.pythonweb.taint.TaintResult;
import java.util.List;

/** What a rule sees: the module it checks, the whole model, the taint findings, and a way to report on the module. */
public interface RuleContext {

  /** The module being checked. */
  Module module();

  /** Every module and endpoint of the project. */
  WebModel model();

  /** The taint findings of the whole project, computed once per analysis. */
  TaintResult taint();

  default ParsedFile file() {
    return module().file();
  }

  /**
   * Reports an issue on the checked module from {@code from} to {@code to} (both included), with secondary locations
   * (in any module of the project; the sensor drops those outside the analysed files).
   */
  void report(Token from, Token to, String message, List<Step> secondaries);

  default void report(Token at, String message) {
    report(at, at, message, List.of());
  }

  /** Reports a finding at its sink, every other step of its path as a secondary location. The sink must be in this module. */
  default void report(Finding f, String message) {
    report(f.sink().token(), f.sink().token(), message, f.path().subList(0, f.path().size() - 1));
  }
}
