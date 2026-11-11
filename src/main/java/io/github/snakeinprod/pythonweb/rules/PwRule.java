package io.github.snakeinprod.pythonweb.rules;

/**
 * One rule. It is called once per module of the project (test files excepted) and decides itself what it checks
 * there. One instance per analysis: a rule may keep state across modules in its fields.
 */
public interface PwRule {

  void check(RuleContext ctx);
}
