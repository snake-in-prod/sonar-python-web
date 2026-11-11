package io.github.snakeinprod.pythonweb.parse;

/**
 * One token. Lines are 1-based, columns 0-based; {@code endLine}/{@code endColumn} point just past the last character.
 * A string token's {@code text} is its full source text, quotes and prefixes included ({@code f"x{y}"}, {@code `a${b}`}).
 */
public record Token(TokenKind kind, String text, int line, int column, int endLine, int endColumn) {

  public boolean is(String s) {
    return text.equals(s);
  }

  public boolean isIdent(String s) {
    return kind == TokenKind.IDENT && text.equals(s);
  }

  @Override
  public String toString() {
    return kind + "'" + text + "'@" + line + ":" + column;
  }
}
