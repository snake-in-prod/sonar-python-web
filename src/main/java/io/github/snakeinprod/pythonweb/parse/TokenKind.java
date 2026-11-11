package io.github.snakeinprod.pythonweb.parse;

/**
 * Token kinds shared by all languages. Keywords are {@link #IDENT}: rules compare the text. Brackets and every other
 * punctuation or operator ({@code .}, {@code ?.}, {@code =>}, {@code ==}, {@code @}) are {@link #OP}. {@link #NEWLINE},
 * {@link #INDENT} and {@link #DEDENT} are Python only (logical line ends and block changes, never inside brackets).
 * JSX text and other text a rule never reads is {@link #OTHER}.
 */
public enum TokenKind {
  IDENT, NUMBER, STRING, OP, NEWLINE, INDENT, DEDENT, OTHER
}
