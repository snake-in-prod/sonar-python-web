package io.github.snakeinprod.pythonweb.parse;

import java.util.List;

/** What a lexer returns: code tokens and, separately, comment tokens (kind {@link TokenKind#OTHER}, text with markers). */
public record Lexed(List<Token> tokens, List<Token> comments) {
}
