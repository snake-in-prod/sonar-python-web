package io.github.snakeinprod.pythonweb.lang.python;

import io.github.snakeinprod.pythonweb.parse.Lexed;
import io.github.snakeinprod.pythonweb.parse.Token;
import io.github.snakeinprod.pythonweb.parse.TokenKind;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Python 3.12 lexer. Strings (every prefix, triple quotes, f-strings with nested quotes and braces) are one STRING token
 * each. NEWLINE ends each logical line, INDENT / DEDENT mark block changes; none of them inside brackets or after a
 * backslash continuation, none for blank or comment-only lines. Unknown characters become OTHER. Never throws.
 */
public final class PythonLexer {

  private static final String[] OPS3 = {"**=", "//=", ">>=", "<<=", "..."};
  private static final String[] OPS2 = {"**", "//", "<<", ">>", "<=", ">=", "==", "!=", "->", ":=", "+=", "-=", "*=", "/=",
    "%=", "&=", "|=", "^=", "@="};
  private static final String OPS1 = "+-*/%@&|^~<>()[]{},:;.=!";
  private static final Set<String> PREFIXES = Set.of("r", "u", "b", "f", "t", "br", "rb", "fr", "rf", "tr", "rt");
  /** Deeper f-string nesting is scanned as plain text, so hostile input cannot overflow the stack. */
  private static final int MAX_NESTING = 32;

  private final String src;
  private final int n;
  private final List<Token> tokens = new ArrayList<>();
  private final List<Token> comments = new ArrayList<>();
  private int pos;
  private int line = 1;
  private int lineStart;
  private boolean lineHasTokens;

  private PythonLexer(String src) {
    this.src = src;
    this.n = src.length();
  }

  public static Lexed lex(String source) {
    PythonLexer l = new PythonLexer(source);
    l.run();
    return new Lexed(List.copyOf(l.tokens), List.copyOf(l.comments));
  }

  private void run() {
    int[] indents = new int[16];
    int top = 0;
    int depth = 0;
    boolean atLineStart = true;
    if (src.startsWith("\uFEFF")) {
      pos = 1;
      lineStart = 1;
    }
    while (pos < n) {
      char c = src.charAt(pos);
      if (atLineStart) {
        atLineStart = false;
        int width = 0;
        while (pos < n) {
          char w = src.charAt(pos);
          if (w == ' ') {
            width++;
          } else if (w == '\t') {
            width = (width / 8 + 1) * 8;
          } else if (w == '\f') {
            width = 0;
          } else {
            break;
          }
          pos++;
        }
        if (pos >= n || isNl(src.charAt(pos)) || src.charAt(pos) == '#') {
          continue;
        }
        while (width < indents[top]) {
          top--;
          layout(TokenKind.DEDENT, "");
        }
        // after a dedent to an unknown level (an IndentationError) this opens a new block, keeping the tokens balanced
        if (width > indents[top]) {
          if (++top == indents.length) {
            indents = java.util.Arrays.copyOf(indents, top * 2);
          }
          indents[top] = width;
          layout(TokenKind.INDENT, "");
        }
        continue;
      }
      if (isNl(c)) {
        if (depth == 0 && lineHasTokens) {
          layout(TokenKind.NEWLINE, "\n");
          lineHasTokens = false;
        }
        skipNewline();
        atLineStart = depth == 0;
      } else if (c == ' ' || c == '\t' || c == '\f') {
        pos++;
      } else if (c == '#') {
        int s = pos;
        while (pos < n && !isNl(src.charAt(pos))) {
          pos++;
        }
        comments.add(make(TokenKind.OTHER, s, pos));
      } else if (c == '\\' && pos + 1 < n && isNl(src.charAt(pos + 1))) {
        pos++;
        skipNewline();
      } else if (c == '\'' || c == '"') {
        emit(TokenKind.STRING, pos, scanString(pos, 0));
      } else if (isIdentStart(c)) {
        int e = identEnd(pos);
        boolean str = isStringStart(pos, e);
        emit(str ? TokenKind.STRING : TokenKind.IDENT, pos, str ? scanString(pos, 0) : e);
      } else if (Character.isDigit(c) || c == '.' && pos + 1 < n && Character.isDigit(src.charAt(pos + 1))) {
        emit(TokenKind.NUMBER, pos, numberEnd(pos));
      } else {
        int len = opLength();
        if (len > 0) {
          char o = src.charAt(pos);
          if (len == 1 && (o == '(' || o == '[' || o == '{')) {
            depth++;
          } else if (len == 1 && (o == ')' || o == ']' || o == '}') && depth > 0) {
            depth--;
          }
          emit(TokenKind.OP, pos, pos + len);
        } else {
          emit(TokenKind.OTHER, pos, pos + Character.charCount(src.codePointAt(pos)));
        }
      }
    }
    if (lineHasTokens) {
      layout(TokenKind.NEWLINE, "");
    }
    for (; top > 0; top--) {
      layout(TokenKind.DEDENT, "");
    }
  }

  private int opLength() {
    for (String op : OPS3) {
      if (src.startsWith(op, pos)) {
        return 3;
      }
    }
    for (String op : OPS2) {
      if (src.startsWith(op, pos)) {
        return 2;
      }
    }
    return OPS1.indexOf(src.charAt(pos)) >= 0 ? 1 : 0;
  }

  private int numberEnd(int p) {
    boolean radix = src.charAt(p) == '0' && p + 1 < n && "xXoObB".indexOf(src.charAt(p + 1)) >= 0;
    p++;
    while (p < n) {
      char d = src.charAt(p);
      if (Character.isLetterOrDigit(d) || d == '_' || d == '.' && !radix) {
        p++;
      } else if ((d == '+' || d == '-') && !radix && (src.charAt(p - 1) == 'e' || src.charAt(p - 1) == 'E')) {
        p++;
      } else {
        break;
      }
    }
    return p;
  }

  private int identEnd(int p) {
    while (p < n && isIdentPart(src.charAt(p))) {
      p++;
    }
    return p;
  }

  private boolean isStringStart(int s, int e) {
    return e < n && (src.charAt(e) == '\'' || src.charAt(e) == '"') && e - s <= 2
      && PREFIXES.contains(src.substring(s, e).toLowerCase(Locale.ROOT));
  }

  /** Scans a string literal starting at its prefix (or quote); returns the index just past it. */
  private int scanString(int p, int nest) {
    int s = p;
    while (p < n && src.charAt(p) != '\'' && src.charAt(p) != '"') {
      p++;
    }
    String prefix = src.substring(s, p).toLowerCase(Locale.ROOT);
    boolean raw = prefix.indexOf('r') >= 0;
    boolean f = (prefix.indexOf('f') >= 0 || prefix.indexOf('t') >= 0) && nest < MAX_NESTING;
    char q = src.charAt(p);
    boolean triple = p + 2 < n && src.charAt(p + 1) == q && src.charAt(p + 2) == q;
    p += triple ? 3 : 1;
    while (p < n) {
      char c = src.charAt(p);
      if (c == '\\') {
        p = skipEscape(p);
      } else if (c == q) {
        if (!triple) {
          return p + 1;
        }
        if (p + 2 < n && src.charAt(p + 1) == q && src.charAt(p + 2) == q) {
          return p + 3;
        }
        p++;
      } else if (!triple && isNl(c)) {
        return p; // unterminated: stop at the line end
      } else if (f && c == '{') {
        p = p + 1 < n && src.charAt(p + 1) == '{' ? p + 2 : scanField(p + 1, q, triple, raw, nest);
      } else {
        p++;
      }
    }
    return n;
  }

  /** Scans the expression of an f-string replacement field (after "{"); returns the index just past its "}". */
  private int scanField(int p, char q, boolean triple, boolean raw, int nest) {
    int depth = 0;
    while (p < n) {
      char c = src.charAt(p);
      if (c == '\'' || c == '"') {
        p = scanString(p, nest + 1);
      } else if (isIdentStart(c)) {
        int e = identEnd(p);
        p = isStringStart(p, e) ? scanString(p, nest + 1) : e;
      } else if (c == '#') {
        while (p < n && !isNl(src.charAt(p))) {
          p++;
        }
      } else if (c == '(' || c == '[' || c == '{') {
        depth++;
        p++;
      } else if (c == ')' || c == ']') {
        depth = Math.max(0, depth - 1);
        p++;
      } else if (c == '}') {
        if (depth == 0) {
          return p + 1;
        }
        depth--;
        p++;
      } else if (c == ':' && depth == 0) {
        return scanSpec(p + 1, q, triple, raw, nest);
      } else {
        p++;
      }
    }
    return n;
  }

  /** Scans a format spec (after ":" in a field); returns the index just past the field's "}". */
  private int scanSpec(int p, char q, boolean triple, boolean raw, int nest) {
    while (p < n) {
      char c = src.charAt(p);
      if (c == '}') {
        return p + 1;
      } else if (c == q || !triple && isNl(c)) {
        return p; // broken field: let the string end here
      } else if (c == '{' && nest < MAX_NESTING) {
        p = scanField(p + 1, q, triple, raw, nest + 1);
      } else if (c == '\\' && !raw) {
        p = skipEscape(p);
      } else {
        p++;
      }
    }
    return n;
  }

  private int skipEscape(int p) {
    p++;
    if (p + 1 < n && src.charAt(p) == '\r' && src.charAt(p + 1) == '\n') {
      return p + 2;
    }
    return Math.min(p + 1, n);
  }

  private void skipNewline() {
    if (src.charAt(pos) == '\r' && pos + 1 < n && src.charAt(pos + 1) == '\n') {
      pos++;
    }
    pos++;
    line++;
    lineStart = pos;
  }

  private void emit(TokenKind kind, int s, int e) {
    tokens.add(make(kind, s, e));
    pos = e;
    lineHasTokens = true;
  }

  /** NEWLINE, INDENT, DEDENT: at the current position, not moving it. */
  private void layout(TokenKind kind, String text) {
    int col = pos - lineStart;
    tokens.add(new Token(kind, text, line, col, line, col + text.length()));
  }

  private Token make(TokenKind kind, int s, int e) {
    int startLine = line;
    int startCol = s - lineStart;
    for (int i = s; i < e; i++) {
      char c = src.charAt(i);
      if (c == '\n' || c == '\r' && (i + 1 >= n || src.charAt(i + 1) != '\n')) {
        line++;
        lineStart = i + 1;
      }
    }
    return new Token(kind, src.substring(s, e), startLine, startCol, line, e - lineStart);
  }

  private static boolean isNl(char c) {
    return c == '\n' || c == '\r';
  }

  private static boolean isIdentStart(char c) {
    return c == '_' || Character.isLetter(c) || c > 127 && Character.isUnicodeIdentifierStart(c);
  }

  private static boolean isIdentPart(char c) {
    return c == '_' || Character.isLetterOrDigit(c) || c > 127 && Character.isUnicodeIdentifierPart(c);
  }
}
