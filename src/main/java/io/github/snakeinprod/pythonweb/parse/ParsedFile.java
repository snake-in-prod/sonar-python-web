package io.github.snakeinprod.pythonweb.parse;

import io.github.snakeinprod.pythonweb.lang.python.PyModule;
import io.github.snakeinprod.pythonweb.lang.python.PythonLexer;
import java.util.List;

/** One parsed Python file: its tokens (comments left out), its comments, the token tree and the statement tree. */
public final class ParsedFile {

  private final String path;
  private final List<String> lines;
  private final List<Token> tokens;
  private final List<Token> comments;
  private final Node.Group root;
  private final PyModule module;
  private List<Chain> chains;

  private ParsedFile(String path, String source) {
    Lexed lexed = PythonLexer.lex(source);
    this.path = path;
    this.lines = List.of(source.split("\r\n|\r|\n", -1));
    this.tokens = lexed.tokens();
    this.comments = lexed.comments();
    this.root = TreeBuilder.build(tokens);
    this.module = PyModule.of(root);
  }

  /** Never throws: a broken file still gives tokens and statements. */
  public static ParsedFile parse(String path, String source) {
    return new ParsedFile(path, source);
  }

  /** Path relative to the project base directory, "/" separated. */
  public String path() {
    return path;
  }

  public List<String> lines() {
    return lines;
  }

  public List<Token> tokens() {
    return tokens;
  }

  public List<Token> comments() {
    return comments;
  }

  public Node.Group root() {
    return root;
  }

  /** The statements and imports. */
  public PyModule py() {
    return module;
  }

  /** Every chain of the file, see {@link Chains#in}. */
  public List<Chain> chains() {
    if (chains == null) {
      chains = Chains.in(root);
    }
    return chains;
  }
}
