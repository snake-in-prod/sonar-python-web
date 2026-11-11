package io.github.snakeinprod.pythonweb.model;

import java.util.Set;

/** The files the model reads: the sensor, the command line scanner and the tests each give one. */
public interface Project {

  /** Paths relative to the base directory, "/" separated, of the project's Python files. */
  Set<String> paths();

  /** Content of a file listed by {@link #paths()}, or null when it cannot be read. */
  String read(String path);
}
