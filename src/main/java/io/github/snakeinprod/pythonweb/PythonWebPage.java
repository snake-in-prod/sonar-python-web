package io.github.snakeinprod.pythonweb;

import org.sonar.api.web.page.Context;
import org.sonar.api.web.page.Page;
import org.sonar.api.web.page.PageDefinition;

/** The project page "Python Web" ({@code static/pythonweb.js}). */
public class PythonWebPage implements PageDefinition {

  @Override
  public void define(Context context) {
    context.addPage(Page.builder("pythonweb/pythonweb").setName("Python Web").setScope(Page.Scope.COMPONENT)
      .setComponentQualifiers(Page.Qualifier.PROJECT).build());
  }
}
