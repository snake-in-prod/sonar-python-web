package io.github.snakeinprod.pythonweb.model;

import io.github.snakeinprod.pythonweb.parse.Token;
import java.util.List;
import java.util.Set;

/**
 * One HTTP endpoint: a FastAPI route, a Django URL pattern's view (a function, a class-based view's handler method or
 * a ViewSet action) or a Flask route.
 *
 * @param path     the full URL path as declared, prefixes included ("/api/items/{item_id}", "/blog/<int:pk>/")
 * @param methods  upper case HTTP methods; "ANY" for a Django function view that does not restrict them
 * @param function the handler; null for a handler inherited from a framework class (a ModelViewSet's create)
 * @param viewClass the class-based view or ViewSet, or null
 * @param token    where to report: the handler's name, else the class name
 * @param label    "create_item", "ItemViewSet.create"
 * @param auth     the evidence that the caller is checked
 * @param writes   the handler body changes data (an ORM save, create, update or delete call)
 */
public record Endpoint(Framework framework, String path, List<String> methods, Module module, Function function, PyClass viewClass,
  Token token, String label, Auth auth, boolean async, boolean writes) {

  private static final Set<String> MUTATING = Set.of("POST", "PUT", "PATCH", "DELETE");

  /**
   * Whether and how the endpoint checks its caller. {@code present}: some check applies; {@code evidence}: what it
   * is ("Depends(get_current_user) on the router", "login_required"), or what explicitly opens it ("AllowAny"), or null.
   */
  public record Auth(boolean present, String evidence) {
    public static final Auth NONE = new Auth(false, null);

    public static Auth by(String evidence) {
      return new Auth(true, evidence);
    }
  }

  /** POST, PUT, PATCH or DELETE, or a Django view open to any method whose body writes. */
  public boolean mutating() {
    return methods.stream().anyMatch(MUTATING::contains) || methods.contains("ANY") && writes;
  }

  /** The lines of the handler, or of the view class when there is none. */
  public int firstLine() {
    return function != null ? function.firstLine() : viewClass != null ? viewClass.firstLine() : token.line();
  }

  public int lastLine() {
    return function != null ? function.lastLine() : viewClass != null ? viewClass.lastLine() : token.line();
  }

  @Override
  public String toString() {
    return framework.key() + " " + String.join(",", methods) + " " + path + " -> " + module.path() + "#" + label
      + (auth.present() ? " [auth: " + auth.evidence() + "]" : auth.evidence() != null ? " [open: " + auth.evidence() + "]" : "")
      + (async ? " async" : "");
  }
}
