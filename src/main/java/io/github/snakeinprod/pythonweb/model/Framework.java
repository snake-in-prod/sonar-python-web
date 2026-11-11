package io.github.snakeinprod.pythonweb.model;

/** A web framework, detected from imports. Django REST framework is DRF (its apps are Django apps too). */
public enum Framework {
  DJANGO("django"), DRF("drf"), FASTAPI("fastapi"), FLASK("flask"), AIOHTTP("aiohttp");

  private final String key;

  Framework(String key) {
    this.key = key;
  }

  /** "django", "drf", "fastapi", "flask" or "aiohttp", as in pw_endpoints_json. */
  public String key() {
    return key;
  }

  /**
   * The framework an imported dotted path belongs to, or null. Starlette counts as FastAPI; aiohttp only for its server
   * ({@code aiohttp.web}, aiohttp_security, aiohttp_session), not for the client.
   */
  public static Framework of(String dotted) {
    String top = dotted.contains(".") ? dotted.substring(0, dotted.indexOf('.')) : dotted;
    return switch (top) {
      case "django" -> DJANGO;
      case "rest_framework" -> DRF;
      case "fastapi", "starlette" -> FASTAPI;
      case "flask" -> FLASK;
      case "aiohttp" -> dotted.startsWith("aiohttp.web") ? AIOHTTP : null;
      case "aiohttp_security", "aiohttp_session" -> AIOHTTP;
      default -> null;
    };
  }
}
