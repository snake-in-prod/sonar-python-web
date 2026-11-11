# Python web rules for SonarQube

A SonarQube plugin with framework-aware security and correctness rules for Django (Django REST framework included),
FastAPI and Flask, for SonarQube Community Build, whose bundled Python analyzer has no taint analysis. It builds a
model of the app's endpoints (routes, views, their authentication) and follows request data across functions and
modules to SQL, shell, file, URL fetch, redirect, template and deserialization sinks. Each issue names the endpoint
and shows the path as secondary locations.

Work in progress: the project model, the taint engine, the measures and the rule catalog are in place; the rules
themselves report nothing yet.

## Install

Requires SonarQube 10.12 or later (Community Build included) and Java 21. Build with `./mvnw verify`, copy
`target/sonar-python-web-<version>.jar` to `extensions/plugins/` and restart. The plugin analyses py files of projects
that import Django, FastAPI, Starlette or Flask; other projects are skipped.

## Rules

Repository `pythonweb-python`, built-in profile "Python Web" (SonarQube allows one built-in "Sonar way" per language,
so activate the rules in your own profile, or extend "Python Web").

| Rule | Type | Severity | In profile |
|---|---|---|---|
| TaintedSql | Vulnerability | Critical | yes |
| TaintedCommand | Vulnerability | Critical | yes |
| TaintedPath | Vulnerability | Major | yes |
| TaintedUrlFetch | Vulnerability | Major | yes |
| OpenRedirect | Vulnerability | Major | yes |
| UnsafeTemplate | Vulnerability | Critical | yes |
| UnsafeDeserialization | Vulnerability | Critical | yes |
| EndpointWithoutAuth | Vulnerability | Major | yes |
| CsrfExemptMutation | Vulnerability | Major | yes |
| BlockingCallInAsync | Bug | Major | yes |
| MissingAwait | Bug | Critical | yes |
| MutableDefaultInModel | Bug | Major | yes |
| ResponseModelLeak | Vulnerability | Major | no |
| NPlusOneQuery | Code smell | Minor | no |

## Measures

pw_endpoints, pw_mutating_endpoints, pw_unprotected_endpoints, pw_async_endpoints, pw_blocking_calls,
pw_taint_findings, and pw_endpoints_json (every endpoint with its path, methods, framework, function, auth, async flag
and issues) for the "Python Web" project page.

See [docs/DESIGN.md](docs/DESIGN.md) for how it works and how to write a rule.

## License

Apache-2.0
