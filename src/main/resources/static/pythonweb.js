/* Project page "Python Web": headline tiles, the endpoint route tree with method badges and a dot per route coloured
   by its issues, the framework split and issues by rule. Plain DOM, charts are inline SVG. */
window.registerExtension('pythonweb/pythonweb', function (options) {
  var base = options.baseUrl || window.baseUrl || '';
  var project = options.component.key;
  var branchLike = options.branchLike;
  // same rule as the SonarQube UI: a non-main branch by name, a pull request by key, the main branch with nothing
  var scope = {};
  if (branchLike && branchLike.isMain !== undefined && !branchLike.isMain) {
    scope.branch = branchLike.name;
  } else if (branchLike && branchLike.key !== undefined) {
    scope.pullRequest = branchLike.key;
  }
  var SVG = 'http://www.w3.org/2000/svg';
  var REPO = 'pythonweb-python';
  var TAINT_RULES = ['TaintedSql', 'TaintedCommand', 'TaintedPath', 'TaintedUrlFetch', 'OpenRedirect', 'UnsafeTemplate',
    'UnsafeDeserialization'];
  var NO_DATA = 'Analyse the project with this plugin installed; it needs Python code importing Django, FastAPI or Flask';
  var MEASURES = ['pw_endpoints', 'pw_mutating_endpoints', 'pw_unprotected_endpoints', 'pw_async_endpoints',
    'pw_blocking_calls', 'pw_taint_findings', 'pw_endpoints_json', 'pw_app_json'];
  var NAMES = {pw_endpoints: 'Endpoints', pw_mutating_endpoints: 'Mutating endpoints',
    pw_unprotected_endpoints: 'Unprotected endpoints', pw_async_endpoints: 'Async endpoints',
    pw_blocking_calls: 'Blocking calls in async', pw_taint_findings: 'Taint findings'};
  var FRAMEWORKS = [{key: 'django', label: 'Django'}, {key: 'drf', label: 'Django REST'}, {key: 'fastapi', label: 'FastAPI'},
    {key: 'flask', label: 'Flask'}];
  var METHOD_ORDER = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];
  var TREE_ROWS = 60;

  function el(ns, tag, attrs, children) {
    var e = ns ? document.createElementNS(ns, tag) : document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      if (attrs[k] !== undefined && attrs[k] !== null) {
        e.setAttribute(k, attrs[k]);
      }
    });
    (children || []).forEach(function (c) {
      if (c !== null && c !== undefined) {
        e.appendChild(typeof c === 'object' ? c : document.createTextNode(String(c)));
      }
    });
    return e;
  }
  function h(tag, attrs, children) { return el(null, tag, attrs, children); }
  function s(tag, attrs, children) { return el(SVG, tag, attrs, children); }

  function fmt(v) {
    return Number(v).toLocaleString(undefined, {maximumFractionDigits: 1});
  }
  function plural(n, word) {
    return fmt(n) + ' ' + word + (n === 1 ? '' : 's');
  }
  function cut(text, n) {
    return text.length > n ? text.slice(0, Math.max(n - 1, 1)) + '…' : text;
  }

  function api(path, params, withScope) {
    var q = new URLSearchParams(Object.assign({}, withScope === false ? {} : scope, params));
    return fetch(base + '/api/' + path + '?' + q.toString(), {credentials: 'same-origin'}).then(function (r) {
      if (!r.ok) {
        throw new Error(path + ' answered HTTP ' + r.status);
      }
      return r.json();
    });
  }
  function page(path, params) {
    return base + '/' + path + '?' + new URLSearchParams(Object.assign({id: project}, scope, params)).toString();
  }
  function fileHref(file, line) {
    return page('code', line ? {selected: project + ':' + file, line: line} : {selected: project + ':' + file});
  }
  function issuesHref(rules) {
    return page('project/issues', {resolved: 'false', rules: rules.map(function (r) { return REPO + ':' + r; }).join(',')});
  }

  // the page follows SonarQube's light or dark theme: read the background the page sits on
  function dark(node) {
    for (; node && node.nodeType === 1; node = node.parentElement) {
      var c = (getComputedStyle(node).backgroundColor.match(/[\d.]+/g) || []).map(Number);
      if (c.length >= 3 && (c.length < 4 || c[3] > 0)) {
        return 0.299 * c[0] + 0.587 * c[1] + 0.114 * c[2] < 128;
      }
    }
    return false;
  }

  // issues of a route: none, a few, many
  function issueColor(n) {
    return n === 0 ? 'var(--clean)' : n < 3 ? 'var(--orange)' : 'var(--red)';
  }
  function methodVar(m) {
    return METHOD_ORDER.indexOf(m) >= 0 ? 'var(--m-' + m.toLowerCase() + ')' : 'var(--m-other)';
  }
  function sortMethods(list) {
    return list.slice().sort(function (a, b) {
      var ia = METHOD_ORDER.indexOf(a);
      var ib = METHOD_ORDER.indexOf(b);
      return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib) || (a < b ? -1 : 1);
    });
  }

  function info(text) {
    return h('span', {class: 'pw-info', title: text, 'aria-label': text, role: 'img', tabindex: '0'}, ['i']);
  }
  function empty(word, hint) {
    return h('div', {class: 'pw-empty'}, [h('span', {class: 'pw-dash', 'aria-hidden': 'true'}, ['–']), word,
      hint ? info(hint) : null]);
  }
  function dot(color) {
    return s('svg', {width: 10, height: 10, class: 'pw-inline', 'aria-hidden': 'true'},
      [s('circle', {cx: 5, cy: 5, r: 4.5, style: 'fill:' + color})]);
  }
  function badge(m) {
    return h('span', {class: 'pw-badge', style: 'color:' + methodVar(m)}, [m]);
  }

  // ---- charts

  // horizontal bars, label above each bar, value at the bar end; items [{label, value, href}]
  function hbars(items, w, o) {
    var row = 34;
    var plot = w - 48;
    var max = Math.max.apply(null, items.map(function (i) { return i.value; })) || 1;
    var chars = Math.max(Math.floor(w / 6.6), 12);
    var marks = items.map(function (it, i) {
      var y = i * row;
      var bw = Math.max(it.value / max * plot, 3);
      var tip = it.label + ': ' + fmt(it.value);
      var kids = [s('title', {}, [tip]), s('rect', {class: 'pw-hit', x: 0, y: y, width: w, height: row, fill: 'transparent'}),
        s('text', {x: 0, y: y + 12, class: 'pw-label'}, [cut(it.label, chars)]),
        s('rect', {x: 0, y: y + 17, width: bw, height: 10, rx: 2, style: 'fill:' + it.color}),
        s('text', {x: bw + 6, y: y + 26, class: 'pw-val'}, [fmt(it.value)])];
      return it.href ? s('a', {href: it.href, 'aria-label': tip}, kids) : s('g', {}, kids);
    });
    return s('svg', {width: w, height: items.length * row, role: 'group', 'aria-label': o.label}, marks);
  }

  function stack(parts, w, label) {
    var total = parts.reduce(function (a, p) { return a + p.value; }, 0) || 1;
    var x = 0;
    return s('svg', {width: w, height: 24, role: 'img', 'aria-label': label}, parts.filter(function (p) { return p.value > 0; })
      .map(function (p) {
        var pw = p.value / total * w;
        var r = s('rect', {x: x, y: 0, width: Math.max(pw - 2, 2), height: 24, rx: 3, style: 'fill:' + p.color},
          [s('title', {}, [p.label + ': ' + fmt(p.value)])]);
        x += pw;
        return r;
      }));
  }

  // the URL tree: one node per path segment, endpoints hang on their node
  function dynamicSeg(seg) {
    return /^[<{(:]/.test(seg) || /^\^?\(\?P</.test(seg);
  }
  function buildTree(endpoints) {
    var root = {seg: '', children: {}, entries: []};
    endpoints.forEach(function (e) {
      var node = root;
      (e.path || '').split('/').filter(Boolean).forEach(function (seg) {
        node = node.children[seg] || (node.children[seg] = {seg: seg, children: {}, entries: []});
      });
      node.entries.push(e);
    });
    return root;
  }
  function kids(node) {
    // static segments first, then path parameters, each alphabetically
    return Object.keys(node.children).map(function (k) { return node.children[k]; }).sort(function (a, b) {
      var da = dynamicSeg(a.seg);
      var db = dynamicSeg(b.seg);
      return da !== db ? (da ? 1 : -1) : a.seg < b.seg ? -1 : 1;
    });
  }
  function flatten(tree) {
    var rows = [];
    (function walk(node, depth, guides, path) {
      // a chain of segments without endpoints collapses into one row: /api/v1 rather than /api then /v1
      var list = kids(node);
      while (depth > 0 && node.entries.length === 0 && list.length === 1) {
        node = {seg: node.seg + '/' + list[0].seg, children: list[0].children, entries: list[0].entries};
        path = path + '/' + list[0].seg.split('/').pop();
        list = kids(node);
      }
      rows.push({node: node, depth: depth, guides: guides, path: path || '/', hasKids: list.length > 0});
      list.forEach(function (k, i) {
        walk(k, depth + 1, guides.concat([i < list.length - 1]), path + '/' + k.seg);
      });
    })(tree, 0, [], '');
    return rows;
  }
  function summary(entries) {
    var methods = [];
    entries.forEach(function (e) {
      (e.methods || []).forEach(function (m) {
        if (methods.indexOf(m) < 0) {
          methods.push(m);
        }
      });
    });
    return {
      methods: sortMethods(methods),
      issues: entries.reduce(function (a, e) { return a + (e.issues || 0); }, 0),
      open: entries.filter(function (e) { return e.mutating && !e.protected; }).length,
      async: entries.some(function (e) { return e.async; })
    };
  }

  // a method badge in SVG: tinted box, the method in its colour; about 6.6 px a character at 10 px monospace
  function svgBadge(m, x, mid) {
    var bw = m.length * 6.6 + 8;
    return {w: bw, node: s('g', {}, [s('rect', {x: x, y: mid - 8, width: bw, height: 16, rx: 3, class: 'pw-badge-bg',
      style: 'fill:' + methodVar(m)}), s('text', {x: x + bw / 2, y: mid + 3.5, 'text-anchor': 'middle', class: 'pw-badge-t',
      style: 'fill:' + methodVar(m)}, [m])])};
  }

  function routeTree(rows, w) {
    var row = 28;
    var step = 18;
    var top = 20;
    var wide = w >= 560;
    var maxSeg = wide ? 40 : 22;
    // the columns follow the longest row (labels about 7 px a character), not the panel's right edge
    var labelEnd = Math.max.apply(null, rows.map(function (r) {
      var sm = summary(r.node.entries);
      var badges = sm.methods.reduce(function (a, m) { return a + m.length * 6.6 + 12; }, 0);
      var tags = (sm.async ? 44 : 0) + (sm.open ? 60 : 0);
      return r.depth * step + 22 + Math.min(r.depth ? r.node.seg.length : 1, maxSeg) * 7.4 + badges + tags;
    }));
    var xIssues = wide ? Math.min(labelEnd + 48, w - 230) : w - 8;
    var xFn = xIssues + 28;
    var fnChars = Math.floor((w - xFn) / 6.6);
    var marks = [
      s('text', {x: xIssues, y: 11, 'text-anchor': 'end', class: 'pw-small'}, ['issues']),
      wide ? s('text', {x: xFn, y: 11, class: 'pw-small'}, ['handler']) : null];
    rows.forEach(function (r, i) {
      var y = top + i * row;
      var mid = y + row / 2;
      var cx = r.depth * step + 6;
      var marksOfRow = [];
      // tree lines: the ancestors' verticals, the elbow to this node, the line down to its children
      r.guides.forEach(function (more, j) {
        var x = j * step + 6;
        if (j < r.guides.length - 1) {
          if (more) {
            marksOfRow.push(s('line', {x1: x, x2: x, y1: y, y2: y + row, class: 'pw-tree-line'}));
          }
        } else {
          marksOfRow.push(s('path', {d: 'M' + x + ' ' + y + 'V' + mid + 'H' + (cx - 5) +
            (more ? 'M' + x + ' ' + mid + 'V' + (y + row) : ''), class: 'pw-tree-line', fill: 'none'}));
        }
      });
      if (r.hasKids) {
        marksOfRow.push(s('line', {x1: cx, x2: cx, y1: mid, y2: y + row, class: 'pw-tree-line'}));
      }
      var entries = r.node.entries;
      var label = cut(r.depth === 0 ? '/' : r.node.seg, maxSeg);
      var dyn = r.node.seg.split('/').some(dynamicSeg);
      if (entries.length === 0) {
        marksOfRow.push(s('circle', {cx: cx, cy: mid, r: 2.5, class: 'pw-hollow'}),
          s('text', {x: cx + 10, y: mid + 4, class: 'pw-label pw-muted' + (dyn ? ' pw-dyn' : '')}, [label]));
        marks.push(s('g', {'aria-hidden': 'true'}, marksOfRow));
        return;
      }
      var sm = summary(entries);
      var labelNode = s('text', {x: cx + 12, y: mid + 4, class: 'pw-label' + (dyn ? ' pw-dyn' : '')}, [label]);
      var x = cx + 12 + label.length * (dyn ? 7.4 : 7.2) + 10;
      var after = [];
      sm.methods.forEach(function (m) {
        var b = svgBadge(m, x, mid);
        after.push(b.node);
        x += b.w + 4;
      });
      if (sm.async) {
        after.push(s('text', {x: x + 4, y: mid + 4, class: 'pw-tag'}, ['async']));
        x += 44;
      }
      if (sm.open) {
        after.push(s('text', {x: x + 4, y: mid + 4, class: 'pw-tag pw-open'}, ['no auth']));
      }
      var handlers = entries.map(function (e) { return e.function; }).filter(function (f, k, a) { return a.indexOf(f) === k; });
      var frameworks = entries.map(function (e) { return e.framework; }).filter(function (f, k, a) { return a.indexOf(f) === k; });
      var tip = r.path + ': ' + entries.map(function (e) {
        return (e.methods || []).join(',') + ' ' + e.function + ' (' + e.framework + (e.async ? ', async' : '') +
          (e.protected ? ', auth: ' + (e.auth || 'yes') : e.mutating ? ', no auth' : '') + ')';
      }).join('; ') + ', ' + plural(sm.issues, 'issue');
      marksOfRow.unshift(s('title', {}, [tip]),
        s('rect', {class: 'pw-hit', x: 0, y: y + 1, width: w, height: row - 2, rx: 4, fill: 'transparent'}));
      marksOfRow.push(s('circle', {cx: cx, cy: mid, r: 6, class: 'pw-dot', style: 'fill:' + issueColor(sm.issues)}), labelNode);
      marksOfRow = marksOfRow.concat(after);
      marksOfRow.push(s('text', {x: xIssues, y: mid + 4, 'text-anchor': 'end', class: sm.issues ? 'pw-val' : 'pw-small',
        style: sm.issues ? 'fill:' + issueColor(sm.issues) : null}, [sm.issues ? fmt(sm.issues) : '–']));
      if (wide) {
        var fn = handlers[0] + (handlers.length > 1 ? ' +' + (handlers.length - 1) : '');
        var fw = frameworks.join(', ');
        marksOfRow.push(s('text', {x: xFn, y: mid + 4, class: 'pw-fn'}, [cut(fn, Math.max(fnChars - fw.length - 2, 6)),
          s('tspan', {dx: 8, class: 'pw-small'}, [fw])]));
      }
      marks.push(s('a', {href: fileHref(entries[0].file, entries[0].line), 'aria-label': tip}, marksOfRow));
    });
    return s('svg', {width: w, height: top + rows.length * row, role: 'group',
      'aria-label': 'Endpoint tree: ' + rows.filter(function (r) { return r.node.entries.length; }).length + ' paths'}, marks);
  }

  // ---- layout

  var style = h('style', {}, [
    '.pw{width:100%;box-sizing:border-box;min-width:0;padding:0 20px 24px 20px;font-size:13px;color:inherit;' +
    '--blue:#2a78d6;--clean:#2a78d6;--orange:#e8a33d;--red:#d03b3b;--dyn:#7b4fc9;--track:rgba(128,128,128,.2);' +
    '--ok:#0b7a0b;--err:#d03b3b;--card:rgba(128,128,128,.06);--rule:rgba(128,128,128,.28);' +
    '--m-get:#2a6fc4;--m-post:#17804a;--m-put:#b36b00;--m-patch:#8a52c2;--m-delete:#c0392b;--m-other:#6b6b6b;' +
    '--fw-django:#0f6e57;--fw-drf:#52a37f;--fw-fastapi:#2a8fb8;--fw-flask:#8f8a7e}' +
    '.pw.pw-dark{--blue:#4a94ec;--clean:#4a94ec;--orange:#f0b45a;--red:#ee6b6b;--dyn:#b294f0;--ok:#3fbf3f;--err:#ee6b6b;' +
    '--m-get:#6aa8f0;--m-post:#4cc27f;--m-put:#f0a33c;--m-patch:#b68cf0;--m-delete:#f07a6e;--m-other:#a3a3a3;' +
    '--fw-django:#2fa384;--fw-drf:#86d1ad;--fw-fastapi:#4fb3de;--fw-flask:#a9a496}' +
    '.pw-head{display:flex;flex-wrap:wrap;align-items:center;gap:8px 16px;margin:16px 0 12px 0}' +
    '.pw h1{font-size:20px;margin:0}.pw h2{font-size:14px;font-weight:600;margin:0 0 12px 0}' +
    '.pw-tiles{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;list-style:none;padding:0;margin:0 0 12px 0}' +
    '.pw-main{display:grid;grid-template-columns:minmax(0,2fr) minmax(0,1fr);gap:12px;align-items:start}' +
    '.pw-side{display:grid;gap:12px;min-width:0}' +
    '.pw.pw-narrow .pw-main{grid-template-columns:minmax(0,1fr)}.pw.pw-narrow .pw-tiles{grid-template-columns:repeat(2,minmax(0,1fr))}' +
    '.pw-panel,.pw-tile{background:var(--card);border:1px solid var(--rule);border-radius:8px;padding:14px 16px;min-width:0}' +
    '.pw-tile{display:flex;flex-direction:column;gap:4px}.pw-tile .pw-name{font-size:12px;opacity:.8}' +
    '.pw-tile .pw-num{font-size:34px;font-weight:600;line-height:1.15}.pw-tile .pw-sub{font-size:12px;opacity:.7}' +
    '.pw-tile a{text-decoration:none}.pw-tile a:hover{text-decoration:underline}' +
    '.pw-bad{color:var(--err)}.pw-muted{opacity:.65}' +
    '.pw-empty{display:flex;align-items:center;gap:8px;opacity:.65;min-height:42px}.pw-dash{font-size:30px;font-weight:600}' +
    '.pw-info{display:inline-flex;align-items:center;justify-content:center;width:16px;height:16px;border-radius:50%;' +
    'border:1px solid currentColor;font:italic 600 11px Georgia,serif;cursor:help}' +
    '.pw svg{display:block;overflow:visible}.pw svg.pw-inline{display:inline-block;vertical-align:baseline;margin-right:6px}' +
    '.pw svg text{fill:currentColor}.pw-label{font-size:12px}.pw-val{font-size:12px;font-weight:600}' +
    '.pw-small{font-size:11px;opacity:.7}.pw-tag{font-size:10px;font-weight:600;opacity:.6;letter-spacing:.04em}' +
    '.pw svg text.pw-open{fill:var(--err);opacity:1}' +
    '.pw svg text.pw-dyn{fill:var(--dyn);font-style:italic}' +
    '.pw-fn,.pw-badge-t,.pw-badge{font-family:ui-monospace,Menlo,Consolas,monospace}.pw-fn{font-size:11px}' +
    '.pw-badge-t{font-size:10px;font-weight:700}.pw-badge-bg{fill-opacity:.14}' +
    '.pw-badge{display:inline-block;font-size:10px;font-weight:700;padding:1px 5px;border-radius:3px;' +
    'background:color-mix(in srgb,currentColor 14%,transparent)}' +
    '.pw-tree-line{stroke:currentColor;opacity:.25}.pw-hollow{fill:none;stroke:currentColor;opacity:.4}' +
    '.pw-dot{stroke:#fff;stroke-width:1.5}.pw.pw-dark .pw-dot{stroke:#1b1d23}' +
    '.pw svg a{cursor:pointer}.pw svg a:hover .pw-hit{fill:var(--track)}' +
    '.pw svg a:focus{outline:none}.pw svg a:focus-visible .pw-hit{stroke:var(--blue);stroke-width:2}' +
    '.pw-legend{list-style:none;padding:0;margin:0 0 10px 0;display:flex;flex-wrap:wrap;align-items:center;gap:4px 14px;font-size:12px}' +
    '.pw-legend .pw-badges{display:inline-flex;gap:3px;margin-right:4px}' +
    '.pw-sw{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:6px}' +
    '.pw-fw{width:100%;border-collapse:collapse;margin-top:12px;font-size:12px}' +
    '.pw-fw th,.pw-fw td{padding:5px 0;text-align:right;font-weight:400;border-top:1px solid var(--rule)}' +
    '.pw-fw thead th{border-top:0;font-size:11px;opacity:.7;padding-top:0}' +
    '.pw-fw th:first-child{text-align:left}.pw-fw td{font-weight:600;padding-left:8px}' +
    '.pw-fw td.pw-zero{font-weight:400;opacity:.5}' +
    '.pw-chips{display:flex;flex-wrap:wrap;gap:6px;list-style:none;padding:0;margin:0}' +
    '.pw-chip{display:inline-flex;gap:6px;align-items:center;border:1px solid var(--rule);border-radius:999px;padding:3px 10px;font-size:12px}' +
    '.pw-chip b{font-weight:700}.pw-pass b{color:var(--ok)}.pw-fail{border-color:var(--err)}.pw-fail b{color:var(--err)}' +
    '.pw-more{margin-top:8px;font:inherit;font-size:12px;color:inherit;background:none;border:1px solid var(--rule);border-radius:6px;' +
    'padding:4px 10px;cursor:pointer}' +
    '.pw a{color:inherit}'
  ]);
  var gate = h('ul', {class: 'pw-chips', 'aria-label': 'Quality gate'});
  var root = h('div', {class: 'pw'}, [style, h('div', {class: 'pw-head'}, [h('h1', {}, ['Python Web']), gate])]);
  var tiles = h('ul', {class: 'pw-tiles', 'aria-label': 'Headline measures'});
  var side = h('div', {class: 'pw-side'});
  var main = h('div', {class: 'pw-main'});
  // SonarQube keeps only the changed files of a pull request: the measures add up those; pw_endpoints_json and the
  // totals in pw_app_json are the whole app
  var whole = scope.pullRequest === undefined;
  var note = h('p', {class: 'pw-muted', style: 'margin:0 0 12px 0'}, ['Pull request: the numbers count the files it changes; ' +
    'the endpoint tree and the framework split show the whole app.']);
  if (!whole) {
    root.appendChild(note);
  }
  root.appendChild(tiles);
  root.appendChild(main);
  // SonarQube places extension pages in a grid of two columns: span both, or the page gets only the first one
  options.el.style.gridColumn = '1 / -1';
  options.el.style.width = '100%';
  options.el.appendChild(root);
  if (dark(options.el)) {
    root.classList.add('pw-dark');
  }

  // each panel draws for its current width and draws again when the page width changes
  var draws = [];
  function panel(title, parent) {
    var body = h('div', {}, [h('span', {class: 'pw-muted'}, ['…'])]);
    var node = h('section', {class: 'pw-panel', 'aria-label': title}, [h('h2', {}, [title]), body]);
    parent.appendChild(node);
    return {
      draw: function (fn) {
        var redraw = function () { body.replaceChildren.apply(body, [].concat(fn(Math.max(body.clientWidth, 200)))); };
        draws.push(redraw);
        redraw();
        return redraw;
      },
      empty: function (word, hint) { body.replaceChildren(empty(word, hint)); },
      fail: function (e) { body.replaceChildren(h('p', {role: 'alert', class: 'pw-muted'}, ['Cannot load: ' + e.message])); }
    };
  }
  var treePanel = panel('Endpoints', main);
  main.appendChild(side);
  var splitPanel = panel('Frameworks', side);
  var rulePanel = panel('Issues by rule', side);

  // no CSS container queries: SonarQube mounts the page in a grid column sized by its content, where inline-size
  // containment would shrink the page to its padding; a class set from the measured width does the same job
  var narrow = function () { root.classList.toggle('pw-narrow', root.clientWidth < 900); };
  narrow();
  var lastWidth = root.clientWidth;
  var observer = window.ResizeObserver ? new ResizeObserver(function () {
    if (Math.abs(root.clientWidth - lastWidth) > 16) {
      lastWidth = root.clientWidth;
      narrow();
      draws.forEach(function (d) { d(); });
    }
  }) : null;
  if (observer) {
    observer.observe(root);
  }

  // ---- data

  api('measures/component', {component: project, metricKeys: MEASURES.join(',')}).then(function (data) {
    var values = {};
    (data.component.measures || []).forEach(function (m) {
      var v = m.value !== undefined ? m.value : (m.period || (m.periods || [])[0] || {}).value;
      if (v !== undefined && v !== '') {
        values[m.metric] = /_json$/.test(m.metric) ? v : Number(v);
      }
    });
    var endpoints = [];
    try {
      endpoints = JSON.parse(values.pw_endpoints_json || '[]');
    } catch (e) {
      endpoints = [];
    }
    // whole-app totals: on a pull request the summed measures cover only its changed files
    var app = null;
    try {
      app = values.pw_app_json ? JSON.parse(values.pw_app_json) : null;
    } catch (e) {
      app = null;
    }
    if (app) {
      Object.keys(NAMES).forEach(function (k) {
        if (typeof app[k] === 'number') {
          values[k] = app[k];
        }
      });
      if (!whole) {
        whole = true;
        note.replaceChildren('Pull request: the numbers and panels show the whole app; issues by rule and the quality gate ' +
          'count the files it changes.');
      }
    }

    // tiles
    var mutating = values.pw_mutating_endpoints;
    var asyncs = values.pw_async_endpoints;
    [
      {key: 'pw_endpoints', sub: mutating !== undefined ? fmt(mutating) + ' mutating · ' + fmt(asyncs || 0) + ' async' : null},
      {key: 'pw_unprotected_endpoints', bad: values.pw_unprotected_endpoints > 0, rules: ['EndpointWithoutAuth'],
        sub: mutating !== undefined ? 'of ' + plural(mutating, 'mutating endpoint') : null},
      {key: 'pw_taint_findings', bad: values.pw_taint_findings > 0, rules: TAINT_RULES, sub: 'request data reaching a sink'},
      {key: 'pw_blocking_calls', bad: values.pw_blocking_calls > 0, rules: ['BlockingCallInAsync'],
        sub: asyncs !== undefined ? 'in ' + plural(asyncs, 'async endpoint') : null}
    ].forEach(function (t) {
      var v = values[t.key];
      var num = v === undefined ? empty('no data', NO_DATA) : h('span', {class: 'pw-num' + (t.bad ? ' pw-bad' : '')}, [fmt(v)]);
      tiles.appendChild(h('li', {class: 'pw-tile'}, [h('span', {class: 'pw-name'}, [NAMES[t.key]]),
        v > 0 && t.rules ? h('a', {href: issuesHref(t.rules), title: 'Open the issues'}, [num]) : num,
        v === undefined || !t.sub ? null : h('span', {class: 'pw-sub'}, [t.sub])]));
    });

    // endpoint tree
    if (endpoints.length === 0) {
      treePanel.empty(values.pw_endpoints === 0 ? 'no endpoints' : 'no data',
        values.pw_endpoints === 0 ? 'No route or view found' : NO_DATA);
    } else {
      var rows = flatten(buildTree(endpoints));
      var showAll = rows.length <= TREE_ROWS;
      var key = [{label: 'no issues', color: issueColor(0)}, {label: '1–2', color: issueColor(1)}, {label: '3+', color: issueColor(3)}];
      var redraw = treePanel.draw(function (w) {
        var out = [h('ul', {class: 'pw-legend', 'aria-label': 'Legend'},
          key.map(function (k) { return h('li', {}, [dot(k.color), k.label]); }).concat([
            h('li', {}, [h('span', {class: 'pw-badges'}, METHOD_ORDER.map(badge)), 'methods']),
            h('li', {}, [h('i', {style: 'color:var(--dyn)'}, ['{param}']), ' path parameter'])])),
        routeTree(showAll ? rows : rows.slice(0, TREE_ROWS), w)];
        if (!showAll) {
          var more = h('button', {type: 'button', class: 'pw-more'}, ['Show all ' + rows.length + ' rows']);
          more.addEventListener('click', function () { showAll = true; redraw(); });
          out.push(more);
        }
        return out;
      });
    }

    // framework split: endpoints per framework, with how many change data and how many of those check nobody
    var parts = FRAMEWORKS.map(function (f) {
      var list = endpoints.filter(function (e) { return e.framework === f.key; });
      var mut = list.filter(function (e) { return e.mutating; });
      return {label: f.label, color: 'var(--fw-' + f.key + ')', value: list.length, mutating: mut.length,
        open: mut.filter(function (e) { return !e.protected; }).length,
        async: list.filter(function (e) { return e.async; }).length};
    }).filter(function (p) { return p.value > 0; });
    if (parts.length === 0) {
      splitPanel.empty(values.pw_endpoints === 0 ? 'no endpoints' : 'no data', values.pw_endpoints === 0 ? 'No route or view found' : NO_DATA);
    } else {
      var total = endpoints.length;
      splitPanel.draw(function (w) {
        var cell = function (n) { return h('td', {class: n ? null : 'pw-zero'}, [fmt(n)]); };
        return [stack(parts, w, plural(total, 'endpoint') + ': ' + parts.map(function (p) { return p.label + ' ' + p.value; }).join(', ')),
          h('table', {class: 'pw-fw'}, [
            h('thead', {}, [h('tr', {}, ['framework', 'endpoints', 'mutating', 'no auth', 'async'].map(function (c) {
              return h('th', {scope: 'col'}, [c]);
            }))]),
            h('tbody', {}, parts.map(function (p) {
              return h('tr', {}, [h('th', {scope: 'row'}, [h('span', {class: 'pw-sw', style: 'background:' + p.color}), p.label,
                h('span', {class: 'pw-muted'}, [' ' + Math.round(p.value / total * 100) + '%'])]),
              cell(p.value), cell(p.mutating), h('td', {class: p.open ? 'pw-bad' : 'pw-zero'}, [fmt(p.open)]), cell(p.async)]);
            }))])];
      });
    }
  }).catch(function (e) {
    tiles.replaceChildren(h('li', {role: 'alert'}, ['Cannot load the measures: ' + e.message]));
    [treePanel, splitPanel].forEach(function (p) { p.fail(e); });
  });

  // quality gate: overall status and the conditions on this plugin's metrics
  api('qualitygates/project_status', {projectKey: project}).then(function (data) {
    var status = data.projectStatus || {};
    var overall = status.status === 'OK' ? 'Passed' : status.status === 'ERROR' ? 'Failed' : null;
    if (!overall) {
      return;
    }
    var chip = function (ok, text) {
      return h('li', {class: 'pw-chip ' + (ok ? 'pw-pass' : 'pw-fail')}, [h('b', {'aria-hidden': 'true'}, [ok ? '✓' : '✗']), text]);
    };
    gate.appendChild(chip(overall === 'Passed', 'Quality gate ' + overall.toLowerCase()));
    (status.conditions || []).filter(function (c) { return /^(new_)?pw_/.test(c.metricKey); }).forEach(function (c) {
      var ok = c.status !== 'ERROR';
      var k = c.metricKey.replace(/^new_/, '');
      gate.appendChild(chip(ok, (c.metricKey === k ? '' : 'New ') + (NAMES[k] || k) + ' ' +
        (c.actualValue === undefined ? '–' : fmt(c.actualValue)) + ' (' + (c.comparator === 'LT' ? '≥ ' : '≤ ') +
        fmt(c.errorThreshold) + ')'));
    });
  }).catch(function () { /* no gate chip */ });

  // open issues of the plugin's rules, coloured by type: vulnerabilities red, bugs orange, code smells grey
  var TYPE_COLOR = {VULNERABILITY: 'var(--red)', BUG: 'var(--orange)'};
  api('rules/search', {repositories: REPO, f: 'name', ps: 500}, false).then(function (data) {
    var rules = {};
    (data.rules || []).forEach(function (r) { rules[r.key] = r; });
    if (Object.keys(rules).length === 0) {
      return [];
    }
    return api('issues/search', {componentKeys: project, resolved: 'false', rules: Object.keys(rules).join(','), facets: 'rules', ps: 1})
      .then(function (issues) {
        var facet = (issues.facets || []).filter(function (f) { return f.property === 'rules'; })[0] || {values: []};
        // SonarQube facets ignore their own filter (sticky facets): keep the values of this plugin's repository
        return facet.values.filter(function (v) { return v.count > 0 && rules[v.val]; }).map(function (v) {
          return {label: rules[v.val].name || v.val.split(':')[1], value: v.count,
            color: TYPE_COLOR[rules[v.val].type] || 'var(--m-other)',
            href: page('project/issues', {resolved: 'false', rules: v.val})};
        });
      });
  }).then(function (counts) {
    counts.sort(function (a, b) { return b.value - a.value; });
    if (counts.length === 0) {
      rulePanel.empty('none', 'No open issues of the Python Web rules');
    } else {
      rulePanel.draw(function (w) {
        return [h('ul', {class: 'pw-legend', 'aria-label': 'Bar colour: rule type'}, [
          h('li', {}, [h('span', {class: 'pw-sw', style: 'background:var(--red)'}), 'vulnerability']),
          h('li', {}, [h('span', {class: 'pw-sw', style: 'background:var(--orange)'}), 'bug']),
          h('li', {}, [h('span', {class: 'pw-sw', style: 'background:var(--m-other)'}), 'code smell'])]),
        hbars(counts, w, {label: 'Open issues by rule'})];
      });
    }
  }).catch(rulePanel.fail);

  return function () {
    if (observer) {
      observer.disconnect();
    }
    root.remove();
  };
});
