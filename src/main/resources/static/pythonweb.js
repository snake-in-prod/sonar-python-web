/* Project page "Python Web". Placeholder: the tiles, the endpoint route tree, the framework split and the issues by
   rule come next. Plain DOM built node by node; it spans the two-column extension grid of SonarQube. */
window.registerExtension('pythonweb/pythonweb', function (options) {
  var root = document.createElement('section');
  root.setAttribute('aria-label', 'Python Web');
  root.style.padding = '16px';
  var title = document.createElement('h1');
  title.textContent = 'Python Web';
  var note = document.createElement('p');
  note.textContent = 'Endpoints, authentication and taint findings of the Django, FastAPI and Flask code of this project.';
  root.appendChild(title);
  root.appendChild(note);
  options.el.style.gridColumn = '1 / -1';
  options.el.style.width = '100%';
  options.el.appendChild(root);
  return function () {
    if (root.parentNode) {
      root.parentNode.removeChild(root);
    }
  };
});
