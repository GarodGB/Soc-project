/* ABSEGA — shared auth guard for frontend.html / ad_dashboard.html.
 *
 * 1. Redirects to login.html if there is no session.
 * 2. Patches window.fetch so every same-origin request carries the bearer
 *    token automatically — none of the existing fetch() call sites need to
 *    change.
 * 3. On 401 (session expired/invalid), clears the session and redirects to
 *    login.html. On 403 (role not permitted), shows a small toast instead of
 *    letting the caller fail silently or show a raw error.
 * 4. For the read-only Analyst role:
 *    - Detections and Telemetry are off-limits — the nav tabs are hidden and
 *      any attempt to navigate there (nav tab, Overview card, feature card —
 *      anything that calls switchNav) is blocked with a message instead.
 *    - Every element tagged data-requires-write stays visible and clickable
 *      (so the analyst can see the app's full surface), but clicking it pops
 *      a message explaining the role can't do that, instead of running the
 *      action. This is delegated at the document level so it also covers
 *      buttons rendered later by JS (table rows, the Web/Linux workspace),
 *      not just what existed at page load.
 */
(function () {
  var user = sessionStorage.getItem('absega_user');
  if (!user) {
    window.location.href = 'login.html';
    return;
  }

  var role = (sessionStorage.getItem('absega_role') || 'analyst').toLowerCase();
  var RESTRICTED_NAV = { detections: true, telemetry: true };

  function token() {
    var t = sessionStorage.getItem('absega_token');
    return (t && t !== 'session') ? t : '';
  }

  function toast(message) {
    var el = document.getElementById('absega-permission-toast');
    if (!el) {
      el = document.createElement('div');
      el.id = 'absega-permission-toast';
      el.style.cssText =
        'position:fixed;bottom:20px;right:20px;z-index:99999;' +
        'background:#3a1f1f;color:#ffb4b4;border:1px solid #7a3a3a;' +
        'padding:12px 16px;border-radius:8px;font:13px system-ui,sans-serif;' +
        'max-width:360px;box-shadow:0 4px 16px rgba(0,0,0,.4);' +
        'opacity:0;transition:opacity .2s;';
      document.body.appendChild(el);
    }
    el.textContent = message;
    el.style.opacity = '1';
    clearTimeout(el._hideTimer);
    el._hideTimer = setTimeout(function () { el.style.opacity = '0'; }, 4000);
  }

  var _fetch = window.fetch;
  window.fetch = function (input, init) {
    init = init || {};
    var url = typeof input === 'string' ? input : (input && input.url) || '';
    var isRelative = url.indexOf('http://') !== 0 && url.indexOf('https://') !== 0;
    var isSameOrigin = isRelative || url.indexOf(window.location.origin) === 0;

    if (isSameOrigin) {
      var t = token();
      if (t) {
        init.headers = Object.assign({}, init.headers || {}, { Authorization: 'Bearer ' + t });
      }
    }

    return _fetch(input, init).then(function (res) {
      if (isSameOrigin && res.status === 401) {
        sessionStorage.removeItem('absega_token');
        sessionStorage.removeItem('absega_user');
        sessionStorage.removeItem('absega_role');
        sessionStorage.removeItem('absega_name');
        window.location.href = 'login.html';
      } else if (isSameOrigin && res.status === 403) {
        res.clone().json().then(function (body) {
          toast((body && body.detail) || 'Your role does not have permission for this action.');
        }).catch(function () {
          toast('Your role does not have permission for this action.');
        });
      }
      return res;
    });
  };

  function applyRoleGating() {
    document.body.setAttribute('data-role', role);
    if (role !== 'analyst') return;

    // Detections / Telemetry are off-limits for Analyst — hide the nav tabs
    // so the primary navigation only ever shows Overview / Validation / Coverage.
    document.querySelectorAll('.nav-tab').forEach(function (tab) {
      var onclickAttr = tab.getAttribute('onclick') || '';
      Object.keys(RESTRICTED_NAV).forEach(function (page) {
        if (onclickAttr.indexOf("'" + page + "'") !== -1) tab.style.display = 'none';
      });
    });

    // Backstop: anything that still calls switchNav('detections'|'telemetry')
    // — Overview cards, feature cards, etc. — is blocked with a message
    // rather than silently opening a page the analyst shouldn't see.
    if (typeof window.switchNav === 'function') {
      var _switchNav = window.switchNav;
      window.switchNav = function (el, id) {
        if (RESTRICTED_NAV[id]) {
          toast('Your Analyst role only has access to Overview, Validation, and Coverage.');
          return;
        }
        return _switchNav.apply(this, arguments);
      };
    }

    // Every write-restricted control stays visible and clickable, but the
    // click is intercepted (document-level, capture phase, so it runs before
    // any inline onclick handler — including on elements rendered after this
    // ran) and replaced with an explanatory message instead of the action.
    document.addEventListener('click', function (e) {
      var el = e.target.closest && e.target.closest('[data-requires-write]');
      if (!el) return;
      e.preventDefault();
      e.stopPropagation();
      e.stopImmediatePropagation();
      toast('Your Analyst role is read-only — this action requires the Detection Engineer or Administrator role.');
    }, true);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', applyRoleGating);
  } else {
    applyRoleGating();
  }

  window.ABSEGA_ROLE = role;
})();
