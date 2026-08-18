/* ═══════════════════════════════════════════════════════════════════════════
   ABSEGA — AI Detection Recommendation panel

   ONE implementation, mounted into every expandable attack card:
     · Active Directory / Windows   → the AD comparison drawer
     · Web / Linux                  → the expandable validation cards
     · Web / Linux                  → the behaviour-matrix drawer

   Mount with:
       AIPanel.mount(containerElement, { surface, attackId, runId });

   Everything the backend returns is treated as untrusted text: all values go
   through esc() and are inserted as escaped strings — never raw innerHTML.
   The API key lives only in the backend and is never requested, received or
   rendered here.
   ═══════════════════════════════════════════════════════════════════════════ */
(function (global) {
  'use strict';

  var API = (global.API || global.location.origin);

  // ── style (injected once, uses the existing ABSEGA theme variables) ───────
  var CSS = [
    '.aip{border:1px solid rgba(139,43,226,.28);border-radius:11px;background:linear-gradient(180deg,rgba(139,43,226,.06),rgba(139,43,226,.02));margin-top:16px;overflow:hidden}',
    '.aip-head{display:flex;align-items:center;gap:10px;padding:12px 14px;border-bottom:1px solid rgba(139,43,226,.18);flex-wrap:wrap}',
    '.aip-title{font-family:var(--mono);font-size:13px;font-weight:700;color:#c4a4ff;letter-spacing:.02em}',
    '.aip-meta{display:flex;gap:6px;flex-wrap:wrap;margin-left:auto}',
    '.aip-chip{font-family:var(--mono);font-size:10px;padding:2px 8px;border-radius:4px;background:rgba(255,255,255,.04);border:1px solid var(--border2);color:var(--text2);white-space:nowrap}',
    '.aip-chip.ai{background:rgba(139,43,226,.12);border-color:rgba(139,43,226,.35);color:#c4a4ff}',
    '.aip-chip.ok{background:rgba(74,222,128,.12);border-color:rgba(74,222,128,.35);color:#4ade80}',
    '.aip-chip.warn{background:rgba(245,158,11,.12);border-color:rgba(245,158,11,.35);color:#f59e0b}',
    '.aip-chip.bad{background:rgba(239,68,68,.12);border-color:rgba(239,68,68,.35);color:#ef4444}',
    '.aip-body{padding:14px}',
    '.aip-note{font-family:var(--mono);font-size:11px;line-height:1.7;color:var(--text2);padding:10px 12px;border-radius:8px;background:rgba(255,255,255,.02);border:1px solid var(--border);margin-bottom:12px}',
    '.aip-note.green{color:#4ade80;background:rgba(74,222,128,.07);border-color:rgba(74,222,128,.3)}',
    '.aip-note.warn{color:#f59e0b;background:rgba(245,158,11,.07);border-color:rgba(245,158,11,.3)}',
    '.aip-note.bad{color:#ef4444;background:rgba(239,68,68,.07);border-color:rgba(239,68,68,.3)}',
    '.aip-note.ai{color:#c4a4ff;background:rgba(139,43,226,.07);border-color:rgba(139,43,226,.3)}',
    '.aip-btn{padding:6px 13px;border-radius:7px;font-size:11.5px;font-family:var(--mono);cursor:pointer;border:1px solid var(--border2);background:transparent;color:var(--text2);transition:all .15s}',
    '.aip-btn:hover:not(:disabled){color:var(--text);background:var(--bg4)}',
    '.aip-btn:disabled{opacity:.4;cursor:not-allowed}',
    '.aip-btn.primary{background:linear-gradient(135deg,#8b2be2,#e8284a);color:#fff;font-weight:700;border-color:transparent}',
    '.aip-btn.primary:hover:not(:disabled){opacity:.9}',
    '.aip-btn.green{background:rgba(74,222,128,.12);color:#4ade80;border-color:rgba(74,222,128,.35)}',
    '.aip-btn.blue{background:rgba(96,165,250,.12);color:#60a5fa;border-color:rgba(96,165,250,.35)}',
    '.aip-btn.red{background:rgba(239,68,68,.12);color:#ef4444;border-color:rgba(239,68,68,.35)}',
    '.aip-actions{display:flex;gap:7px;flex-wrap:wrap;margin-top:14px;padding-top:12px;border-top:1px solid var(--border)}',
    '.aip-tabs{display:flex;gap:3px;flex-wrap:wrap;border-bottom:1px solid var(--border);margin-bottom:12px}',
    '.aip-tab{padding:6px 12px;font-family:var(--mono);font-size:11px;color:var(--text2);background:transparent;border:none;border-bottom:2px solid transparent;cursor:pointer}',
    '.aip-tab:hover{color:var(--text)}',
    '.aip-tab.active{color:#c4a4ff;border-bottom-color:#8b2be2}',
    '.aip-pane{display:none}.aip-pane.active{display:block}',
    '.aip-code{width:100%;min-height:210px;font-family:var(--mono);font-size:11.5px;line-height:1.65;color:#60a5fa;background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:11px;resize:vertical;white-space:pre;overflow:auto;tab-size:2}',
    '.aip-code:focus{outline:none;border-color:rgba(139,43,226,.5)}',
    '.aip-pre{font-family:var(--mono);font-size:11.5px;line-height:1.65;color:var(--text2);background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:11px;white-space:pre-wrap;word-break:break-word;max-height:320px;overflow:auto}',
    '.aip-lbl{font-family:var(--mono);font-size:10px;text-transform:uppercase;letter-spacing:.06em;color:var(--text3);margin:12px 0 6px}',
    '.aip-lbl:first-child{margin-top:0}',
    '.aip-list{margin:0;padding-left:18px;font-size:12px;line-height:1.8;color:var(--text2)}',
    '.aip-row{display:flex;gap:10px;padding:5px 0;border-bottom:1px solid var(--border);font-size:12px}',
    '.aip-row:last-child{border-bottom:none}',
    '.aip-row .k{min-width:150px;font-family:var(--mono);font-size:11px;color:var(--text3)}',
    '.aip-row .v{color:var(--text);flex:1;word-break:break-word}',
    '.aip-check{display:flex;align-items:center;gap:8px;padding:4px 0;font-family:var(--mono);font-size:11.5px}',
    '.aip-check .ico{width:16px;text-align:center}',
    '.aip-spin{display:inline-block;width:12px;height:12px;border:2px solid rgba(196,164,255,.25);border-top-color:#c4a4ff;border-radius:50%;animation:aipspin .8s linear infinite;vertical-align:-2px}',
    '@keyframes aipspin{to{transform:rotate(360deg)}}',
    '.aip-modal-bg{position:fixed;inset:0;background:rgba(0,0,0,.65);z-index:9998;display:flex;align-items:center;justify-content:center;padding:20px}',
    '.aip-modal{background:var(--bg3);border:1px solid rgba(139,43,226,.35);border-radius:12px;width:640px;max-width:100%;max-height:88vh;overflow:auto;padding:18px}',
    '.aip-ta{width:100%;min-height:110px;font-family:var(--mono);font-size:12px;color:var(--text);background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:10px;resize:vertical}',
    '.aip-ta:focus{outline:none;border-color:rgba(139,43,226,.5)}',
    '.aip-diff{font-family:var(--mono);font-size:11px;line-height:1.6;background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:10px;max-height:280px;overflow:auto}',
    '.aip-diff .add{color:#4ade80}.aip-diff .del{color:#ef4444}.aip-diff .ctx{color:var(--text3)}',
    '.aip-hist{display:flex;gap:10px;align-items:flex-start;padding:8px 0;border-bottom:1px solid var(--border);font-size:12px}',
    '.aip-hist:last-child{border-bottom:none}',
    '.aip-vbadge{font-family:var(--mono);font-size:10px;padding:2px 7px;border-radius:4px;background:rgba(139,43,226,.14);color:#c4a4ff;border:1px solid rgba(139,43,226,.3);white-space:nowrap}'
  ].join('\n');

  function injectStyle() {
    if (document.getElementById('aip-style')) return;
    var el = document.createElement('style');
    el.id = 'aip-style';
    el.textContent = CSS;
    document.head.appendChild(el);
  }

  // ── helpers ──────────────────────────────────────────────────────────────

  function esc(value) {
    if (value === null || value === undefined) return '';
    return String(value)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function token() {
    try { var t = sessionStorage.getItem('absega_token'); return (t && t !== 'session') ? t : ''; }
    catch (e) { return ''; }
  }

  function headers(json) {
    var h = {};
    var t = token();
    if (t) h['Authorization'] = 'Bearer ' + t;
    if (json) h['Content-Type'] = 'application/json';
    return h;
  }

  async function call(method, path, body) {
    var opts = { method: method, headers: headers(!!body) };
    if (body) opts.body = JSON.stringify(body);
    var res = await fetch(API + path, opts);
    var data = null;
    try { data = await res.json(); } catch (e) { data = null; }
    if (!res.ok) {
      var detail = (data && (data.detail || data.message)) || ('HTTP ' + res.status);
      if (typeof detail !== 'string') { try { detail = JSON.stringify(detail); } catch (e2) { detail = 'HTTP ' + res.status; } }
      var err = new Error(detail);
      err.status = res.status;
      throw err;
    }
    return data;
  }

  function fmtTime(value) {
    if (!value) return '—';
    var d = new Date(value);
    if (isNaN(d.getTime())) return String(value);
    return d.toLocaleString();
  }

  function list(items, empty) {
    var arr = Array.isArray(items) ? items.filter(function (x) { return x !== null && x !== undefined && x !== ''; }) : [];
    if (!arr.length) return '<div class="aip-note">' + esc(empty || 'None recorded.') + '</div>';
    return '<ul class="aip-list">' + arr.map(function (x) {
      return '<li>' + esc(typeof x === 'string' ? x : JSON.stringify(x)) + '</li>';
    }).join('') + '</ul>';
  }

  function checkRow(label, value, notRunText) {
    var ico = '—', cls = 'aip-chip';
    if (value === true) { ico = '✓'; cls = 'ok'; }
    else if (value === false) { ico = '✗'; cls = 'bad'; }
    var color = value === true ? '#4ade80' : value === false ? '#ef4444' : 'var(--text3)';
    var text = value === true ? 'pass' : value === false ? 'fail' : (notRunText || 'not run');
    return '<div class="aip-check"><span class="ico" style="color:' + color + '">' + ico + '</span>' +
      '<span style="color:var(--text2);min-width:200px">' + esc(label) + '</span>' +
      '<span style="color:' + color + '">' + esc(text) + '</span></div>';
  }

  // Minimal LCS-free line diff — good enough to show what a regeneration changed.
  function diffLines(before, after) {
    var a = String(before || '').split('\n');
    var b = String(after || '').split('\n');
    var setA = {}, i;
    for (i = 0; i < a.length; i++) setA[a[i]] = (setA[a[i]] || 0) + 1;
    var setB = {};
    for (i = 0; i < b.length; i++) setB[b[i]] = (setB[b[i]] || 0) + 1;
    var out = [];
    for (i = 0; i < a.length; i++) {
      if (!setB[a[i]]) out.push('<div class="del">- ' + esc(a[i]) + '</div>');
    }
    for (i = 0; i < b.length; i++) {
      if (!setA[b[i]]) out.push('<div class="add">+ ' + esc(b[i]) + '</div>');
    }
    if (!out.length) out.push('<div class="ctx">No line-level differences.</div>');
    return out.join('');
  }

  // ── panel instance ───────────────────────────────────────────────────────

  var seq = 0;

  function Panel(container, opts) {
    this.el = container;
    this.surface = opts.surface;
    this.attackId = opts.attackId;
    this.runId = opts.runId || null;
    this.uid = 'aip' + (++seq);
    this.state = null;
    this.tab = 'overview';
    this.busy = false;
    this.edits = {};
    this.error = '';
  }

  Panel.prototype.path = function () {
    var p = '/api/ai/rule-suggestions/by-attack/' +
      encodeURIComponent(this.surface) + '/' + encodeURIComponent(this.attackId);
    return this.runId ? p + '?validation_run_id=' + encodeURIComponent(this.runId) : p;
  };

  Panel.prototype.load = async function () {
    this.renderLoading('Loading AI recommendation state…');
    try {
      this.state = await call('GET', this.path());
      this.error = '';
    } catch (e) {
      this.state = null;
      this.error = e.message;
    }
    this.render();
  };

  Panel.prototype.renderLoading = function (message) {
    this.el.innerHTML =
      '<div class="aip"><div class="aip-head"><span class="aip-title">✦ AI Detection Recommendation</span></div>' +
      '<div class="aip-body"><div class="aip-note ai"><span class="aip-spin"></span> &nbsp;' + esc(message) + '</div></div></div>';
  };

  Panel.prototype.run = async function (fn, message) {
    if (this.busy) return;
    this.busy = true;
    this.renderLoading(message);
    try {
      this.state = await fn();
      this.error = '';
    } catch (e) {
      this.error = e.message;
      // Re-read state so the panel still shows whatever was persisted.
      try { this.state = await call('GET', this.path()); } catch (e2) { /* keep last */ }
    }
    this.busy = false;
    this.edits = {};
    this.render();
  };

  // ── actions ──────────────────────────────────────────────────────────────

  Panel.prototype.generate = function (force) {
    var self = this;
    this.run(function () {
      return call('POST', '/api/ai/rule-suggestions/generate', {
        surface: self.surface, attack_id: self.attackId,
        validation_run_id: self.runId, force_regenerate: !!force
      });
    }, 'Gemini is analyzing sanitized validation evidence…');
  };

  Panel.prototype.validate = function () {
    var id = this.suggestionId();
    this.run(function () {
      return call('POST', '/api/ai/rule-suggestions/' + id + '/validate', {});
    }, 'Validating the draft against Wazuh and the Sigma evaluator…');
  };

  Panel.prototype.saveChanges = function () {
    var id = this.suggestionId();
    var body = {};
    var xml = document.getElementById(this.uid + '-xml');
    var yaml = document.getElementById(this.uid + '-yaml');
    var cur = this.state.current_version || {};
    if (xml && xml.value !== (cur.wazuh_xml || '')) body.wazuh_xml = xml.value;
    if (yaml && yaml.value !== (cur.sigma_yaml || '')) body.sigma_yaml = yaml.value;
    if (!Object.keys(body).length) { alert('No changes to save.'); return; }
    body.comment = 'Edited by the Detection Engineer in the AI panel.';
    this.run(function () {
      return call('PATCH', '/api/ai/rule-suggestions/' + id + '/draft', body);
    }, 'Saving your edits as a new version…');
  };

  Panel.prototype.approve = function () {
    var id = this.suggestionId();
    if (!confirm('Approve this draft?\n\nApproval records your review. It does NOT deploy anything to Wazuh.')) return;
    this.run(function () {
      return call('POST', '/api/ai/rule-suggestions/' + id + '/approve', {});
    }, 'Recording approval…');
  };

  Panel.prototype.saveToPlatform = function () {
    var id = this.suggestionId();
    this.run(function () {
      return call('POST', '/api/ai/rule-suggestions/' + id + '/save-to-platform', {});
    }, 'Saving to the detection store…');
  };

  Panel.prototype.deleteDetection = function () {
    var id = this.suggestionId();
    if (!confirm('Delete the saved AI detection rule?\n\nThis is a testing-only action: it removes the saved detection from the platform (and its Sigma coverage on attack replay) so you can regenerate and save again. It does not affect anything already deployed to Wazuh.')) return;
    this.run(function () {
      return call('DELETE', '/api/ai/rule-suggestions/' + id + '/platform-save', {});
    }, 'Deleting the saved detection…');
  };

  Panel.prototype.copyRule = function (kind) {
    var el = document.getElementById(this.uid + (kind === 'sigma' ? '-yaml' : '-xml'));
    if (!el) return;
    var done = function () {
      var btn = document.getElementById(this.uid + '-copy-' + kind);
      if (btn) { var old = btn.textContent; btn.textContent = 'Copied'; setTimeout(function () { btn.textContent = old; }, 1400); }
    }.bind(this);
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(el.value).then(done, function () { el.select(); document.execCommand('copy'); done(); });
    } else { el.select(); document.execCommand('copy'); done(); }
  };

  Panel.prototype.suggestionId = function () {
    return this.state && this.state.suggestion ? this.state.suggestion.suggestion_id : null;
  };

  // ── reject & regenerate modal ────────────────────────────────────────────

  Panel.prototype.openFeedback = function () {
    var self = this;
    var bg = document.createElement('div');
    bg.className = 'aip-modal-bg';
    bg.innerHTML =
      '<div class="aip-modal">' +
        '<div class="aip-title" style="margin-bottom:6px">✦ Reject &amp; Regenerate</div>' +
        '<div class="aip-note">Your feedback is sent to Gemini with the current draft. ' +
        'A new version is created — the existing version is preserved and stays in the history.</div>' +
        '<div class="aip-lbl">What should change? (required)</div>' +
        '<textarea class="aip-ta" id="' + self.uid + '-fb" placeholder="e.g. Exclude the approved scanner 10.10.10.50 and require five matching events within 60 seconds."></textarea>' +
        '<div class="aip-lbl">Examples</div>' +
        '<ul class="aip-list" style="font-size:11.5px">' +
          '<li>Require five events within 60 seconds.</li>' +
          '<li>Exclude approved scanner 10.10.10.50.</li>' +
          '<li>Use Windows Event ID 4769 and encryption type 0x17.</li>' +
          '<li>Require the LFI path pattern instead of only the ModSecurity message.</li>' +
          '<li>Use auditd execve telemetry instead of matching only process names.</li>' +
        '</ul>' +
        '<div style="display:flex;gap:8px;margin-top:14px;justify-content:flex-end">' +
          '<button class="aip-btn" id="' + self.uid + '-fb-cancel">Cancel</button>' +
          '<button class="aip-btn red" id="' + self.uid + '-fb-reject">Reject only</button>' +
          '<button class="aip-btn primary" id="' + self.uid + '-fb-go">Regenerate with feedback</button>' +
        '</div>' +
      '</div>';
    document.body.appendChild(bg);
    var close = function () { if (bg.parentNode) bg.parentNode.removeChild(bg); };
    bg.addEventListener('click', function (e) { if (e.target === bg) close(); });
    document.getElementById(self.uid + '-fb-cancel').onclick = close;

    document.getElementById(self.uid + '-fb-reject').onclick = function () {
      var text = document.getElementById(self.uid + '-fb').value.trim();
      if (!text) { alert('A reason is required to reject a draft.'); return; }
      var id = self.suggestionId();
      close();
      self.run(function () {
        return call('POST', '/api/ai/rule-suggestions/' + id + '/reject', { reason: text });
      }, 'Recording the rejection…');
    };

    document.getElementById(self.uid + '-fb-go').onclick = function () {
      var text = document.getElementById(self.uid + '-fb').value.trim();
      if (!text) { alert('Feedback is required to regenerate a draft.'); return; }
      var id = self.suggestionId();
      var previous = self.state.current_version || {};
      close();
      self.pendingDiffBase = {
        wazuh_xml: previous.wazuh_xml || '', sigma_yaml: previous.sigma_yaml || '',
        version_number: previous.version_number
      };
      self.run(function () {
        return call('POST', '/api/ai/rule-suggestions/' + id + '/regenerate', { feedback: text });
      }, 'Gemini is revising the draft with your feedback…');
    };

    setTimeout(function () { var t = document.getElementById(self.uid + '-fb'); if (t) t.focus(); }, 40);
  };

  // ── deployment confirmation ──────────────────────────────────────────────

  Panel.prototype.openDeploy = async function () {
    var self = this;
    var id = this.suggestionId();
    var preview;
    try {
      preview = await call('GET', '/api/ai/rule-suggestions/' + id + '/deployment-preview');
    } catch (e) {
      alert('Cannot prepare deployment: ' + e.message);
      return;
    }
    var rules = (preview.rules || []).map(function (r) {
      return '<div class="aip-row"><div class="k">Rule ' + esc(r.rule_id) + '</div><div class="v">' +
        esc(r.title) + ' <span style="color:var(--text3)">(level ' + esc(r.level) + ')</span></div></div>';
    }).join('') || '<div class="aip-note bad">No rule found in the draft.</div>';

    var bg = document.createElement('div');
    bg.className = 'aip-modal-bg';
    bg.innerHTML =
      '<div class="aip-modal">' +
        '<div class="aip-title" style="margin-bottom:8px">Deploy to Wazuh — confirm</div>' +
        '<div class="aip-row"><div class="k">Target manager</div><div class="v">' + esc(preview.manager) + '</div></div>' +
        '<div class="aip-row"><div class="k">Target file</div><div class="v">' + esc(preview.target_file) + '</div></div>' +
        rules +
        '<div class="aip-row"><div class="k">Validation</div><div class="v">' +
          ((preview.validation_status && preview.validation_status.ready_for_deployment)
            ? '<span style="color:#4ade80">passed — ready for deployment</span>'
            : '<span style="color:#ef4444">not ready</span>') +
        '</div></div>' +
        '<div class="aip-note warn" style="margin-top:12px">⚠ ' + esc(preview.warning) + '<br>' +
        'A timestamped backup of the current managed rules file is taken first. If validation or the health check fails, the backup is restored automatically.</div>' +
        '<div class="aip-note">After deploying, re-run the original attack and re-validate. Deployment alone does not prove the gap is closed.</div>' +
        '<div style="display:flex;gap:8px;margin-top:14px;justify-content:flex-end">' +
          '<button class="aip-btn" id="' + self.uid + '-dep-cancel">Cancel</button>' +
          '<button class="aip-btn primary" id="' + self.uid + '-dep-go"' +
            ((preview.validation_status && preview.validation_status.ready_for_deployment && preview.may_deploy) ? '' : ' disabled') +
            '>Confirm &amp; deploy</button>' +
        '</div>' +
      '</div>';
    document.body.appendChild(bg);
    var close = function () { if (bg.parentNode) bg.parentNode.removeChild(bg); };
    bg.addEventListener('click', function (e) { if (e.target === bg) close(); });
    document.getElementById(self.uid + '-dep-cancel').onclick = close;
    var go = document.getElementById(self.uid + '-dep-go');
    if (go) go.onclick = function () {
      close();
      self.run(function () {
        return call('POST', '/api/ai/rule-suggestions/' + id + '/deploy-to-wazuh',
                    { confirm: true });
      }, 'Backing up, staging, validating and reloading the Wazuh Manager…');
    };
  };

  // ── render ───────────────────────────────────────────────────────────────

  Panel.prototype.render = function () {
    var s = this.state;
    var self = this;

    if (!s) {
      this.el.innerHTML =
        '<div class="aip"><div class="aip-head"><span class="aip-title">✦ AI Detection Recommendation</span></div>' +
        '<div class="aip-body"><div class="aip-note bad">' +
        esc(this.error || 'Could not load the AI recommendation state for this attack.') +
        '</div></div></div>';
      return;
    }

    var decision = s.decision || {};
    var provider = s.provider || {};
    var perms = s.permissions || {};
    var sugg = s.suggestion;
    var cur = s.current_version;
    var validation = cur ? cur.validation_result : null;

    // header chips
    var chips = [];
    chips.push('<span class="aip-chip ai">' + esc(provider.provider || 'gemini') + '</span>');
    chips.push('<span class="aip-chip">' + esc(provider.model || 'model not set') + '</span>');
    chips.push('<span class="aip-chip">gap: ' + esc(decision.gap_type || '—') + '</span>');
    if (sugg) {
      var statusCls = ({ deployed: 'ok', approved: 'ok', ready_for_review: 'ok',
                         rejected: 'bad', validation_failed: 'bad', deployment_failed: 'bad',
                         rolled_back: 'warn', revision_requested: 'warn' })[sugg.status] || '';
      chips.push('<span class="aip-chip ' + statusCls + '">' + esc(sugg.status) + '</span>');
      if (sugg.confidence !== null && sugg.confidence !== undefined) {
        chips.push('<span class="aip-chip">confidence ' + esc(sugg.confidence) + '%</span>');
      }
      chips.push('<span class="aip-chip">v' + esc(sugg.current_version) + '</span>');
    } else {
      chips.push('<span class="aip-chip">not requested</span>');
    }

    var head =
      '<div class="aip-head"><span class="aip-title">✦ AI Detection Recommendation</span>' +
      '<div class="aip-meta">' + chips.join('') + '</div></div>';

    var body = '';

    if (this.error) {
      body += '<div class="aip-note bad">' + esc(this.error) + '</div>';
    }
    if (s.message) {
      var deployFailed = s.deployment && s.deployment.success === false;
      body += '<div class="aip-note ' + (deployFailed ? 'bad' : 'green') + '">' + esc(s.message) + '</div>';
    }

    // ── A. verified coverage — nothing to generate ─────────────────────────
    if (decision.gap_type === 'none') {
      body += '<div class="aip-note green">' + esc(decision.message) + '</div>';
      body += '<div class="aip-note">' + esc(decision.reason) + '</div>';
      var canReviewNone = !!perms.may_review;
      if ((s.platform_saves || []).length && sugg && sugg.status === 'saved_to_platform') {
        body += '<div class="aip-actions">' +
          '<button class="aip-btn red" id="' + this.uid + '-delete-detection" ' +
          'title="Testing only — deletes the saved detection so you can regenerate and re-save."' +
          (canReviewNone ? '' : ' disabled') + '>Delete AI Detection Rule</button></div>';
      }
      this.el.innerHTML = '<div class="aip">' + head + '<div class="aip-body">' + body + '</div></div>';
      var delBtnNone = document.getElementById(this.uid + '-delete-detection');
      if (delBtnNone) delBtnNone.onclick = function () { self.deleteDetection(); };
      return;
    }

    // ── G. incomplete validation / Wazuh unavailable ───────────────────────
    if (decision.gap_type === 'incomplete') {
      body += '<div class="aip-note warn">' + esc(decision.message) + '</div>';
      body += '<div class="aip-note">' + esc(decision.reason) + '</div>';
      if (s.wazuh_health && s.wazuh_health.reason) {
        body += '<div class="aip-note">Wazuh pipeline: ' + esc(s.wazuh_health.reason) + '</div>';
      }
      this.el.innerHTML = '<div class="aip">' + head + '<div class="aip-body">' + body + '</div></div>';
      return;
    }

    // ── no draft yet, or the last draft was rejected — offer generation ────
    var wasRejected = !!(sugg && sugg.status === 'rejected');
    if (!sugg || !cur || wasRejected) {
      if (wasRejected) {
        body += '<div class="aip-note bad">The previous draft (v' + esc(sugg.current_version) + ') was rejected' +
          (s.last_action && s.last_action.comment ? ': ' + esc(s.last_action.comment) : '.') +
          (s.last_action ? ' — by ' + esc(s.last_action.actor || 'unknown') + ' · ' +
            esc(fmtTime(s.last_action.created_at)) : '') + '</div>';
      }
      body += '<div class="aip-note ai">' + esc(decision.message) + '</div>';
      body += '<div class="aip-note">' + esc(decision.reason) + '</div>';
      if (decision.gap_type === 'telemetry' || decision.gap_type === 'evaluator') {
        body += '<div class="aip-note warn">Approval and deployment stay disabled for this state — ' +
          'the recommendation will be guidance, not a deployable rule.</div>';
      }
      body += '<div class="aip-note">' + esc(provider.notice || '') + '</div>';
      if (!provider.enabled || !provider.configured) {
        body += '<div class="aip-note bad">' + esc(provider.reason || 'Gemini is not available.') + '</div>';
      }
      if (!perms.authenticated) {
        body += '<div class="aip-note warn">Sign in to generate a recommendation.</div>';
      }
      body += '<div class="aip-actions">' +
        '<button class="aip-btn primary" id="' + this.uid + '-gen"' +
        (perms.can_generate ? '' : ' disabled') + '>✦ Generate Recommended Rule</button></div>';
      this.el.innerHTML = '<div class="aip">' + head + '<div class="aip-body">' + body + '</div></div>';
      var genBtn = document.getElementById(this.uid + '-gen');
      if (genBtn) genBtn.onclick = function () { genBtn.disabled = true; self.generate(wasRejected); };
      return;
    }

    // ── draft present — tabbed view ────────────────────────────────────────
    var hasWazuh = !!(cur.wazuh_xml && cur.wazuh_xml.trim());
    var hasSigma = !!(cur.sigma_yaml && cur.sigma_yaml.trim());
    var hasTelemetry = !!(cur.telemetry_recommendations && cur.telemetry_recommendations.length);

    // No Wazuh/Sigma rule was drafted (e.g. the evaluator had nothing to test
    // against, or telemetry is missing) — this is guidance-only by design,
    // but nothing else on this screen says so, so say it up front.
    if (!hasWazuh && !hasSigma) {
      body += '<div class="aip-note warn">' + esc(decision.message) + '</div>';
      body += '<div class="aip-note">' + esc(decision.reason) + '</div>';
      body += '<div class="aip-note">No Wazuh or Sigma rule was drafted for this recommendation' +
        (hasTelemetry ? ' — see the Telemetry tab for what to fix.' : '.') + '</div>';
    }

    var tabs = [['overview', 'Overview'], ['wazuh', 'Wazuh XML'], ['sigma', 'Sigma YAML']];
    if (hasTelemetry) tabs.push(['telemetry', 'Telemetry']);
    tabs.push(['fp', 'False Positives']);
    tabs.push(['validation', 'Validation']);
    tabs.push(['history', 'Version History']);
    if (!tabs.some(function (t) { return t[0] === self.tab; })) self.tab = 'overview';

    body += '<div class="aip-tabs">' + tabs.map(function (t) {
      return '<button class="aip-tab' + (t[0] === self.tab ? ' active' : '') +
        '" data-aiptab="' + t[0] + '">' + esc(t[1]) + '</button>';
    }).join('') + '</div>';

    // Overview
    var ov = '';
    ov += '<div class="aip-note ai">' + esc(cur.summary || '') + '</div>';
    if (cur.reasoning_summary) ov += '<div class="aip-note">' + esc(cur.reasoning_summary) + '</div>';
    ov += '<div class="aip-row"><div class="k">Deterministic verdict</div><div class="v">' +
      esc(decision.verdict) + ' <span style="color:var(--text3)">(engine: ' + esc(decision.raw_verdict) + ')</span></div></div>';
    ov += '<div class="aip-row"><div class="k">Gap type</div><div class="v">' + esc(decision.gap_type) + '</div></div>';
    ov += '<div class="aip-row"><div class="k">MITRE</div><div class="v">' +
      esc((cur.mitre && cur.mitre.technique_id) || '—') + ' ' +
      esc((cur.mitre && cur.mitre.technique_name) || '') + '</div></div>';
    ov += '<div class="aip-row"><div class="k">Provider / model</div><div class="v">' +
      esc(sugg.provider) + ' · ' + esc(sugg.model || '—') + '</div></div>';
    ov += '<div class="aip-row"><div class="k">Current version</div><div class="v">v' +
      esc(cur.version_number) + ' (' + esc(cur.origin) + ')</div></div>';
    ov += '<div class="aip-row"><div class="k">Created</div><div class="v">' +
      esc(fmtTime(cur.generated_at)) + ' by ' + esc(cur.generated_by || 'unknown') + '</div></div>';
    var last = s.last_action;
    ov += '<div class="aip-row"><div class="k">Last engineer action</div><div class="v">' +
      (last ? esc(last.action) + ' · ' + esc(last.actor || 'unknown') + ' · ' + esc(fmtTime(last.created_at)) +
        (last.comment ? ' — ' + esc(last.comment) : '')
        : '—') + '</div></div>';
    ov += '<div class="aip-lbl">Assumptions</div>' + list(cur.assumptions, 'No assumptions recorded.');
    ov += '<div class="aip-lbl">Required data sources</div>' + list(cur.required_data_sources, 'None recorded.');
    ov += '<div class="aip-lbl">Deployment risks</div>' + list(cur.deployment_risks, 'None recorded.');
    ov += '<div class="aip-note" style="margin-top:12px">' + esc(provider.notice || '') + '</div>';

    body += '<div class="aip-pane' + (self.tab === 'overview' ? ' active' : '') + '" data-aippane="overview">' + ov + '</div>';

    body += '<div class="aip-pane' + (self.tab === 'wazuh' ? ' active' : '') + '" data-aippane="wazuh">' +
      (hasWazuh
        ? ('<div class="aip-lbl">Wazuh rule XML — editable</div>' +
           '<textarea class="aip-code" id="' + this.uid + '-xml" spellcheck="false">' + esc(cur.wazuh_xml) + '</textarea>' +
           '<div class="aip-lbl">Expected fields</div>' + list((cur.wazuh_meta || {}).expected_fields, 'Not specified.') +
           ((cur.wazuh_meta || {}).test_event
             ? '<div class="aip-lbl">Suggested test event</div><div class="aip-pre">' + esc(cur.wazuh_meta.test_event) + '</div>'
             : ''))
        : ('<div class="aip-note warn">No Wazuh rule was drafted for this recommendation.</div>' +
           '<div class="aip-note">' + esc(decision.message || '') + '</div>' +
           '<div class="aip-note">' + esc(decision.reason || '') + '</div>')) +
      '</div>';
    body += '<div class="aip-pane' + (self.tab === 'sigma' ? ' active' : '') + '" data-aippane="sigma">' +
      (hasSigma
        ? ('<div class="aip-lbl">Sigma rule YAML — editable</div>' +
           '<textarea class="aip-code" id="' + this.uid + '-yaml" spellcheck="false">' + esc(cur.sigma_yaml) + '</textarea>' +
           ((cur.sigma_meta || {}).logsource_explanation
             ? '<div class="aip-lbl">Log source</div><div class="aip-note">' + esc(cur.sigma_meta.logsource_explanation) + '</div>'
             : '') +
           '<div class="aip-lbl">Expected fields</div>' + list((cur.sigma_meta || {}).expected_fields, 'Not specified.'))
        : ('<div class="aip-note warn">No Sigma rule was drafted for this recommendation.</div>' +
           '<div class="aip-note">' + esc(decision.message || '') + '</div>' +
           '<div class="aip-note">' + esc(decision.reason || '') + '</div>')) +
      '</div>';
    if (hasTelemetry) {
      var tel = (cur.telemetry_recommendations || []).map(function (t) {
        return '<div style="border:1px solid var(--border);border-radius:8px;padding:11px;margin-bottom:9px">' +
          '<div style="font-family:var(--mono);font-size:12px;color:#c4a4ff;margin-bottom:6px">' + esc(t.source) + '</div>' +
          '<div class="aip-row"><div class="k">Problem</div><div class="v">' + esc(t.problem) + '</div></div>' +
          '<div class="aip-row"><div class="k">Configuration</div><div class="v"><span style="font-family:var(--mono);color:#60a5fa">' + esc(t.configuration) + '</span></div></div>' +
          '<div class="aip-row"><div class="k">Verify with</div><div class="v"><span style="font-family:var(--mono);color:#60a5fa">' + esc(t.verification) + '</span></div></div>' +
          '</div>';
      }).join('');
      body += '<div class="aip-pane' + (self.tab === 'telemetry' ? ' active' : '') + '" data-aippane="telemetry">' +
        '<div class="aip-note warn">Approval and deployment stay disabled until the telemetry below is actually reaching Wazuh.</div>' +
        tel + '</div>';
    }

    var telSources = ((s.telemetry || {}).sources || []).map(function (src) {
      var cls = src.tracked ? (src.healthy ? 'ok' : 'bad') : '';
      return '<span class="aip-chip ' + cls + '">' + esc(src.name) + ': ' + esc(src.status) + '</span>';
    }).join(' ');

    body += '<div class="aip-pane' + (self.tab === 'fp' ? ' active' : '') + '" data-aippane="fp">' +
      '<div class="aip-lbl">Known false positives</div>' + list(cur.false_positives, 'None documented.') +
      '<div class="aip-lbl">Tuning recommendations</div>' + list(cur.tuning_notes, 'None documented.') +
      '<div class="aip-lbl">Telemetry health</div>' +
      '<div class="aip-note' + ((s.telemetry || {}).available ? '' : ' warn') + '">' +
      esc((s.telemetry || {}).reason || '') + '</div>' +
      '<div style="display:flex;gap:5px;flex-wrap:wrap">' + telSources + '</div>' +
      '</div>';

    // Validation pane
    var vp = '';
    if (!validation) {
      vp += '<div class="aip-note">This version has not been validated yet. Click "Validate Draft".</div>';
    } else {
      if (validation.errors && validation.errors.length) {
        vp += '<div class="aip-note bad">' + esc(validation.errors.join(' • ')) + '</div>';
      }
      if (validation.warnings && validation.warnings.length) {
        vp += '<div class="aip-note warn">' + esc(validation.warnings.join(' • ')) + '</div>';
      }
      ['wazuh', 'sigma'].forEach(function (kind) {
        var r = validation[kind];
        if (!r) return;
        var relevant = (kind === 'wazuh' && hasWazuh) || (kind === 'sigma' && hasSigma);
        if (!relevant) return;
        vp += '<div class="aip-lbl">' + (kind === 'wazuh' ? 'Wazuh XML' : 'Sigma YAML') + ' checks</div>';
        vp += checkRow('syntax_valid', r.syntax_valid);
        vp += checkRow('schema_valid', r.schema_valid);
        vp += checkRow('rule_id_available', r.rule_id_available, 'not applicable');
        vp += checkRow('fields_supported', r.fields_supported);
        vp += checkRow('duplicate_check_passed', r.duplicate_check_passed);
        vp += checkRow('telemetry_available', r.telemetry_available);
        vp += checkRow('positive_test_executed', r.positive_test_executed);
        vp += checkRow('positive_test_matched', r.positive_test_matched, 'test did not run');
        vp += checkRow('negative_test_executed', r.negative_test_executed);
        vp += checkRow('negative_test_passed', r.negative_test_passed, 'test did not run');
        vp += checkRow('ready_for_review', r.ready_for_review);
        vp += checkRow('ready_for_deployment', r.ready_for_deployment);
        if (r.evaluator_status === 'EVALUATOR_UNSUPPORTED') {
          vp += '<div class="aip-note warn">Sigma evaluator limitation — not a failed rule.</div>';
        }
        if (r.notes && r.notes.length) {
          vp += '<div class="aip-note">' + esc(r.notes.join(' • ')) + '</div>';
        }
      });
    }
    body += '<div class="aip-pane' + (self.tab === 'validation' ? ' active' : '') + '" data-aippane="validation">' + vp + '</div>';

    // History pane (+ diff after a regeneration)
    var hp = '';
    if (this.pendingDiffBase && cur.version_number !== this.pendingDiffBase.version_number) {
      hp += '<div class="aip-lbl">Changes from v' + esc(this.pendingDiffBase.version_number) +
        ' → v' + esc(cur.version_number) + '</div>';
      hp += '<div class="aip-diff">' +
        diffLines(this.pendingDiffBase.wazuh_xml + '\n' + this.pendingDiffBase.sigma_yaml,
                  (cur.wazuh_xml || '') + '\n' + (cur.sigma_yaml || '')) + '</div>';
    }
    hp += '<div class="aip-lbl">Versions</div>';
    hp += (s.versions || []).map(function (v) {
      return '<div class="aip-hist"><span class="aip-vbadge">v' + esc(v.version_number) + '</span>' +
        '<div style="flex:1"><div style="color:var(--text)">' + esc(v.summary || '—') + '</div>' +
        '<div style="font-family:var(--mono);font-size:10.5px;color:var(--text3)">' +
        esc(v.origin) + ' · ' + esc(fmtTime(v.generated_at)) + ' · ' + esc(v.generated_by || 'unknown') +
        (v.confidence !== null && v.confidence !== undefined ? ' · confidence ' + esc(v.confidence) + '%' : '') +
        '</div>' +
        (v.engineer_feedback ? '<div style="font-size:11.5px;color:#f59e0b;margin-top:3px">Feedback: ' + esc(v.engineer_feedback) + '</div>' : '') +
        '</div></div>';
    }).join('') || '<div class="aip-note">No versions yet.</div>';
    hp += '<div class="aip-lbl">Audit trail</div>';
    hp += (s.actions || []).map(function (a) {
      return '<div class="aip-hist"><span class="aip-vbadge">' + esc(a.action) + '</span>' +
        '<div style="flex:1"><div style="font-family:var(--mono);font-size:10.5px;color:var(--text3)">' +
        esc(a.actor || 'unknown') + ' · ' + esc(fmtTime(a.created_at)) + '</div>' +
        (a.comment ? '<div style="font-size:11.5px;color:var(--text2)">' + esc(a.comment) + '</div>' : '') +
        '</div></div>';
    }).join('') || '<div class="aip-note">No actions recorded.</div>';
    if ((s.platform_saves || []).length) {
      hp += '<div class="aip-lbl">Saved to platform</div>' +
        s.platform_saves.map(function (p) {
          return '<div class="aip-hist"><span class="aip-vbadge">#' + esc(p.detection_id) + '</span>' +
            '<div style="flex:1;font-family:var(--mono);font-size:10.5px;color:var(--text3)">version ' +
            esc(p.version_id) + ' · ' + esc(fmtTime(p.created_at)) + '</div></div>';
        }).join('');
    }
    body += '<div class="aip-pane' + (self.tab === 'history' ? ' active' : '') + '" data-aippane="history">' + hp + '</div>';

    // ── action bar ────────────────────────────────────────────────────────
    var readyReview = !!(validation && validation.ready_for_review);
    var readyDeploy = !!(validation && validation.ready_for_deployment);
    var canApprove = !!perms.can_approve && readyReview;
    var canDeploy = !!perms.can_deploy && readyDeploy && hasWazuh &&
                    !!(s.telemetry || {}).available;
    var canReview = !!perms.may_review;

    var acts = '<div class="aip-actions">';
    acts += '<button class="aip-btn blue" id="' + this.uid + '-val">Validate Draft</button>';
    if (canReview && (hasWazuh || hasSigma)) {
      acts += '<button class="aip-btn" id="' + this.uid + '-save">Save Changes</button>';
    }
    if (hasWazuh) acts += '<button class="aip-btn" id="' + this.uid + '-copy-wazuh">Copy Wazuh Rule</button>';
    if (hasSigma) acts += '<button class="aip-btn" id="' + this.uid + '-copy-sigma">Copy Sigma Rule</button>';
    if (hasWazuh || hasSigma) {
      acts += '<button class="aip-btn green" id="' + this.uid + '-platform"' +
        (canReview ? '' : ' disabled') + '>Save to Platform</button>';
    }
    if ((s.platform_saves || []).length && sugg && sugg.status === 'saved_to_platform') {
      acts += '<button class="aip-btn red" id="' + this.uid + '-delete-detection" ' +
        'title="Testing only — deletes the saved detection so you can regenerate and re-save."' +
        (canReview ? '' : ' disabled') + '>Delete AI Detection Rule</button>';
    }
    acts += '<button class="aip-btn green" id="' + this.uid + '-approve"' +
      (canApprove ? '' : ' disabled') + '>Approve Draft</button>';
    if (hasWazuh) {
      acts += '<button class="aip-btn primary" id="' + this.uid + '-deploy"' +
        (canDeploy ? '' : ' disabled') + '>Deploy to Wazuh</button>';
    }
    acts += '<button class="aip-btn red" id="' + this.uid + '-reject"' +
      (canReview ? '' : ' disabled') + '>Reject &amp; Regenerate</button>';
    acts += '</div>';

    if (!canApprove) {
      var whyApprove = [];
      if (!perms.may_review) whyApprove.push('your role may not approve drafts');
      else if (!decision.approval_allowed) whyApprove.push(decision.message || 'this recommendation cannot be approved as a deployable rule');
      else if (!readyReview) whyApprove.push('the draft has not passed validation yet — click "Validate Draft"');
      if (whyApprove.length) {
        var whyApproveText = whyApprove.join('; ');
        acts += '<div class="aip-note warn" style="margin-top:9px">Approval is disabled — ' +
          esc(whyApproveText) + (/[.!?]$/.test(whyApproveText) ? '' : '.') + '</div>';
      }
    }
    if (!canDeploy && hasWazuh) {
      var why = [];
      if (!perms.may_deploy) why.push('your role may not deploy to Wazuh');
      if (!readyDeploy) why.push('the draft has not passed Wazuh XML validation');
      if (!(s.telemetry || {}).available) why.push('the required telemetry is not available');
      acts += '<div class="aip-note warn" style="margin-top:9px">Deployment is disabled — ' +
        esc(why.join('; ')) + '.</div>';
    }
    body += acts;

    this.el.innerHTML = '<div class="aip">' + head + '<div class="aip-body">' + body + '</div></div>';
    this.bind();
  };

  Panel.prototype.bind = function () {
    var self = this;
    var root = this.el;

    root.querySelectorAll('[data-aiptab]').forEach(function (btn) {
      btn.onclick = function () {
        self.tab = btn.getAttribute('data-aiptab');
        root.querySelectorAll('[data-aiptab]').forEach(function (b) {
          b.classList.toggle('active', b === btn);
        });
        root.querySelectorAll('[data-aippane]').forEach(function (p) {
          p.classList.toggle('active', p.getAttribute('data-aippane') === self.tab);
        });
      };
    });

    var on = function (id, fn) {
      var el = document.getElementById(self.uid + '-' + id);
      if (el) el.onclick = function () { if (!el.disabled) fn(); };
    };
    on('val', function () { self.validate(); });
    on('save', function () { self.saveChanges(); });
    on('copy-wazuh', function () { self.copyRule('wazuh'); });
    on('copy-sigma', function () { self.copyRule('sigma'); });
    on('platform', function () { self.saveToPlatform(); });
    on('delete-detection', function () { self.deleteDetection(); });
    on('approve', function () { self.approve(); });
    on('deploy', function () { self.openDeploy(); });
    on('reject', function () { self.openFeedback(); });
  };

  // ── public API ───────────────────────────────────────────────────────────

  var AIPanel = {
    /**
     * Mount the panel into `container` for one attack.
     * @param {HTMLElement|string} container element or element id
     * @param {{surface:string, attackId:string, runId?:string}} opts
     */
    mount: function (container, opts) {
      injectStyle();
      var el = (typeof container === 'string') ? document.getElementById(container) : container;
      if (!el || !opts || !opts.surface || !opts.attackId) return null;
      if (el.getAttribute('data-aip-mounted') === opts.surface + '|' + opts.attackId + '|' + (opts.runId || '')) {
        return el.__aipPanel || null;
      }
      el.setAttribute('data-aip-mounted', opts.surface + '|' + opts.attackId + '|' + (opts.runId || ''));
      var panel = new Panel(el, opts);
      el.__aipPanel = panel;
      panel.load();
      return panel;
    },

    /** Create the empty host div markup a renderer can drop into its HTML. */
    placeholder: function (id) {
      return '<div id="' + esc(id) + '" class="aip-host"></div>';
    },

    /** Mount every placeholder produced by mountLater(). */
    mountPending: function (root) {
      var scope = root || document;
      scope.querySelectorAll('.aip-host[data-aip-surface]').forEach(function (el) {
        AIPanel.mount(el, {
          surface: el.getAttribute('data-aip-surface'),
          attackId: el.getAttribute('data-aip-attack'),
          runId: el.getAttribute('data-aip-run') || null
        });
      });
    },

    /** Markup for a deferred mount — call mountPending() after insertion. */
    host: function (surface, attackId, runId) {
      return '<div class="aip-host" data-aip-surface="' + esc(surface) +
        '" data-aip-attack="' + esc(attackId) +
        '" data-aip-run="' + esc(runId || '') + '"></div>';
    },

    escape: esc
  };

  global.AIPanel = AIPanel;
})(window);
