(function () {
  'use strict';

  // ---- live status ----
  // While something is in flight (body[data-busy]) poll /api/status and, when it changes, re-fetch this page and
  // swap only the [data-live] regions. Forms outside those regions keep whatever the user typed.
  // Without JavaScript the <noscript> meta refresh in base.html does the same job more bluntly.
  function busy(j) {
    var t = j.task && j.task.status, k;
    if (t === 'queued' || t === 'running') return true;
    for (k in j.apps) if (/^(queued|signing|downloading|uploading)$/.test(j.apps[k])) return true;
    return false;
  }
  function swap() {
    return fetch(location.href, { cache: 'no-store' }).then(function (r) { return r.text(); }).then(function (html) {
      var doc = new DOMParser().parseFromString(html, 'text/html');
      document.querySelectorAll('[data-live]').forEach(function (el) {
        var fresh = el.id && doc.getElementById(el.id);
        if (fresh && fresh.innerHTML !== el.innerHTML) el.innerHTML = fresh.innerHTML;
      });
    });
  }
  if (document.body.hasAttribute('data-busy') && window.fetch && window.DOMParser) {
    var last = null;   // null: always swap once, the state may have moved on while this page was loading
    var tick = function () {
      fetch('/api/status', { cache: 'no-store' }).then(function (r) { return r.json(); }).then(function (j) {
        var s = JSON.stringify(j), again = busy(j);
        var done = function () { if (again) setTimeout(tick, 2000); };
        if (s === last) return done();
        last = s;
        return swap().then(done);
      }).catch(function () { setTimeout(tick, 5000); });
    };
    setTimeout(tick, 1200);
  }

  // ---- upload form: file label, drag highlight, progress bar ----
  var f = document.getElementById('up');
  if (!f) return;
  var inp = document.getElementById('ipa'), drop = inp.parentNode,
      title = document.getElementById('ipa-title'), hint = document.getElementById('ipa-hint'),
      idle = [title.textContent, hint.textContent], btn = f.querySelector('button[type=submit]');
  function size(n) {
    var u = ['B', 'KB', 'MB', 'GB'], i = 0;
    while (n >= 1024 && i < 3) { n /= 1024; i++; }
    return (i ? n.toFixed(1) : n) + ' ' + u[i];
  }
  inp.addEventListener('change', function () {
    var file = inp.files[0];
    drop.classList.toggle('has', !!file);
    title.textContent = file ? file.name : idle[0];
    hint.textContent = file ? size(file.size) + ' · tap to change' : idle[1];
  });
  ['dragenter', 'dragover'].forEach(function (ev) { drop.addEventListener(ev, function () { drop.classList.add('over'); }); });
  ['dragleave', 'dragend', 'drop'].forEach(function (ev) { drop.addEventListener(ev, function () { drop.classList.remove('over'); }); });

  f.addEventListener('submit', function (e) {
    if (!window.FormData || !inp.files.length) return;      // URL-only uploads: normal submit
    e.preventDefault();
    var p = document.getElementById('prog'), bar = p.querySelector('div'), txt = p.querySelector('span');
    p.hidden = false; btn.disabled = true; txt.textContent = 'Uploading…';
    var x = new XMLHttpRequest();
    x.open('POST', '/upload');
    x.upload.onprogress = function (ev) {
      if (!ev.lengthComputable) return;
      var pc = Math.round(ev.loaded / ev.total * 100);
      bar.style.width = pc + '%'; txt.textContent = pc < 100 ? 'Uploading ' + pc + '%' : 'Reading app…';
    };
    var fail = function (why) { txt.textContent = 'Upload failed - ' + why; bar.style.width = 0; btn.disabled = false; };
    x.onload = function () {
      if (x.status >= 400) fail((x.responseText || 'error ' + x.status).slice(0, 80));
      else location.href = x.responseURL || '/';
    };
    x.onerror = function () { fail('check Tailscale and try again'); };
    x.send(new FormData(f));
  });
})();
