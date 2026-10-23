/* Site-geneli OSCP/Metodoloji filter.
 * - "/" veya floating buton ile açılır; yazdıkça başlıkları filtreler.
 * - Seçim Enter/tık ile ilgili bölüme deep-link atar (#jump=<başlık>).
 * - Hedef sayfada başlık METNİ eşleştirilerek kaydırılır (kramdown id'sine bağımsız).
 */
(function () {
  "use strict";
  var INDEX_URL = window.OSF_INDEX_URL || "/assets/data/oscp-index.json";

  function norm(s) {
    return (s || "").replace(/`/g, "").replace(/\s+/g, " ").trim().toLowerCase();
  }

  /* ---- Hedef sayfada #jump= varsa ilgili başlığa kaydır ---- */
  function handleJump() {
    var h = location.hash || "";
    var m = h.match(/^#jump=(.+)$/);
    if (!m) return;
    var target = norm(decodeURIComponent(m[1]));
    var heads = document.querySelectorAll("h1,h2,h3,h4,h5,h6");
    for (var i = 0; i < heads.length; i++) {
      if (norm(heads[i].textContent) === target) {
        heads[i].scrollIntoView({ behavior: "smooth", block: "start" });
        heads[i].classList.add("osf-flash");
        setTimeout(function (el) { return function () { el.classList.remove("osf-flash"); }; }(heads[i]), 2100);
        break;
      }
    }
  }

  function go(entry) {
    var here = location.pathname.replace(/\/+$/, "");
    var there = entry.u.replace(/\/+$/, "");
    var hash = entry.k ? "#jump=" + encodeURIComponent(entry.k) : "";
    if (here === there) {
      if (entry.k) { location.hash = hash; handleJump(); }
      else { window.scrollTo({ top: 0, behavior: "smooth" }); }
    } else {
      location.href = entry.u + hash;
    }
  }

  /* ---- UI ---- */
  var data = null, fab, overlay, input, results, hint, sel = -1, shown = [];

  function build() {
    fab = document.createElement("button");
    fab.id = "osf-fab";
    fab.title = "OSCP & Metodoloji içinde ara (/)";
    fab.innerHTML = '<span>⌕ Ara</span><kbd>/</kbd>';
    fab.addEventListener("click", open);

    overlay = document.createElement("div");
    overlay.id = "osf-overlay";
    overlay.innerHTML =
      '<div id="osf-box" role="dialog" aria-label="OSCP arama">' +
      '<input id="osf-input" type="text" autocomplete="off" spellcheck="false" ' +
      'placeholder="Teknik, komut ya da bölüm ara… (ör. kerberoast, SUID, chisel)">' +
      '<ul id="osf-results"></ul>' +
      '<div id="osf-hint"><kbd>↑</kbd><kbd>↓</kbd> gez · <kbd>Enter</kbd> git · <kbd>Esc</kbd> kapat</div>' +
      "</div>";
    document.body.appendChild(fab);
    document.body.appendChild(overlay);
    input = overlay.querySelector("#osf-input");
    results = overlay.querySelector("#osf-results");
    hint = overlay.querySelector("#osf-hint");

    overlay.addEventListener("click", function (e) { if (e.target === overlay) close(); });
    input.addEventListener("input", render);
    input.addEventListener("keydown", onKey);
  }

  function ensureData(cb) {
    if (data) { cb(); return; }
    fetch(INDEX_URL).then(function (r) { return r.json(); })
      .then(function (j) { data = j; cb(); })
      .catch(function () { data = []; cb(); });
  }

  function open() {
    ensureData(function () {
      overlay.classList.add("open");
      input.value = ""; sel = -1; render();
      input.focus();
    });
  }
  function close() { overlay.classList.remove("open"); }

  function highlight(text, tokens) {
    var out = text;
    tokens.forEach(function (t) {
      if (!t) return;
      var re = new RegExp("(" + t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + ")", "ig");
      out = out.replace(re, "\u0001$1\u0002");
    });
    out = out.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    return out.replace(/\u0001/g, "<mark>").replace(/\u0002/g, "</mark>");
  }

  function render() {
    var q = norm(input.value);
    var tokens = q ? q.split(" ") : [];
    shown = [];
    if (!q) {
      shown = data.filter(function (e) { return e.k === ""; }); // boşken sayfa başlıkları
    } else {
      shown = data.filter(function (e) {
        var hay = norm(e.t + " " + e.p);
        return tokens.every(function (t) { return hay.indexOf(t) !== -1; });
      }).sort(function (a, b) {
        // başlıkta geçen, sayfa-başlığında geçene göre öne
        return norm(b.t).indexOf(tokens[0]) === 0 ? 1 : (norm(a.t).indexOf(tokens[0]) === 0 ? -1 : 0);
      });
    }
    shown = shown.slice(0, 40);
    sel = shown.length ? 0 : -1;
    if (!shown.length) {
      results.innerHTML = '<div id="osf-empty">Sonuç yok.</div>';
      return;
    }
    results.innerHTML = shown.map(function (e, i) {
      return '<li data-i="' + i + '" class="' + (i === sel ? "sel" : "") + '">' +
        '<div class="osf-t">' + highlight(e.t, tokens) + "</div>" +
        '<div class="osf-p">' + highlight(e.p || "", tokens) + "</div></li>";
    }).join("");
    Array.prototype.forEach.call(results.children, function (li) {
      li.addEventListener("click", function () { go(shown[+li.dataset.i]); close(); });
    });
  }

  function moveSel(d) {
    if (!shown.length) return;
    sel = (sel + d + shown.length) % shown.length;
    Array.prototype.forEach.call(results.children, function (li, i) {
      li.classList.toggle("sel", i === sel);
      if (i === sel) li.scrollIntoView({ block: "nearest" });
    });
  }

  function onKey(e) {
    if (e.key === "ArrowDown") { e.preventDefault(); moveSel(1); }
    else if (e.key === "ArrowUp") { e.preventDefault(); moveSel(-1); }
    else if (e.key === "Enter") { e.preventDefault(); if (sel >= 0) { go(shown[sel]); close(); } }
    else if (e.key === "Escape") { close(); }
  }

  /* "/" ile aç (input/textarea içinde değilsek) */
  document.addEventListener("keydown", function (e) {
    if (e.key !== "/" || e.ctrlKey || e.metaKey || e.altKey) return;
    var a = document.activeElement, tag = a && a.tagName;
    if (tag === "INPUT" || tag === "TEXTAREA" || (a && a.isContentEditable)) return;
    e.preventDefault(); open();
  });

  function init() { build(); handleJump(); }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else { init(); }
  window.addEventListener("hashchange", handleJump);
})();
