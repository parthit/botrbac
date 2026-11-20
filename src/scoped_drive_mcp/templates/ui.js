(function () {
  var navBtn = document.querySelector(".nav-toggle");
  var nav = document.getElementById("site-nav");
  if (navBtn && nav) {
    navBtn.addEventListener("click", function () {
      var open = nav.classList.toggle("open");
      navBtn.setAttribute("aria-expanded", open ? "true" : "false");
    });
  }

  var account = document.querySelector("details.account");
  if (account) {
    document.addEventListener("click", function (event) {
      if (account.open && !account.contains(event.target)) account.open = false;
    });
    document.addEventListener("keydown", function (event) {
      if (event.key === "Escape" && account.open) {
        account.open = false;
        account.querySelector("summary").focus();
      }
    });
  }

  function fallbackCopy(value) {
    var area = document.createElement("textarea");
    area.value = value;
    area.setAttribute("readonly", "");
    area.style.position = "absolute";
    area.style.left = "-9999px";
    document.body.appendChild(area);
    area.select();
    try { document.execCommand("copy"); } catch (err) { /* ignore */ }
    area.remove();
  }

  document.addEventListener("click", function (event) {
    var btn = event.target.closest("[data-copy]");
    if (!btn) return;
    var value = btn.getAttribute("data-copy") || "";
    var label = btn.textContent;
    var done = function () {
      btn.textContent = "Copied";
      window.setTimeout(function () { btn.textContent = label; }, 1500);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(value).then(done, function () { fallbackCopy(value); done(); });
    } else {
      fallbackCopy(value);
      done();
    }
  });

  // ---- Row actions without a full page reload --------------------------------
  // Forms marked data-async (Allow, Remove, Share, Stop sharing, Disconnect) post in the
  // background and update only their own row. The server answers JSON when asked for it
  // and still redirects a plain form post, so the page works without JavaScript too.

  function showFlash(kind, message) {
    var main = document.getElementById("main");
    if (!main || !message) return;
    var old = main.querySelectorAll(":scope > .flash:not([id])");
    for (var i = 0; i < old.length; i++) old[i].remove();
    var note = document.createElement("div");
    note.className = "flash " + (kind === "ok" ? "ok" : "error");
    note.setAttribute("role", kind === "ok" ? "status" : "alert");
    note.textContent = message;
    note.tabIndex = -1;
    main.insertBefore(note, main.firstChild);
    return note;
  }

  function flipRow(form, note) {
    var key = form.getAttribute("data-flip");
    var row = form.closest("[data-row]");
    if (!key || !row) return;
    var next = row.getAttribute("data-" + key) === "on" ? "off" : "on";
    row.setAttribute("data-" + key, next);
    var parts = row.querySelectorAll("[data-" + key + "-when]");
    for (var i = 0; i < parts.length; i++) {
      parts[i].hidden = parts[i].getAttribute("data-" + key + "-when") !== next;
    }
    // Keep keyboard focus on the row: move it to the button that replaced this one.
    var shown = row.querySelector("form[data-flip='" + key + "']:not([hidden]) button");
    if (shown) shown.focus();
    else if (note) note.focus();
  }

  function removeRow(form) {
    var row = form.closest("[data-row]");
    if (!row) return;
    var body = row.parentNode;
    row.remove();
    if (body && !body.querySelector("tr, li")) {
      var list = body.closest("[data-list]");
      if (list) list.hidden = true;
      var scope = list ? list.parentNode : document;
      var empty = scope.querySelector("[data-empty]");
      if (empty) empty.hidden = false;
    }
  }

  if (window.fetch && window.URLSearchParams && window.FormData) window.__asyncForms = true;

  document.addEventListener("submit", function (event) {
    var form = event.target;
    if (!form || !form.hasAttribute || !form.hasAttribute("data-async")) return;
    if (!window.fetch || !window.URLSearchParams || !window.FormData) return;
    event.preventDefault();
    if (form.getAttribute("aria-busy") === "true") return;
    var ask = form.getAttribute("data-confirm");
    if (ask && !window.confirm(ask)) return;
    var button = form.querySelector("button[type=submit], button:not([type])");
    form.setAttribute("aria-busy", "true");
    if (button) button.disabled = true;

    fetch(form.getAttribute("action"), {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: new URLSearchParams(new FormData(form)).toString(),
      credentials: "same-origin"
    })
      .then(function (response) {
        var type = response.headers.get("content-type") || "";
        if (type.indexOf("application/json") === -1) throw new Error("not json");
        return response.json();
      })
      .then(function (data) {
        var note = showFlash(data.ok ? "ok" : "error", data.message);
        var changed = typeof data.changed === "boolean" ? data.changed : data.ok;
        if (!changed) return;
        if (form.getAttribute("data-on-success") === "remove-row") removeRow(form);
        else flipRow(form, note);
      })
      .catch(function () {
        // Signed out, CSRF expired or a server error page: say so instead of guessing.
        showFlash("error", "That did not save. Reload the page and try again.");
      })
      .then(function () {
        form.removeAttribute("aria-busy");
        if (button) button.disabled = false;
      });
  });

  // ---- Times ---------------------------------------------------------------------
  // The server writes <time datetime="…" data-time>Nov 19, 2026, 23:58 UTC</time>. Show it
  // in the reader's own time zone, as "5 minutes ago" or "Yesterday, 3:04 PM" when recent.
  // The full local date and time stays in the tooltip.
  function localTimes() {
    var nodes = document.querySelectorAll("time[data-time]");
    if (!nodes.length || !window.Intl || !Intl.DateTimeFormat) return;
    var full = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });
    var clock = new Intl.DateTimeFormat(undefined, { timeStyle: "short" });
    var rel = Intl.RelativeTimeFormat ? new Intl.RelativeTimeFormat(undefined, { numeric: "auto" }) : null;
    var now = new Date();
    var startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
    var day = 24 * 3600 * 1000;
    Array.prototype.forEach.call(nodes, function (el) {
      var t = Date.parse(el.getAttribute("datetime") || "");
      if (isNaN(t)) return;
      var d = new Date(t);
      var secs = (now.getTime() - t) / 1000;
      var text;
      if (rel && secs >= -60 && secs < 60) text = "just now";
      else if (rel && secs >= 0 && secs < 3600) text = rel.format(-Math.round(secs / 60), "minute");
      else if (rel && secs >= 0 && secs < 6 * 3600) text = rel.format(-Math.round(secs / 3600), "hour");
      else if (t >= startOfToday && t < startOfToday + day) text = "Today, " + clock.format(d);
      else if (t >= startOfToday - day && t < startOfToday) text = "Yesterday, " + clock.format(d);
      else text = full.format(d);
      el.textContent = text;
      el.title = full.format(d);
    });
  }
  localTimes();

  var pick = document.getElementById("pick-drive");
  if (!pick) return;

  function loadPicker() {
    return new Promise(function (resolve, reject) {
      if (window.google && google.picker) { resolve(); return; }
      var script = document.createElement("script");
      script.src = "https://apis.google.com/js/api.js";
      script.async = true;
      script.onload = function () {
        window.gapi.load("picker", { callback: resolve, onerror: reject });
      };
      script.onerror = reject;
      document.head.appendChild(script);
    });
  }

  function safeBrowsePath(value) {
    if (!value || value.charAt(0) !== "/" || value.indexOf("//") === 0 || value.indexOf("\\") !== -1) {
      return "/browse";
    }
    return value;
  }

  function grantPicked(docs) {
    var csrf = document.querySelector('meta[name="csrf"]');
    var token = csrf ? csrf.getAttribute("content") : "";
    var next = safeBrowsePath(pick.getAttribute("data-next"));
    var requestId = pick.getAttribute("data-request") || "";
    if (!/^[A-Za-z0-9_-]{22,64}$/.test(requestId)) requestId = "";

    function postForm(path, fields) {
      var body = new URLSearchParams();
      body.set("csrf", token || "");
      Object.keys(fields).forEach(function (key) { body.set(key, fields[key]); });
      return fetch(path, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: body.toString(),
        redirect: "manual",
        credentials: "same-origin"
      });
    }

    function httpError(response) {
      return response.type !== "opaqueredirect" && response.status >= 400;
    }

    function showServerPage(response) {
      return response.text().then(function (html) {
        document.open();
        document.write(html);
        document.close();
      });
    }

    var chain = Promise.resolve();
    docs.forEach(function (doc) {
      chain = chain.then(function () {
        return postForm("/grant", { file_id: doc.id, next: next }).then(function (response) {
          if (httpError(response)) {
            return showServerPage(response).then(function () { throw new Error("shown"); });
          }
        });
      });
    });
    if (requestId && docs.length) {
      chain = chain.then(function () {
        return postForm("/requests/" + requestId + "/approve", {
          target_id: docs[0].id
        }).then(function (response) {
          if (httpError(response)) {
            return showServerPage(response).then(function () { throw new Error("shown"); });
          }
        });
      });
    }
    var done = requestId ? "/requests/" + requestId : next;
    return chain.then(function () {
      window.location.assign(done);
    }).catch(function (err) {
      if (err && err.message === "shown") return;
      var note = document.getElementById("pick-error");
      if (note) note.hidden = false;
    });
  }

  function openPicker(cfg) {
    var view = new google.picker.DocsView(google.picker.ViewId.DOCS);
    view.setIncludeFolders(true);
    view.setSelectFolderEnabled(true);
    var builder = new google.picker.PickerBuilder()
      .addView(view)
      .enableFeature(google.picker.Feature.MULTISELECT_ENABLED)
      .enableFeature(google.picker.Feature.SUPPORT_DRIVES)
      .setOAuthToken(cfg.access_token)
      .setDeveloperKey(cfg.api_key)
      .setAppId(String(cfg.app_id))
      .setTitle("Choose files and folders to share")
      .setCallback(function (data) {
        if (!data || data.action !== google.picker.Action.PICKED) return;
        grantPicked(data.docs || []);
      });
    if (builder.setOrigin) {
      builder.setOrigin(window.location.protocol + "//" + window.location.host);
    }
    builder.build().setVisible(true);
  }

  pick.addEventListener("click", function () {
    var note = document.getElementById("pick-error");
    if (note) note.hidden = true;
    pick.disabled = true;
    fetch("/picker/session", { headers: { Accept: "application/json" }, credentials: "same-origin" })
      .then(function (response) {
        if (!response.ok) throw new Error("session");
        return response.json();
      })
      .then(function (cfg) { return loadPicker().then(function () { return cfg; }); })
      .then(openPicker)
      .catch(function () { if (note) note.hidden = false; })
      .then(function () { pick.disabled = false; });
  });
})();
