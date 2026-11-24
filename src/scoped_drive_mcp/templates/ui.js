(function () {
  var navBtn = document.querySelector(".nav-toggle");
  var nav = document.getElementById("site-nav");
  if (navBtn && nav) {
    // The phone menu is a fixed overlay: close it on Escape, on a click or tap outside it,
    // and when focus moves past it, so focus never sits on content hidden underneath.
    var setNav = function (open, returnFocus) {
      nav.classList.toggle("open", open);
      navBtn.setAttribute("aria-expanded", open ? "true" : "false");
      if (!open && returnFocus) navBtn.focus();
    };
    var navOpen = function () { return nav.classList.contains("open"); };
    navBtn.addEventListener("click", function () { setNav(!navOpen(), false); });
    document.addEventListener("keydown", function (event) {
      if (event.key !== "Escape" || !navOpen()) return;
      // An open account menu inside the nav closes first (handled below).
      var acct = nav.querySelector("details.account[open]");
      if (acct) return;
      setNav(false, true);
    });
    document.addEventListener("click", function (event) {
      if (navOpen() && !nav.contains(event.target) && !navBtn.contains(event.target)) setNav(false, false);
    });
    nav.addEventListener("focusout", function (event) {
      var to = event.relatedTarget;
      if (navOpen() && to && !nav.contains(to) && to !== navBtn) setNav(false, false);
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
    var ok = false;
    try { ok = document.execCommand("copy"); } catch (err) { /* ignore */ }
    area.remove();
    return ok;
  }

  document.addEventListener("click", function (event) {
    var btn = event.target.closest("[data-copy]");
    if (!btn) return;
    var value = btn.getAttribute("data-copy") || "";
    // The label and width are taken once, so a second click while it says "Copied"
    // neither keeps "Copied" as the label nor holds the button at that width.
    if (btn.__label == null) {
      btn.__label = btn.textContent;
      // Hold the button's width so the shorter "Copied" does not pull the row in.
      btn.style.minWidth = btn.getBoundingClientRect().width + "px";
    }
    var label = btn.__label;
    // Only say "Copied" when it was, and say it to screen readers too.
    var done = function (ok) {
      btn.textContent = ok ? "Copied" : "Copy failed";
      announce(ok ? "ok" : "error", ok ? "Copied to the clipboard." : "Could not copy. Select the text and copy it yourself.");
      window.clearTimeout(btn.__copyTimer);
      btn.__copyTimer = window.setTimeout(function () {
        btn.textContent = label;
        btn.style.minWidth = "";
        btn.__label = null;
      }, 1500);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(value).then(
        function () { done(true); },
        function () { done(fallbackCopy(value)); }
      );
    } else {
      done(fallbackCopy(value));
    }
  });

  // ---- Row actions without a full page reload --------------------------------
  // Forms marked data-async (Allow, Remove, Share, Stop sharing, Disconnect) post in the
  // background and update only their own row. The server answers JSON when asked for it
  // and still redirects a plain form post, so the page works without JavaScript too.

  // One persistent live region (in base.html) carries every announcement. Writing into a
  // region that already exists is announced reliably; inserting a new role=status node is not.
  var live = document.getElementById("live");
  var liveAlert = document.getElementById("live-alert");
  function announce(kind, message) {
    var region = kind === "ok" ? live : (liveAlert || live);
    if (!region || !message) return;
    region.textContent = "";
    // A fresh write on the next tick so the same message twice is still announced.
    window.setTimeout(function () { region.textContent = message; }, 60);
  }

  // A flash rendered with the page is not announced on load; read it out once.
  var pageFlash = document.querySelector("#main > .flash:not([id])");
  if (pageFlash) announce(pageFlash.classList.contains("error") ? "error" : "ok", pageFlash.textContent.trim());

  // Every notice can be closed. The button is added here, so a page without JavaScript
  // shows the message with nothing that does not work.
  function addDismiss(note) {
    if (!note || note.querySelector(":scope > button.dismiss")) return;
    var text = document.createElement("span");
    text.className = "note-text";
    while (note.firstChild) text.appendChild(note.firstChild);
    note.appendChild(text);
    var close = document.createElement("button");
    close.type = "button";
    close.className = "dismiss";
    close.setAttribute("aria-label", "Dismiss");
    close.textContent = "\u00d7";
    note.appendChild(close);
    note.classList.add("dismissable");
  }
  function setNote(note, message) {
    var text = note.querySelector(":scope > .note-text");
    if (text) text.textContent = message;
    else { note.textContent = message; addDismiss(note); }
  }
  Array.prototype.forEach.call(document.querySelectorAll("#main > .flash"), addDismiss);
  document.addEventListener("click", function (event) {
    var close = event.target.closest("button.dismiss");
    if (!close) return;
    var note = close.parentNode;
    var back = note.__returnFocus;
    if (note === toast) { note.hidden = true; window.clearTimeout(toastTimer); }
    else note.remove();
    if (back && document.contains(back)) back.focus();
  });

  var toast = null;
  var toastTimer = null;
  function inView(el) {
    var r = el.getBoundingClientRect();
    return r.bottom > 64 && r.top < window.innerHeight;
  }

  function showFlash(kind, message) {
    var main = document.getElementById("main");
    if (!main || !message) return;
    var cls = kind === "ok" ? "ok" : "error";
    announce(cls, message);
    // A flash already at the top (from the last page load) is stale now. Update it in place
    // so nothing moves; if it is on screen that is all the person needs to see.
    var old = main.querySelectorAll(":scope > .flash:not([id])");
    for (var i = 1; i < old.length; i++) old[i].remove();
    if (old.length) {
      old[0].className = "flash dismissable " + cls;
      old[0].removeAttribute("role");
      setNote(old[0], message);
      if (inView(old[0])) { if (toast) toast.hidden = true; return; }
    }
    // Otherwise show a fixed toast by the bottom edge: no layout shift, and visible on a
    // long phone list where the top of the page is far away.
    if (!toast) {
      // Announced through the live region above, so the toast itself is not a live region.
      toast = document.createElement("div");
      toast.textContent = message;
      addDismiss(toast);
      document.body.appendChild(toast);
    }
    toast.className = "toast dismissable " + cls;
    setNote(toast, message);
    toast.hidden = false;
    window.clearTimeout(toastTimer);
    toastTimer = window.setTimeout(function () { toast.hidden = true; }, cls === "ok" ? 4000 : 8000);
  }

  function flipRow(form) {
    var key = form.getAttribute("data-flip");
    var row = form.closest("[data-row]");
    if (!key || !row) return;
    var next = row.getAttribute("data-" + key) === "on" ? "off" : "on";
    // A shortcut's Allow / Share acts on its target, so every row on the page for that
    // same item (the target itself, other shortcuts to it) changes with it.
    var rows = [row];
    var target = row.getAttribute("data-acts-on");
    if (target) {
      var all = document.querySelectorAll("[data-row][data-acts-on]");
      for (var j = 0; j < all.length; j++) {
        if (all[j] !== row && all[j].getAttribute("data-acts-on") === target) rows.push(all[j]);
      }
    }
    rows.forEach(function (r) {
      r.setAttribute("data-" + key, next);
      var parts = r.querySelectorAll("[data-" + key + "-when]");
      for (var i = 0; i < parts.length; i++) {
        parts[i].hidden = parts[i].getAttribute("data-" + key + "-when") !== next;
      }
    });
    // Keep keyboard focus on the row: move it to the button that replaced this one.
    // When no button replaced it (the item is still covered by a folder), stay on the row.
    var shown = row.querySelector("form[data-flip='" + key + "']:not([hidden]) button") || rowTarget(row);
    if (shown) shown.focus();
  }

  function rowTarget(row) {
    // The row's own action is the natural next stop; else its first link.
    return row && (row.querySelector("form:not([hidden]) button") || row.querySelector("a[href]"));
  }

  function removeRow(form) {
    var row = form.closest("[data-row]");
    if (!row) return;
    var body = row.parentNode;
    var hadFocus = row.contains(document.activeElement);
    var next = row.nextElementSibling;
    while (next && !next.hasAttribute("data-row")) next = next.nextElementSibling;
    var prev = row.previousElementSibling;
    while (prev && !prev.hasAttribute("data-row")) prev = prev.previousElementSibling;
    // A row's Change panel (Sharing) lives in the next table row; it goes with it.
    var panel = row.nextElementSibling;
    if (panel && panel.classList.contains("edit-row")) panel.remove();
    row.remove();
    var target = rowTarget(next) || rowTarget(prev);
    if (body && !body.querySelector("tr, li")) {
      var list = body.closest("[data-list]");
      if (list) list.hidden = true;
      var scope = list ? list.parentNode : document;
      var empty = scope.querySelector("[data-empty]");
      if (empty) {
        empty.hidden = false;
        target = empty.querySelector("h2, h3, p");
        if (target) target.tabIndex = -1;
      }
    }
    // Do not leave keyboard focus on <body> after its button disappeared.
    if (hadFocus || document.activeElement === document.body) {
      if (target) target.focus();
      else {
        var main = document.getElementById("main");
        if (main) { main.tabIndex = -1; main.focus(); }
      }
    }
  }

  // The Allowed tab's number follows Allow / Remove on the same page.
  function setAllowCount(n) {
    var count = document.querySelector('.tabs a[href="/files?tab=allowed"] .count');
    if (count) count.textContent = String(n);
  }

  // Tabs stay on one row and scroll sideways on a narrow screen; keep the current one in view.
  Array.prototype.forEach.call(document.querySelectorAll(".tabs"), function (tabs) {
    var on = tabs.querySelector("[aria-current]");
    if (!on || tabs.scrollWidth <= tabs.clientWidth) return;
    var left = on.getBoundingClientRect().left - tabs.getBoundingClientRect().left;
    if (left + on.offsetWidth > tabs.clientWidth) tabs.scrollLeft = left - 16;
  });

  if (window.fetch && window.URLSearchParams && window.FormData) window.__asyncForms = true;

  // ---- Confirm -------------------------------------------------------------------
  // An in-page dialog instead of the browser's confirm(). data-confirm is the question,
  // data-confirm-action the button label, and data-confirm-check (a field name) with
  // data-confirm-check-label adds one optional checkbox that posts <name>=on.
  function askConfirm(form) {
    var ask = form.getAttribute("data-confirm");
    if (!ask) return Promise.resolve(true);
    if (typeof HTMLDialogElement !== "function") return Promise.resolve(window.confirm(ask));
    return new Promise(function (resolve) {
      var dlg = document.createElement("dialog");
      dlg.className = "confirm";
      var text = document.createElement("p");
      text.id = "confirm-text";
      text.textContent = ask;
      dlg.setAttribute("aria-labelledby", "confirm-text");
      dlg.appendChild(text);
      var checkName = form.getAttribute("data-confirm-check");
      var box = null;
      if (checkName) {
        var label = document.createElement("label");
        box = document.createElement("input");
        box.type = "checkbox";
        label.appendChild(box);
        label.appendChild(document.createTextNode(" " + (form.getAttribute("data-confirm-check-label") || checkName)));
        dlg.appendChild(label);
      }
      var row = document.createElement("div");
      row.className = "actions";
      var cancel = document.createElement("button");
      cancel.type = "button";
      cancel.textContent = "Cancel";
      var ok = document.createElement("button");
      ok.type = "button";
      var submit = form.querySelector("button[type=submit], button:not([type])");
      ok.className = submit && submit.classList.contains("danger") ? "danger" : "primary";
      ok.textContent = form.getAttribute("data-confirm-action") ||
        (submit ? (submit.childNodes[0] && submit.childNodes[0].textContent || "").trim() : "") || "Confirm";
      row.appendChild(cancel);
      row.appendChild(ok);
      dlg.appendChild(row);
      var settled = false;
      function done(value) {
        if (settled) return;
        settled = true;
        if (checkName) {
          var old = form.querySelector('input[data-from-confirm]');
          if (old) old.remove();
          if (value && box && box.checked) {
            var hidden = document.createElement("input");
            hidden.type = "hidden";
            hidden.name = checkName;
            hidden.value = "on";
            hidden.setAttribute("data-from-confirm", "");
            form.appendChild(hidden);
          }
        }
        if (dlg.open) dlg.close();
        dlg.remove();
        if (submit && !value) submit.focus();
        resolve(value);
      }
      cancel.addEventListener("click", function () { done(false); });
      ok.addEventListener("click", function () { done(true); });
      dlg.addEventListener("cancel", function (event) { event.preventDefault(); done(false); });
      dlg.addEventListener("click", function (event) { if (event.target === dlg) done(false); });
      document.body.appendChild(dlg);
      dlg.showModal();
      cancel.focus();
    });
  }
  window.__askConfirm = askConfirm;

  document.addEventListener("submit", function (event) {
    var form = event.target;
    if (!form || !form.hasAttribute || !form.hasAttribute("data-async")) return;
    if (!window.fetch || !window.URLSearchParams || !window.FormData) return;
    event.preventDefault();
    if (form.getAttribute("aria-busy") === "true") return;
    askConfirm(form).then(function (yes) {
      if (!yes) return;
      if (form.hasAttribute("data-refresh")) sendAndRefresh(form);
      else sendInPlace(form);
    });
  });

  // ---- Settings: update the changed sections only --------------------------------------
  // A wake-up change can touch more than its own card (a move empties one card and fills
  // another; "Answers other people" sits on a card but is set below). So after the change
  // the page is fetched again in the background and only those sections are swapped in.
  // Scroll position, other open panels and anything typed elsewhere on the page stay.
  var REFRESH = ["assistants", "other-people"];

  function postForm(form) {
    return fetch(form.getAttribute("action"), {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(new FormData(form)).toString(),
      credentials: "same-origin"
    }).then(function (response) {
      var type = response.headers.get("content-type") || "";
      if (type.indexOf("application/json") === -1) throw new Error("not json");
      return response.json();
    });
  }

  function refreshSections(keepClosed) {
    return fetch(window.location.pathname, {
      headers: { Accept: "text/html" },
      credentials: "same-origin",
      cache: "no-store"
    })
      .then(function (response) {
        if (!response.ok) throw new Error("reload");
        return response.text();
      })
      .then(function (html) {
        var fresh = new DOMParser().parseFromString(html, "text/html");
        REFRESH.forEach(function (id) {
          var now = document.getElementById(id);
          var next = fresh.getElementById(id);
          if (!now || !next) return;
          // Panels the person had open stay open, except the one they just used.
          var open = {};
          Array.prototype.forEach.call(now.querySelectorAll("details[open][id]"), function (d) {
            if (d.id !== keepClosed) open[d.id] = true;
          });
          now.innerHTML = next.innerHTML;
          Array.prototype.forEach.call(now.querySelectorAll("details[id]"), function (d) {
            if (open[d.id]) d.open = true;
          });
        });
        localTimes();
      });
  }

  // A message shown inside the card the person is working in, where they are looking.
  function cardNote(cardId, kind, message) {
    var card = cardId && document.getElementById(cardId);
    if (!card) { showFlash(kind, message); return; }
    // An older success toast must not sit over this message.
    if (toast) { toast.hidden = true; window.clearTimeout(toastTimer); }
    var old = card.querySelectorAll(":scope > .flash.in-card");
    for (var i = 0; i < old.length; i++) old[i].remove();
    var note = document.createElement("div");
    note.className = "flash in-card " + (kind === "ok" ? "ok" : "error");
    note.textContent = message;
    addDismiss(note);
    var head = card.querySelector(":scope > .card-head, :scope > h3");
    if (head) head.insertAdjacentElement("afterend", note);
    else card.insertBefore(note, card.firstChild);
    announce(kind === "ok" ? "ok" : "error", message);
    var r = note.getBoundingClientRect();
    if (r.top < 72 || r.bottom > window.innerHeight) note.scrollIntoView({ block: "center", behavior: "smooth" });
    return note;
  }

  function sendAndRefresh(form) {
    var button = form.querySelector("button[type=submit], button:not([type])");
    var card = form.closest(".card[id]");
    var cardId = card ? card.id : "";
    var panel = form.closest("details[id]");
    var hadFocus = form.contains(document.activeElement);
    form.setAttribute("aria-busy", "true");
    if (button) button.disabled = true;
    var done = function () {
      form.removeAttribute("aria-busy");
      if (button) button.disabled = false;
    };
    postForm(form)
      .then(function (data) {
        var changed = typeof data.changed === "boolean" ? data.changed : data.ok;
        var after = changed ? refreshSections(data.ok && panel ? panel.id : "") : Promise.resolve();
        return after.then(function () {
          done();
          if (data.ok) {
            showFlash("ok", data.message);
            // Keep keyboard focus nearby when the button that had it was replaced.
            if (hadFocus && !document.contains(form)) {
              var target = cardId && document.getElementById(cardId);
              var heading = target ? target.querySelector("h3") : document.getElementById("assistants");
              if (heading) { heading.tabIndex = -1; heading.focus({ preventScroll: true }); }
            }
          } else {
            var note = cardNote(cardId, "error", data.message);
            var back = cardId && document.getElementById(cardId);
            if (note && back) {
              var same = document.contains(form) ? button : back.querySelector("button[type=submit]");
              note.__returnFocus = same;
            }
          }
        });
      })
      .catch(function () {
        done();
        cardNote(cardId, "error", "That did not save. Check your connection, reload the page and try again.");
      });
  }

  function sendInPlace(form) {
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
        // Refusals (signed out, expired page, bad input) are JSON too and carry their own message.
        return response.json();
      })
      .then(function (data) {
        showFlash(data.ok ? "ok" : "error", data.message);
        if (typeof data.allow_count === "number") setAllowCount(data.allow_count);
        var changed = typeof data.changed === "boolean" ? data.changed : data.ok;
        if (!changed) return;
        if (form.getAttribute("data-on-success") === "remove-row") removeRow(form);
        else flipRow(form);
      })
      .catch(function () {
        // A network failure or a server error page: say so instead of guessing.
        showFlash("error", "That did not save. Check your connection, reload the page and try again.");
      })
      .then(function () {
        form.removeAttribute("aria-busy");
        if (button) button.disabled = false;
      });
  }

  // ---- Times ---------------------------------------------------------------------
  // The server writes <time datetime="…" data-time>Nov 19, 2026, 23:58 UTC</time>. One rule
  // for every page, in the reader's own time zone: "5 minutes ago" / "3 hours ago" within a
  // day, otherwise "18 Nov, 21:29" (with the year only when it is not this year). The full
  // local date and time stays in the tooltip.
  function localTimes() {
    var nodes = document.querySelectorAll("time[data-time]");
    if (!nodes.length || !window.Intl || !Intl.DateTimeFormat) return;
    var full = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });
    var opts = { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" };
    var thisYear = new Intl.DateTimeFormat(undefined, opts);
    var otherYear = new Intl.DateTimeFormat(undefined, Object.assign({ year: "numeric" }, opts));
    var dayOpts = { day: "numeric", month: "short" };
    var dateThisYear = new Intl.DateTimeFormat(undefined, dayOpts);
    var dateOtherYear = new Intl.DateTimeFormat(undefined, Object.assign({ year: "numeric" }, dayOpts));
    var rel = Intl.RelativeTimeFormat ? new Intl.RelativeTimeFormat(undefined, { numeric: "auto" }) : null;
    var now = new Date();
    Array.prototype.forEach.call(nodes, function (el) {
      var t = Date.parse(el.getAttribute("datetime") || "");
      if (isNaN(t)) return;
      var d = new Date(t);
      var secs = (now.getTime() - t) / 1000;
      var sameYear = d.getFullYear() === now.getFullYear();
      var text;
      if (el.getAttribute("data-time") === "date") text = (sameYear ? dateThisYear : dateOtherYear).format(d);
      else if (rel && secs >= -60 && secs < 60) text = "just now";
      else if (rel && secs >= 0 && secs < 3570) text = rel.format(-Math.round(secs / 60), "minute");
      else if (rel && secs >= 3570 && secs < 24 * 3600) text = rel.format(-Math.round(secs / 3600), "hour");
      else text = (sameYear ? thisYear : otherYear).format(d);
      el.textContent = text;
      el.title = full.format(d);
    });
  }
  localTimes();

  // "Add from Google Drive", "Choose the file to approve", and each "Pick again" button.
  var pickButtons = document.querySelectorAll("#pick-drive, [data-pick]");
  if (!pickButtons.length) return;
  var pick = pickButtons[0];

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
    // Same rule as the server's safe_next: a same-site path with no control characters.
    if (!value || value.charAt(0) !== "/" || value.indexOf("//") === 0 || value.indexOf("\\") !== -1 ||
        /[\u0000-\u0020\u007f]/.test(value)) {
      return "/files";
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
    // "Pick again" opens Google's search already filled in with the item's name.
    var query = (pick.getAttribute("data-query") || "").slice(0, 200);
    if (query && typeof view.setQuery === "function") view.setQuery(query);
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

  function onPickClick(event) {
    pick = event.currentTarget;
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
  }
  Array.prototype.forEach.call(pickButtons, function (button) {
    button.addEventListener("click", onPickClick);
  });
})();

// Sharing: Change opens the item's panel in the row below, without a page load.
// Without JS the same link loads ?edit=<id>, which renders that panel open.
(function () {
  document.addEventListener("click", function (event) {
    var link = event.target.closest("[data-edit-toggle]");
    if (!link) return;
    var panel = document.getElementById(link.getAttribute("data-edit-toggle"));
    if (!panel) return;
    event.preventDefault();
    var opening = panel.hidden;
    panel.hidden = !opening;
    var opener = document.querySelector('[aria-controls="' + CSS.escape(panel.id) + '"]');
    if (opener) opener.setAttribute("aria-expanded", opening ? "true" : "false");
    if (opening) {
      // Two lookups: a selector list matches in document order, so it would pick the hidden csrf field.
      var first = panel.querySelector("input:checked") || panel.querySelector("input:not([type=hidden])");
      if (first) first.focus();
    } else if (opener) {
      opener.focus();
    }
  });
})();

// Files sent to a paired person (Sharing → Shared with me). Vercel refuses request and
// response bodies over 4.5 MB, so a file goes up, and comes back down, in pieces of at
// most 4 MB. Without JavaScript the plain form still sends files up to 4 MB.
(function () {
  function fail(response) {
    return response.json().then(
      function (body) { throw new Error((body && body.message) || "Something went wrong. Try again."); },
      function () { throw new Error("Something went wrong (" + response.status + "). Reload the page and try again."); }
    );
  }

  function post(url, body) {
    return fetch(url, {
      method: "POST",
      body: body,
      credentials: "same-origin",
      headers: { Accept: "application/json" },
    }).then(function (response) { return response.ok ? response.json() : fail(response); });
  }

  var form = document.querySelector("form[data-drop-send]");
  if (form && window.fetch && window.FormData) {
    var status = form.querySelector("[data-drop-status]");
    var button = form.querySelector("button[type=submit]");
    var say = function (text) { if (status) status.textContent = text; };
    form.addEventListener("submit", function (event) {
      var file = form.elements.file.files[0];
      if (!file) return;
      event.preventDefault();
      var max = parseInt(form.getAttribute("data-drop-max"), 10) || 0;
      if (max && file.size > max) {
        say("That file is larger than " + Math.floor(max / 1048576) + " MB.");
        return;
      }
      var csrf = form.elements.csrf.value;
      var start = new FormData();
      start.append("csrf", csrf);
      start.append("to", form.elements.to.value);
      start.append("name", file.name);
      start.append("type", file.type || "application/octet-stream");
      start.append("size", String(file.size));
      button.disabled = true;
      say("Starting…");
      var upload;
      post("/shared/send/start", start)
        .then(function (begun) {
          upload = begun;
          var base = "/shared/send/" + encodeURIComponent(begun.upload_id);
          var next = function (n) {
            if (n >= begun.pieces) return Promise.resolve();
            say("Sending… " + Math.round((n / begun.pieces) * 100) + "%");
            var body = new FormData();
            body.append("csrf", csrf);
            body.append("piece", file.slice(n * begun.piece_bytes, (n + 1) * begun.piece_bytes), "piece");
            var send = function () { return post(base + "/piece/" + n, body); };
            // One retry for a dropped connection; a refusal from the server is final.
            return send()
              .catch(function (err) { if (err instanceof TypeError) return send(); throw err; })
              .then(function () { return next(n + 1); });
          };
          return next(0).then(function () {
            var done = new FormData();
            done.append("csrf", csrf);
            say("Finishing…");
            return post(base + "/finish", done);
          });
        })
        .then(function () { window.location.assign("/sharing?tab=with-me"); })
        .catch(function (err) {
          button.disabled = false;
          say(err && err.message ? err.message : "The file could not be sent. Try again.");
        });
    });
  }

  document.addEventListener("click", function (event) {
    var link = event.target.closest("a[data-drop-download]");
    if (!link || !window.fetch || !window.Blob || !window.URL) return;
    var pieces = parseInt(link.getAttribute("data-drop-pieces"), 10) || 1;
    if (pieces <= 1) return; // small enough for the plain link
    event.preventDefault();
    if (link.getAttribute("aria-busy") === "true") return;
    var id = encodeURIComponent(link.getAttribute("data-drop-download"));
    var label = link.textContent;
    var parts = [];
    link.setAttribute("aria-busy", "true");
    var next = function (n) {
      if (n >= pieces) return Promise.resolve();
      link.textContent = "Downloading… " + Math.round((n / pieces) * 100) + "%";
      return fetch("/drops/" + id + "/piece/" + n, { credentials: "same-origin" })
        .then(function (response) { return response.ok ? response.blob() : fail(response); })
        .then(function (blob) { parts.push(blob); return next(n + 1); });
    };
    next(0)
      .then(function () {
        var url = URL.createObjectURL(new Blob(parts, { type: "application/octet-stream" }));
        var a = document.createElement("a");
        a.href = url;
        a.download = link.getAttribute("data-drop-name") || "file";
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(function () { URL.revokeObjectURL(url); }, 60000);
      })
      .catch(function (err) {
        window.alert(err && err.message ? err.message : "The file could not be downloaded.");
      })
      .then(function () {
        link.textContent = label;
        link.removeAttribute("aria-busy");
      });
  });
})();
