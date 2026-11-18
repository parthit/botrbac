(function () {
  var navBtn = document.querySelector(".nav-toggle");
  var nav = document.getElementById("site-nav");
  if (navBtn && nav) {
    navBtn.addEventListener("click", function () {
      var open = nav.classList.toggle("open");
      navBtn.setAttribute("aria-expanded", open ? "true" : "false");
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
    var chain = Promise.resolve();
    docs.forEach(function (doc, index) {
      chain = chain.then(function () {
        var body = new URLSearchParams();
        body.set("csrf", token || "");
        var path = "/grant";
        if (requestId && index === 0) {
          body.set("target_id", doc.id);
          path = "/requests/" + requestId + "/approve";
        } else {
          body.set("file_id", doc.id);
          body.set("next", next);
        }
        return fetch(path, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: body.toString(),
          redirect: "manual",
          credentials: "same-origin"
        });
      });
    });
    var done = requestId ? "/requests/" + requestId : next;
    return chain.then(function () { window.location.assign(done); });
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
