// Vercel Speed Insights and Web Analytics, loaded right after this file (base.html).
// Both are cookieless. Before anything is sent, every address is reduced to its page:
// no query string (search text, folder ids), no #fragment, and any path segment that
// looks like an id (a Drive file id, a request id) becomes ":id". So /requests/<id>?q=x
// is reported as /requests/:id. The referrer is reduced the same way.
(function () {
  var KEEP = { tab: 1, view: 1 };
  var ID = /^[A-Za-z0-9_-]{16,}$/;

  function redact(href) {
    var url = new URL(href, window.location.href);
    var keep = new URLSearchParams();
    url.searchParams.forEach(function (value, key) {
      // Only the page's own tab names, which are short fixed words.
      if (KEEP[key] && /^[a-z-]{1,20}$/.test(value)) keep.set(key, value);
    });
    url.search = keep.toString();
    url.hash = "";
    url.pathname = url.pathname
      .split("/")
      .map(function (part) { return ID.test(part) ? ":id" : part; })
      .join("/");
    return url.href;
  }

  function beforeSend(event) {
    try {
      event.url = redact(event.url);
      return event;
    } catch (err) {
      return null; // Not sure what it holds: send nothing.
    }
  }

  try {
    var ref = document.referrer;
    var safeRef = "";
    if (ref) {
      var from = new URL(ref);
      safeRef = from.origin === window.location.origin ? redact(ref) : from.origin + "/";
    }
    Object.defineProperty(document, "referrer", { configurable: true, get: function () { return safeRef; } });
  } catch (err) { /* keep the browser's own value; the policy already limits it to this site */ }

  window.va = window.va || function () { (window.vaq = window.vaq || []).push(arguments); };
  window.si = window.si || function () { (window.siq = window.siq || []).push(arguments); };
  window.va("beforeSend", beforeSend);
  window.si("beforeSend", beforeSend);
})();
