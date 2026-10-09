// ntfy-admin: small progressive enhancements. Everything works without JS,
// except confirm dialogs, copy buttons, filters and password generation.
(function () {
  "use strict";

  // Confirm dialogs: <form data-confirm="message">
  document.addEventListener("submit", function (ev) {
    var form = ev.target;
    var msg = form.getAttribute("data-confirm");
    if (msg && !window.confirm(msg)) {
      ev.preventDefault();
    }
  });

  document.addEventListener("click", function (ev) {
    var btn = ev.target.closest("button");
    if (!btn) return;

    // Copy to clipboard: <button data-copy="#selector">
    var copySel = btn.getAttribute("data-copy");
    if (copySel) {
      var el = document.querySelector(copySel);
      if (!el) return;
      navigator.clipboard.writeText(el.textContent.trim()).then(function () {
        var old = btn.textContent;
        btn.textContent = "Copied";
        setTimeout(function () { btn.textContent = old; }, 1500);
      });
      return;
    }

    // Password generator: <button data-genpw="#input">
    var pwSel = btn.getAttribute("data-genpw");
    if (pwSel) {
      var input = document.querySelector(pwSel);
      var bytes = new Uint8Array(18);
      crypto.getRandomValues(bytes);
      var pw = btoa(String.fromCharCode.apply(null, bytes)).replace(/\+/g, "-").replace(/\//g, "_");
      input.type = "text";
      input.value = pw;
      input.select();
      return;
    }

    // Add rule row: <button data-add-rule> inside <fieldset data-rules>
    if (btn.hasAttribute("data-add-rule")) {
      var fs = btn.closest("[data-rules]");
      var rows = fs.querySelector(".rule-rows");
      var clone = rows.querySelector(".rule-row").cloneNode(true);
      clone.querySelector("input").value = "";
      rows.appendChild(clone);
      clone.querySelector("input").focus();
    }
  });

  // Client-side filter: <input data-filter="#table-or-container" [data-filter-items=".selector"]>
  document.querySelectorAll("input[data-filter]").forEach(function (input) {
    var target = document.querySelector(input.getAttribute("data-filter"));
    if (!target) return;
    var itemSel = input.getAttribute("data-filter-items") || "tbody tr";
    input.addEventListener("input", function () {
      var q = input.value.trim().toLowerCase();
      target.querySelectorAll(itemSel).forEach(function (item) {
        item.hidden = q !== "" && item.textContent.toLowerCase().indexOf(q) === -1;
      });
    });
  });

  // Custom expiry date: show the date field only for "custom".
  document.querySelectorAll("select[data-expiry]").forEach(function (sel) {
    var form = sel.closest("form");
    var date = form.querySelector(".expiry-date");
    var sync = function () {
      var custom = sel.value === "custom";
      date.hidden = !custom;
      date.querySelector("input").required = custom;
    };
    sel.addEventListener("change", sync);
    sync();
  });
})();
