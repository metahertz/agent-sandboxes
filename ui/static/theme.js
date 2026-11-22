"use strict";
// Before first paint: the theme picked in the sidebar (Auto / Light / Dark), kept per browser.
(() => {
  let t = "";
  try { t = localStorage.getItem("aio-theme") || ""; } catch { /* storage blocked: Auto */ }
  if (t === "light" || t === "dark") document.documentElement.dataset.theme = t;
})();
