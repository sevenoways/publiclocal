// Google Analytics with consent mode: no cookies until the visitor allows
// them. Without consent GA still receives cookieless, anonymous pings, which
// is enough to count visits. Rybbit (cookieless) runs alongside via its own
// tag. Only the site's own pages load this; tunnels and the warning page never do.
(function () {
  var ID = "G-Q0P2XYKYX8";
  window.dataLayer = window.dataLayer || [];
  function gtag() { dataLayer.push(arguments); }
  window.gtag = gtag;

  var choice = null;
  try { choice = localStorage.getItem("pl_consent"); } catch (e) {}

  gtag("consent", "default", {
    analytics_storage: choice === "granted" ? "granted" : "denied",
    ad_storage: "denied",
    ad_user_data: "denied",
    ad_personalization: "denied"
  });
  gtag("js", new Date());
  gtag("config", ID);

  var s = document.createElement("script");
  s.async = true;
  s.src = "https://www.googletagmanager.com/gtag/js?id=" + ID;
  document.head.appendChild(s);

  if (choice) return;
  document.addEventListener("DOMContentLoaded", function () {
    var bar = document.createElement("div");
    bar.className = "consent";
    bar.setAttribute("role", "dialog");
    bar.setAttribute("aria-label", "Cookie choice");
    bar.innerHTML = '<span>We use Google Analytics to count visits. Allow analytics cookies? <a href="/terms#privacy">Details</a></span>' +
      '<span class="consent-actions"><button type="button" data-c="granted">Allow</button><button type="button" data-c="denied" class="quiet">No thanks</button></span>';
    bar.addEventListener("click", function (e) {
      var c = e.target.getAttribute && e.target.getAttribute("data-c");
      if (!c) return;
      try { localStorage.setItem("pl_consent", c); } catch (err) {}
      if (c === "granted") gtag("consent", "update", { analytics_storage: "granted" });
      bar.remove();
    });
    document.body.appendChild(bar);
  });
})();
