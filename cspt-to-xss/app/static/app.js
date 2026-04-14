// VULN (CWE-22 client-side / CWE-79 DOM XSS):
//
// The username is read from the URL fragment and concatenated directly
// into the fetch() path. No validation, no encoding, no allowlist.
//
// If the attacker supplies a hash like
//     #../echo?data=<img src=x onerror=alert(1)>
// then the template literal builds
//     /api/users/../echo?data=<img src=x onerror=alert(1)>/profile
// which the URL parser normalizes to
//     /api/echo?data=<img src=x onerror=alert(1)>/profile
// — a completely different endpoint on the same origin.
//
// The response's 'bio' field is then written to innerHTML, so whatever
// bytes the attacker chose to echo are parsed as HTML and executed.

const username = location.hash.slice(1) || "alice";

fetch(`/api/users/${username}/profile`)
  .then(r => r.json())
  .then(data => {
    document.getElementById("name").textContent = data.displayName || "unknown";
    // dangerous sink — innerHTML on attacker-influenced string
    document.getElementById("bio").innerHTML = data.bio || "";
  })
  .catch(err => {
    document.getElementById("bio").textContent = "error: " + err;
  });
