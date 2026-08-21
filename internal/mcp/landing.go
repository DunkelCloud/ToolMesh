// Copyright 2026 Dunkel Cloud GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mcp

import (
	"html/template"
	"net/http"
	"strings"
)

// wantsHTML reports whether a request is a human opening the URL in a browser
// rather than an MCP client probing the endpoint.
//
// The signal is an explicit text/html in Accept. Command-line tooling sends */*
// or no Accept header at all and does not match, so every non-browser caller
// keeps the response it has always received. A client that asks for a stream
// wins outright: acceptsSSE is the same test the POST path uses to decide
// whether to stream, so the two can never disagree about who is a browser.
func wantsHTML(r *http.Request) bool {
	if acceptsSSE(r) {
		return false
	}
	for _, part := range strings.Split(r.Header.Get("Accept"), ",") {
		mediaType, _, _ := strings.Cut(part, ";")
		if strings.EqualFold(strings.TrimSpace(mediaType), mimeTextHTML) {
			return true
		}
	}
	return false
}

// endpointURL reconstructs the absolute URL of the MCP endpoint as the caller
// reached it. It deliberately uses the request's own host instead of
// cfg.Issuer: the visitor just typed this URL into an address bar, so echoing
// it back is the value they need to paste into a connector, and it stays
// correct on deployments that never set TOOLMESH_ISSUER. The host is
// attacker-controllable, so it is only ever rendered through html/template.
func endpointURL(r *http.Request) string {
	scheme := schemeHTTP
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), schemeHTTPS) {
		scheme = schemeHTTPS
	}
	host := r.Host
	if host == "" {
		host = "localhost"
	}
	return scheme + "://" + host + "/mcp"
}

// handleRoot serves the landing page at / and 404s everything else. The mux
// pattern "/" is a catch-all, so this handler is what unmatched paths reach;
// they got a bare 404 before and still do. Serving the page at the site root
// keeps a visitor who trimmed the URL down to the bare host from concluding
// the service is broken.
//
// A deployment that has somewhere better to send them — a demo page, an
// internal wiki — sets TOOLMESH_ROOT_REDIRECT and gets a redirect instead. The
// status is 302 and not 301 on purpose: a permanent redirect is cached by
// browsers indefinitely, so an operator who later clears or retargets the
// setting could not reach their own root again without the visitor clearing
// their cache. Only / redirects; /mcp keeps serving the page, since a visitor
// who landed there needs the URL in front of them to copy.
func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.cfg.RootRedirect != "" {
		http.Redirect(w, r, s.cfg.RootRedirect, http.StatusFound)
		return
	}
	s.serveLanding(w, r)
}

// serveLanding renders the "this is an MCP endpoint, not a website" page.
func (s *Server) serveLanding(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	if err := landingTmpl.Execute(w, landingData{
		Endpoint:     endpointURL(r),
		AuthRequired: s.authRequired(),
	}); err != nil {
		s.logger.ErrorContext(r.Context(), "landing page render failed", outcomeError, err)
	}
}

type landingData struct {
	Endpoint     string
	AuthRequired bool
}

// landingTmpl is self-contained on purpose: the page must render on a host that
// serves nothing but the MCP endpoint, with no static asset route to reach.
var landingTmpl = template.Must(template.New("landing").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>ToolMesh MCP endpoint</title>
<style>
:root { color-scheme: light dark; --fg:#1f2933; --muted:#6b7280; --bg:#ffffff; --card:#f6f7f9; --line:#e2e5ea; --accent:#2563eb; }
@media (prefers-color-scheme: dark) {
  :root { --fg:#e5e7eb; --muted:#9ca3af; --bg:#111418; --card:#1b1f26; --line:#2c323b; --accent:#60a5fa; }
}
body { font-family: system-ui, -apple-system, "Segoe UI", sans-serif; line-height:1.6;
       color:var(--fg); background:var(--bg); margin:0; padding:48px 20px; }
main { max-width:640px; margin:0 auto; }
h1 { font-size:1.5rem; margin:0 0 4px; }
p.lead { color:var(--muted); margin:0 0 28px; }
h2 { font-size:0.8rem; text-transform:uppercase; letter-spacing:0.06em; color:var(--muted);
     margin:28px 0 8px; font-weight:600; }
.endpoint { display:flex; gap:8px; align-items:stretch; }
code#url { flex:1; background:var(--card); border:1px solid var(--line); border-radius:6px;
           padding:10px 12px; font-size:0.95rem; overflow-x:auto; white-space:nowrap; }
button { background:var(--accent); color:#fff; border:0; border-radius:6px; padding:10px 16px;
         font-size:0.9rem; cursor:pointer; white-space:nowrap; }
button:hover { filter:brightness(0.92); }
ul { padding-left:1.2em; margin:8px 0; }
a { color:var(--accent); }
.note { background:var(--card); border-left:3px solid var(--accent); border-radius:0 6px 6px 0;
        padding:12px 16px; margin:24px 0 0; font-size:0.95rem; }
footer { margin-top:36px; padding-top:16px; border-top:1px solid var(--line);
         color:var(--muted); font-size:0.85rem; }
</style>
</head>
<body>
<main>
<h1>This is an MCP endpoint, not a website</h1>
<p class="lead">There is nothing to browse here. The address belongs in the connector
settings of an MCP client, which talks to it over JSON-RPC.</p>

<h2>Endpoint URL</h2>
<div class="endpoint">
<code id="url">{{.Endpoint}}</code>
<button type="button" id="copy">Copy</button>
</div>

<h2>Authentication</h2>
<p>{{if .AuthRequired}}Required. The client is sent through OAuth on first
connect; an API key in the <code>Authorization</code> header works too.{{else}}None
configured — this endpoint accepts unauthenticated requests.{{end}}</p>

<h2>Where to paste it</h2>
<ul>
<li><a href="https://www.toolmesh.io/en/setup-claude/">Claude</a> — Settings &rarr; Connectors &rarr; Add custom connector</li>
<li><a href="https://www.toolmesh.io/en/setup-openai/">ChatGPT</a> — Settings &rarr; Connectors &rarr; Create</li>
<li><a href="https://www.toolmesh.io/en/getting-started/">All clients and setup docs</a></li>
</ul>

<div class="note">Seeing <code>Method not allowed</code> instead of this page? That is
the endpoint working: it answers POST with JSON-RPC, not GET with HTML.</div>

<footer>Served by <a href="https://www.toolmesh.io/">ToolMesh</a>, an MCP gateway.</footer>
</main>
<script>
document.getElementById('copy').addEventListener('click', function () {
  var button = this;
  var url = document.getElementById('url').textContent;
  var done = function () {
    button.textContent = 'Copied';
    setTimeout(function () { button.textContent = 'Copy'; }, 1500);
  };
  // navigator.clipboard needs a secure context; fall back to selecting the text
  // so a visitor on plain http can still copy with the keyboard.
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(url).then(done, select);
  } else {
    select();
  }
  function select() {
    var range = document.createRange();
    range.selectNodeContents(document.getElementById('url'));
    var sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
    button.textContent = 'Press Ctrl+C';
    setTimeout(function () { button.textContent = 'Copy'; }, 2500);
  }
});
</script>
</body>
</html>`))
