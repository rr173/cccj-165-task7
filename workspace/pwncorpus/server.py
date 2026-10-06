"""HTTP server: batch API, anonymous range API, publication review page.

Stdlib-only (ThreadingHTTPServer). Each request gets its own SQLite
connection. Error responses never echo submitted items.
"""
from __future__ import annotations

import hashlib
import html
import json
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import budget, core, db

MAX_BODY = 256 * 1024 * 1024  # 256 MiB request cap

SEC_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Cache-Control": "no-store",
}


def make_server(db_path: str, host: str, port: int) -> ThreadingHTTPServer:

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "PwnCorpus/1.0"

        # -- plumbing ------------------------------------------------------
        def log_message(self, fmt, *args):  # redact tokens from access log
            msg = re.sub(r"token=[^&\s]+", "token=REDACTED", fmt % args)
            sys.stderr.write("%s - %s\n" % (self.address_string(), msg))

        def _send(self, code, body, ctype="text/plain; charset=utf-8", headers=None):
            if isinstance(body, str):
                body = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in SEC_HEADERS.items():
                self.send_header(k, v)
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if body:
                self.wfile.write(body)

        def _json(self, code, obj, headers=None):
            self._send(code, json.dumps(obj, indent=2, sort_keys=True) + "\n",
                       "application/json; charset=utf-8", headers)

        def _error(self, code, msg):
            self._json(code, {"error": msg})

        def _body_json(self):
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0 or length > MAX_BODY:
                raise core.CorpusError("missing or oversized request body")
            try:
                return json.loads(self.rfile.read(length))
            except json.JSONDecodeError:
                raise core.CorpusError("invalid JSON body")

        def _token(self, conn):
            auth = self.headers.get("Authorization", "")
            token = None
            if auth.startswith("Bearer "):
                token = auth[7:].strip()
            else:
                qs = parse_qs(urlparse(self.path).query)
                token = qs.get("token", [None])[0]
            return core.lookup_token(conn, token) if token else None

        def _require(self, conn, scope):
            row = self._token(conn)
            if row is None:
                self._error(401, "missing or invalid token")
                return None
            if scope not in row["scopes"].split(","):
                self._error(403, f"token lacks required scope '{scope}'")
                return None
            return row

        def _require_admin(self, conn):
            """Budget admin routes: a VALID token of a different kind (e.g. a
            budget query token) is 403, never mistaken for missing auth."""
            row = self._token(conn)
            if row is None:
                # still a valid budget QUERY token? then it's a scope problem
                auth = self.headers.get("Authorization", "")
                raw = auth[7:].strip() if auth.startswith("Bearer ") else None
                if raw:
                    h = hashlib.sha256(raw.encode()).hexdigest()
                    brows = conn.execute(
                        "SELECT 1 FROM budget_tokens WHERE token_sha256=?",
                        (h,)).fetchall()
                    if brows:
                        self._error(403, "token lacks required scope"
                                         " 'budget-admin'")
                        return None
                self._error(401, "missing or invalid token")
                return None
            if "budget-admin" not in row["scopes"].split(","):
                self._error(403, "token lacks required scope 'budget-admin'")
                return None
            return row

        # -- routing -------------------------------------------------------
        def do_GET(self):
            path = urlparse(self.path).path
            conn = db.connect(db_path)
            try:
                if path == "/api/health":
                    return self._json(200, {"ok": True,
                                            "active_version": core.current_version(conn)})
                m = re.fullmatch(r"/api/range/([^/]+)", path)
                if m:
                    return self._range(conn, m.group(1))
                m = re.fullmatch(r"/api/budget/tenants/([^/]+)/status", path)
                if m:
                    if not self._require_admin(conn):
                        return
                    qs = parse_qs(urlparse(self.path).query)
                    ws = budget.parse_window(qs.get("window", [None])[0]) \
                        if qs.get("window", [None])[0] else None
                    return self._json(
                        200, budget.admin_status(conn, m.group(1), ws))
                if path == "/api/budget/status":
                    if not self._require_admin(conn):
                        return
                    qs = parse_qs(urlparse(self.path).query)
                    ws = budget.parse_window(qs.get("window", [None])[0]) \
                        if qs.get("window", [None])[0] else None
                    return self._json(200, budget.admin_status(conn, None, ws))
                if path == "/api/publications":
                    if not self._require(conn, "publish"):
                        return
                    return self._json(200, {"publications": core.list_publications(conn),
                                            "active_version": core.current_version(conn)})
                m = re.fullmatch(r"/api/publications/(\d+)", path)
                if m:
                    if not self._require(conn, "publish"):
                        return
                    return self._publication_detail(conn, int(m.group(1)))
                m = re.fullmatch(r"/api/publications/(\d+)/manifest", path)
                if m:  # public: manifests contain only hashes
                    return self._manifest(conn, int(m.group(1)))
                if path == "/review":
                    if not self._require(conn, "publish"):
                        return
                    return self._review_page(conn)
                return self._error(404, "not found")
            except core.CorpusError as exc:
                return self._error(400, str(exc))
            except budget.BudgetError as exc:
                return self._error(400, str(exc))
            except BrokenPipeError:  # client went away
                pass
            finally:
                conn.close()

        def do_POST(self):
            path = urlparse(self.path).path
            conn = db.connect(db_path)
            try:
                if path == "/api/batches":
                    if not self._require(conn, "ingest"):
                        return
                    return self._ingest(conn)
                m = re.fullmatch(r"/api/batches/([0-9a-f]{32})/retract", path)
                if m:
                    if not self._require(conn, "retract"):
                        return
                    return self._json(200, core.retract_batch(conn, m.group(1)))
                m = re.fullmatch(r"/api/batches/([0-9a-f]{32})/corrections", path)
                if m:
                    if not self._require(conn, "retract"):
                        return
                    payload = self._body_json()
                    return self._json(200, core.add_corrections(
                        conn, m.group(1), payload.get("items")))
                if path == "/api/publications/build":
                    if not self._require(conn, "publish"):
                        return
                    payload = self._body_json() if self.headers.get("Content-Length") else {}
                    k = payload.get("k", core.DEFAULT_THRESHOLD_K)
                    return self._json(201, core.build_candidate(conn, int(k)))
                m = re.fullmatch(r"/api/publications/(\d+)/activate", path)
                if m:
                    if not self._require(conn, "publish"):
                        return
                    length = int(self.headers.get("Content-Length") or 0)
                    payload = self._body_json() if length else {}
                    return self._json(200, core.activate(
                        conn, int(m.group(1)),
                        expected_manifest=payload.get("expected_manifest")))
                m = re.fullmatch(r"/api/publications/(\d+)/refresh", path)
                if m:
                    if not self._require(conn, "publish"):
                        return
                    return self._json(200, core.refresh_candidate(conn, int(m.group(1))))
                if path == "/review/activate":
                    return self._review_activate(conn)
                if path == "/review/refresh":
                    return self._review_refresh(conn)
                # ---- per-caller privacy budget administration -------------
                if path == "/api/budget/tenants/tokens":
                    if not self._require_admin(conn):
                        return
                    payload = self._body_json()
                    return self._json(201, budget.issue_token(
                        conn, payload.get("tenant_id"), payload.get("label")))
                m = re.fullmatch(r"/api/budget/tenants/([^/]+)/topup", path)
                if m:
                    if not self._require_admin(conn):
                        return
                    payload = self._body_json()
                    return self._json(200, budget.topup(
                        conn, m.group(1), int(payload.get("amount", 0)),
                        str(payload.get("note", ""))))
                m = re.fullmatch(r"/api/budget/tenants/([^/]+)/freeze", path)
                if m:
                    if not self._require_admin(conn):
                        return
                    return self._json(200, budget.freeze_tenant(conn, m.group(1)))
                m = re.fullmatch(r"/api/budget/tenants/([^/]+)/unfreeze", path)
                if m:
                    if not self._require_admin(conn):
                        return
                    return self._json(200,
                                      budget.unfreeze_tenant(conn, m.group(1)))
                m = re.fullmatch(r"/api/budget/tokens/([^/]+)/revoke", path)
                if m:
                    if not self._require_admin(conn):
                        return
                    return self._json(200, budget.revoke_token(conn, m.group(1)))
                return self._error(404, "not found")
            except core.NotFound as exc:
                return self._error(404, str(exc))
            except core.Conflict as exc:
                return self._error(409, str(exc))
            except core.CorpusError as exc:
                return self._error(400, str(exc))
            except budget.BudgetError as exc:
                return self._error(400, str(exc))
            except (TypeError, ValueError):
                return self._error(400, "invalid numeric parameter")
            except BrokenPipeError:
                pass
            finally:
                conn.close()

        # -- handlers ------------------------------------------------------
        def _range(self, conn, prefix):
            # When the privacy-budget module is enabled every range read is
            # gated by a per-caller daily budget. When it is not initialised
            # the endpoint stays fully anonymous (existing behaviour).
            if budget.is_initialised(conn):
                auth = self.headers.get("Authorization", "")
                raw = []
                if auth.startswith("Bearer "):
                    raw = [t.strip() for t in auth[len("Bearer "):].split(",")
                           if t.strip()]
                try:
                    result = budget.consume(
                        conn, raw, prefix,
                        idem_key=self.headers.get("Idempotency-Key"))
                except budget.BudgetAuth:
                    return self._error(401, "missing or invalid budget token")
                except budget.NoActivePublication:
                    return self._error(503, "no active publication")
                bhdr = {
                    "X-Budget-Tenant": result["tenant_id"],
                    "X-Budget-Remaining": str(result["remaining_after"]),
                    "X-Budget-Policy-Revision": str(result["policy_revision"]),
                    "X-Corpus-Version": str(result["version"]),
                }
                if result["status"] == "denied":
                    # Identifiable only by the caller's own state; the body
                    # never states whether the prefix bucket exists.
                    if result["http_result"] == 429:
                        bhdr["Retry-After"] = str(budget.seconds_until_next_window(
                            result["window_start"]))
                    return self._json(result["http_result"],
                                      {"error": result["reason"]}, headers=bhdr)
                if result["http_result"] == 404:
                    return self._json(404, {"error": "prefix not found"},
                                      headers=bhdr)
                bhdr["Cache-Control"] = "no-store"
                return self._send(200, result["body"],
                                  "text/plain; charset=utf-8", bhdr)

            version, body = core.query_range(conn, prefix)
            hdr = {"X-Corpus-Version": str(version)} if version else {}
            if version is None:
                return self._error(503, "no active publication")
            if body is None:
                return self._json(404, {"error": "prefix not found"}, headers=hdr)
            hdr["Cache-Control"] = "public, max-age=60"
            return self._send(200, body, "text/plain; charset=utf-8", hdr)

        def _ingest(self, conn):
            payload = self._body_json()
            result = core.ingest_batch(
                conn,
                payload.get("source"),
                payload.get("items"),
                payload.get("idempotency_key"),
            )
            payload.clear()  # drop raw material reference promptly
            return self._json(200 if result["duplicate"] else 201, result)

        def _publication_detail(self, conn, version):
            pub = core.get_publication(conn, version)
            active_v = core.current_version(conn)
            out = {"publication": pub, "active_version": active_v}
            if pub["status"] == "candidate":
                pub["stale"] = pub["corpus_state"] != core.corpus_state(conn)
                if active_v is not None:
                    out["diff_vs_active"] = core.diff_versions(conn, active_v, version)
            return self._json(200, out)

        def _manifest(self, conn, version):
            manifest = core.manifest_for(conn, version)
            manifest["manifest_sha256"] = hashlib.sha256(
                core.canonical_json(manifest).encode()).hexdigest()
            pub = core.get_publication(conn, version)
            if manifest["manifest_sha256"] != pub["manifest_sha256"]:
                return self._error(500, "stored manifest hash mismatch")
            manifest["status"] = pub["status"]
            return self._json(200, manifest)

        def _review_activate(self, conn):
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0 or length > 65536:
                return self._error(400, "bad form")
            form = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
            token = form.get("token", [""])[0]
            row = core.lookup_token(conn, token) if token else None
            if row is None or "publish" not in row["scopes"].split(","):
                return self._error(403, "invalid token or missing 'publish' scope")
            try:
                version = int(form.get("version", ["0"])[0])
            except ValueError:
                return self._error(400, "bad version")
            expected = form.get("expected_manifest", [None])[0] or None
            try:
                core.activate(conn, version, expected_manifest=expected)
            except core.CorpusError as exc:
                return self._error(409, str(exc))
            tok_q = f"?token={html.escape(token)}"
            self._send(
                200,
                f"<html><body><h2>Publication v{version} activated</h2>"
                f"<p><a href='/review{tok_q}'>back to review</a></p></body></html>",
                "text/html; charset=utf-8",
            )

        def _review_refresh(self, conn):
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0 or length > 65536:
                return self._error(400, "bad form")
            form = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
            token = form.get("token", [""])[0]
            row = core.lookup_token(conn, token) if token else None
            if row is None or "publish" not in row["scopes"].split(","):
                return self._error(403, "invalid token or missing 'publish' scope")
            try:
                version = int(form.get("version", ["0"])[0])
            except ValueError:
                return self._error(400, "bad version")
            try:
                core.refresh_candidate(conn, version)
            except core.CorpusError as exc:
                return self._error(409, str(exc))
            tok_q = f"?token={html.escape(token)}"
            self._send(
                200,
                f"<html><body><h2>Candidate v{version} refreshed from current"
                " source data (threshold k kept)</h2>"
                f"<p><a href='/review{tok_q}'>back to review</a></p></body></html>",
                "text/html; charset=utf-8",
            )

        # -- review page ---------------------------------------------------
        def _review_page(self, conn):
            state = core.review_state(conn)
            qs = parse_qs(urlparse(self.path).query)
            token_q = qs.get("token", [""])[0]
            e = html.escape

            def pub_card(title, pub):
                if not pub:
                    return f"<div class='card'><h3>{title}</h3><p>none</p></div>"
                rows = "".join(
                    f"<tr><th>{e(str(k))}</th><td>{e(str(pub[k]))}</td></tr>"
                    for k in ("version", "status", "threshold_k", "prefix_len",
                              "bucket_count", "suffix_count",
                              "suppressed_bucket_count", "created_at",
                              "activated_at", "retired_at", "corpus_sha256",
                              "corpus_state", "manifest_sha256")
                )
                return f"<div class='card'><h3>{title}</h3><table>{rows}</table></div>"

            diff_html = ""
            if state["diff"]:
                d = state["diff"]
                sample = "".join(
                    f"<tr><td>{e(t)}</td><td>{e(p)}</td><td>{e(s)}</td>"
                    f"<td>{e(str(o))}</td><td>{e(str(n))}</td></tr>"
                    for t, p, s, o, n in d["sample"]
                )
                diff_html = f"""
                <div class='card'><h3>Diff: active v{d['from_version']} &rarr; candidate v{d['to_version']}</h3>
                <p>buckets added: {len(d['buckets_added'])} &nbsp;
                   buckets removed: {len(d['buckets_removed'])} &nbsp;
                   suffixes added: {d['suffixes_added']} &nbsp;
                   suffixes removed: {d['suffixes_removed']} &nbsp;
                   counts changed: {d['counts_changed']}</p>
                <table><tr><th>change</th><th>prefix</th><th>suffix</th>
                <th>old count</th><th>new count</th></tr>{sample}</table>
                <p class='muted'>showing at most 100 sampled rows</p></div>"""

            action_html = ""
            candidate = state["candidate"]
            if candidate:
                v = candidate["version"]
                if candidate["stale"]:
                    action_html = f"""
                <div class='card stale'><h3>Candidate v{v} is STALE</h3>
                <p>Source data changed after this draft was built (new batch,
                retraction or corrections). Activating the old snapshot would
                overwrite the newer source state, so activation is blocked.
                Refresh the draft to rebuild it from current data &mdash; the
                threshold k={candidate['threshold_k']} is kept &mdash; then
                review and activate as usual.</p>
                <form method='post' action='/review/refresh'>
                  <input type='hidden' name='version' value='{v}'>
                  <label>re-enter publish token:
                    <input type='password' name='token' required></label>
                  <button type='submit'>Refresh candidate v{v}</button>
                </form></div>"""
                else:
                    action_html = f"""
                <div class='card'><h3>Activate candidate v{v}</h3>
                <p>The draft matches current source data
                (corpus-state {candidate['corpus_state']}).</p>
                <form method='post' action='/review/activate'
                      onsubmit="return confirm('Activate publication v{v}? Old version stays verifiable but stops serving queries.');">
                  <input type='hidden' name='version' value='{v}'>
                  <input type='hidden' name='expected_manifest'
                         value='{e(candidate["manifest_sha256"])}'>
                  <label>re-enter publish token:
                    <input type='password' name='token' required></label>
                  <button type='submit'>Activate v{v}</button>
                </form></div>"""

            batches = "".join(
                f"<tr><td>{e(b['batch_id'][:12])}&hellip;</td><td>{e(b['source'])}</td>"
                f"<td>{b['item_count']}</td><td>{b['occurrence_count']}</td>"
                f"<td>{e(b['status'])}</td><td>{e(b['created_at'])}</td></tr>"
                for b in state["batches"]
            )
            history = "".join(
                f"<tr><td>{p['version']}</td><td>{e(p['status'])}</td>"
                f"<td>{p['threshold_k']}</td><td>{p['bucket_count']}</td>"
                f"<td>{p['suffix_count']}</td>"
                f"<td class='mono'>{e(p['manifest_sha256'][:16])}&hellip;</td>"
                f"<td>{e(str(p['activated_at']))}</td></tr>"
                for p in state["publications"]
            )
            s = state["stats"]
            cand_title = "Latest candidate (not serving)"
            if candidate and candidate["stale"]:
                cand_title += " — STALE: source data changed"
            page = f"""<!doctype html><html><head><meta charset='utf-8'>
<title>pwncorpus publication review</title><style>
body{{font-family:system-ui,sans-serif;margin:2rem;background:#f6f7f9;color:#222}}
.card{{background:#fff;border:1px solid #ddd;border-radius:8px;padding:1rem;margin:1rem 0}}
.stale{{border-color:#c33;background:#fff5f5}}
table{{border-collapse:collapse;font-size:.9rem}}td,th{{border:1px solid #ccc;padding:.3rem .6rem;text-align:left}}
th{{background:#eee}}.mono{{font-family:monospace}}.muted{{color:#777;font-size:.8rem}}
button{{padding:.4rem 1rem}}</style></head><body>
<h2>Publication review</h2>
<p>active batches: {s['active_batches']} &nbsp; retracted: {s['retracted_batches']}
   &nbsp; corrections pending: {s['corrections']}
   &nbsp; source-state token: {state['corpus_state']}</p>
{pub_card('Active publication (serving queries)', state['active'])}
{pub_card(cand_title, candidate)}
{diff_html}
{action_html}
<div class='card'><h3>Recent batches</h3>
<table><tr><th>batch</th><th>source</th><th>distinct</th><th>occurrences</th>
<th>status</th><th>created</th></tr>{batches}</table></div>
<div class='card'><h3>Publication history (retired versions remain verifiable offline)</h3>
<table><tr><th>v</th><th>status</th><th>k</th><th>buckets</th><th>suffixes</th>
<th>manifest</th><th>activated</th></tr>{history}</table></div>
</body></html>"""
            return self._send(200, page, "text/html; charset=utf-8")

    srv = ThreadingHTTPServer((host, port), Handler)
    srv.daemon_threads = True
    return srv
