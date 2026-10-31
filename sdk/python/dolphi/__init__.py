"""Synchronous Community SDK; no automatic retries of state-changing requests."""
import json
import urllib.error
import urllib.parse
import urllib.request


class DolphiError(Exception):
    def __init__(self, status, code):
        self.status = status
        self.code = code
        super().__init__(f"Dolphi request failed: {status} {code}")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # Never forward bearer secrets to another destination.


class Client:
    def __init__(self, base_url, token, timeout=5):
        parsed = urllib.parse.urlsplit(base_url)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or parsed.username or parsed.password or parsed.query or parsed.fragment
                or parsed.path not in {"", "/"}):
            raise ValueError("base URL must be an HTTP(S) origin without credentials or path")
        if parsed.scheme == "http" and parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError("plaintext HTTP is allowed only for loopback")
        if len(token) != 64 or any(c not in "0123456789abcdefABCDEF" for c in token):
            raise ValueError("invalid credential format")
        if not 0 < timeout <= 30:
            raise ValueError("timeout must be between 0 and 30 seconds")
        self._url = base_url.rstrip("/")
        self._token = token
        self._timeout = timeout
        # Explicit HTTPS verification uses Python's default SSL context. Ignore
        # ambient proxy variables, which could otherwise intercept bearer traffic.
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())

    def __repr__(self):
        return "Dolphi Client(credentials=<redacted>)"

    def _request(self, path, body=None):
        encoded = None if body is None else json.dumps(body, ensure_ascii=False).encode("utf-8")
        if encoded is not None and len(encoded) > 96 * 1024:
            raise DolphiError(413, "body_limit")
        request = urllib.request.Request(self._url + path, data=encoded,
            headers={"Authorization": "Bearer " + self._token, "Content-Type": "application/json"})
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                data = response.read(2 * 1024 * 1024 + 1)
                if len(data) > 2 * 1024 * 1024:
                    raise DolphiError(0, "response_limit")
                return json.loads(data)
        except urllib.error.HTTPError as error:
            # Do not include arbitrary server response bodies, URLs or headers.
            code = {400:"invalid_request", 401:"unauthorized", 403:"forbidden",
                    404:"not_found", 409:"conflict", 413:"body_limit", 429:"quota_exceeded"}.get(error.code, "http_error")
            error.close()
            raise DolphiError(error.code, code) from None
        except (urllib.error.URLError, TimeoutError, OSError, ValueError, RecursionError):
            raise DolphiError(0, "transport_or_protocol_error") from None

    def me(self): return self._request("/v1/me")
    def _mutation(self, path, body, operation_id):
        if operation_id is not None:
            if (not isinstance(operation_id, str) or not 1 <= len(operation_id) <= 128
                    or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for c in operation_id)):
                raise ValueError("operation_id must be 1-128 ASCII letters, digits, underscores or hyphens")
            body["operation_id"] = operation_id
        return self._request(path, body)

    def remember(self, key, value, *, operation_id=None): return self._mutation("/v1/memory/remember", {"key":key,"value":value}, operation_id)
    def recall(self, key): return self._request("/v1/memory/recall", {"key":key})["value"]
    def read_shared(self, key): return self._request("/v1/shared/read", {"key":key})["value"]
    def propose(self, key, value, *, operation_id=None): return self._mutation("/v1/proposals/create", {"key":key,"value":value}, operation_id)["id"]
    def operation_status(self, operation_id): return self._request("/v1/operations/status", {"id":operation_id})["operation"]
    def create_agent(self, ttl_seconds=3600): return self._request("/v1/admin/agents", {"ttl_seconds":ttl_seconds})
    def issue_credential(self, agent_id, ttl_seconds=3600): return self._request("/v1/admin/credentials/issue", {"agent_id":agent_id,"ttl_seconds":ttl_seconds})
    def revoke_credential(self, credential_id, *, operation_id=None): return self._mutation("/v1/admin/credentials/revoke", {"id":credential_id}, operation_id)
    def revoke_agent(self, agent_id, *, operation_id=None): return self._mutation("/v1/admin/agents/revoke", {"id":agent_id}, operation_id)
    def inspect(self, proposal_id): return self._request("/v1/admin/proposals/inspect", {"id":proposal_id})["proposal"]
    def approve(self, proposal_id, *, operation_id=None): return self._mutation("/v1/admin/proposals/approve", {"id":proposal_id}, operation_id)
    def reject(self, proposal_id, *, operation_id=None): return self._mutation("/v1/admin/proposals/reject", {"id":proposal_id}, operation_id)
    def audit(self, after=0, limit=100): return self._request("/v1/admin/audit", {"after":after,"limit":limit})["events"]
