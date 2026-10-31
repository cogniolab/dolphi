"""Real socket/process acceptance tests. All credentials/data are temporary."""
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import subprocess
import sys
import tempfile
import unittest
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from dolphi import Client, DolphiError


def read_line(process):
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        if not selector.select(10):
            raise AssertionError("subprocess response timed out")
    line = process.stdout.readline()
    if not line:
        raise AssertionError("subprocess exited without response")
    return line


class Integration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="dolphi-api-")
        cls.directory = Path(cls.temp.name)
        default_binary = Path(__file__).resolve().parents[3] / "target/debug/dolphi-server"
        cls.binary = Path(os.environ.get("DOLPHI_TEST_SERVER", str(default_binary))).resolve()
        cls.db = str(cls.directory/"community.db")
        cls.key = str(cls.directory/"key")
        cls.token_file = str(cls.directory/"owner-token")
        subprocess.run([str(cls.binary),"init",cls.db,cls.key,cls.token_file],check=True,capture_output=True)
        cls.owner_token = Path(cls.token_file).read_text()
        cls.start()

    @classmethod
    def start(cls):
        cls.server = subprocess.Popen([str(cls.binary),"serve",cls.db,cls.key,"0"],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        line = read_line(cls.server).decode()
        cls.url = line.split(" at ",1)[1].split(" ",1)[0]
        cls.owner = Client(cls.url,cls.owner_token)

    @classmethod
    def stop(cls):
        cls.server.send_signal(signal.SIGINT)
        try: cls.server.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            cls.server.kill(); cls.server.communicate()

    @classmethod
    def tearDownClass(cls):
        cls.stop()
        cls.temp.cleanup()

    def agent(self):
        registration = self.owner.create_agent(300)
        return Client(self.url,registration["secret"]), registration

    def test_mcp_private_file_credentials_do_not_enter_environment(self):
        _,registration=self.agent()
        path=self.directory/'private-mcp.token'
        path.write_text(registration['secret']);path.chmod(0o600)
        env=os.environ.copy();env.pop('DOLPHI_TOKEN',None)
        env.update({'DOLPHI_URL':self.url,'DOLPHI_TOKEN_FILE':str(path)})
        request=json.dumps({'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-06-18'}})+'\n'
        def invoke(environment):
            result=subprocess.run([sys.executable,'-m','dolphi.mcp'],input=request,env=environment,capture_output=True,text=True,timeout=15)
            self.assertNotIn(registration['secret'],result.stdout+result.stderr)
            return result
        result=invoke(env)
        self.assertEqual(result.returncode,0)
        self.assertIn('result',json.loads(result.stdout))
        path.chmod(0o644)
        self.assertEqual(invoke(env).returncode,1)
        path.chmod(0o600)
        alias=self.directory/'private-mcp-alias';alias.symlink_to(path)
        self.assertEqual(invoke(dict(env,DOLPHI_TOKEN_FILE=str(alias))).returncode,1)
        fifo=self.directory/'private-mcp-fifo';os.mkfifo(fifo,0o600)
        self.assertEqual(invoke(dict(env,DOLPHI_TOKEN_FILE=str(fifo))).returncode,1)
        self.assertEqual(invoke(dict(env,DOLPHI_TOKEN=registration['secret'])).returncode,1)

    def test_durable_retry_survives_restart_and_rejects_changed_input(self):
        agent, registration = self.agent()
        operation_id = uuid.uuid4().hex
        proposal = agent.propose("retry-key", "value", operation_id=operation_id)
        receipt = agent.operation_status(operation_id)
        self.assertEqual(receipt["status"], "committed")
        self.stop(); self.start()
        agent = Client(self.url, registration["secret"])
        self.assertEqual(agent.propose("retry-key", "value", operation_id=operation_id), proposal)
        self.assertEqual(agent.operation_status(operation_id), receipt)
        with self.assertRaises(DolphiError) as failure:
            agent.propose("retry-key", "changed", operation_id=operation_id)
        self.assertEqual(failure.exception.status, 409)
        other, _ = self.agent()
        self.assertIsNone(other.operation_status(operation_id))
        self.assertIsNone(self.owner.operation_status(operation_id))
        self.owner.approve(proposal, operation_id=operation_id)
        self.owner.approve(proposal, operation_id=operation_id)
        self.assertEqual(agent.read_shared("retry-key")["version"], 1)
        self.assertEqual(sum(e["action"]=="proposal.created" and e["subject"]==proposal for e in self.owner.audit(limit=1000)),1)

    def test_disconnect_without_reading_response_then_concurrent_retry(self):
        from concurrent.futures import ThreadPoolExecutor
        agent, registration = self.agent()
        operation_id = uuid.uuid4().hex
        body = json.dumps({"key":"dropped-response","value":"12","operation_id":operation_id}).encode()
        from urllib.parse import urlsplit
        url = urlsplit(self.url)
        request = (f"POST /v1/proposals/create HTTP/1.1\r\nHost: {url.netloc}\r\nAuthorization: Bearer {registration['secret']}\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body
        with socket.create_connection((url.hostname,url.port),timeout=5) as connection:
            connection.sendall(request)
            # Discard the response entirely: the caller cannot know the outcome.
        def retry(_):
            return Client(self.url,registration["secret"]).propose("dropped-response","12",operation_id=operation_id)
        with ThreadPoolExecutor(max_workers=8) as pool:
            proposals = list(pool.map(retry,range(8)))
        self.assertEqual(len(set(proposals)),1)
        self.assertEqual(agent.operation_status(operation_id)["result"]["id"],proposals[0])
        self.assertEqual(sum(e["action"]=="proposal.created" and e["subject"]==proposals[0] for e in self.owner.audit(limit=1000)),1)
        self.owner.revoke_credential(registration["credential_id"],operation_id=uuid.uuid4().hex)
        with self.assertRaises(DolphiError) as failure: agent.operation_status(operation_id)
        self.assertEqual(failure.exception.status,401)

    def test_mcp_explicit_operation_id_replays_and_status_is_scoped(self):
        from dolphi.mcp import Bridge
        agent, _ = self.agent()
        bridge = Bridge(agent)
        def invoke(identifier,method,params):
            return bridge.handle({"jsonrpc":"2.0","id":identifier,"method":method,"params":params})
        invoke(1,"initialize",{"protocolVersion":"2025-06-18"})
        bridge.handle({"jsonrpc":"2.0","method":"notifications/initialized"})
        operation_id=uuid.uuid4().hex
        params={"name":"proposal_create","arguments":{"key":"mcp-retry","value":"value","operation_id":operation_id}}
        one=invoke(2,"tools/call",params)["result"]["structuredContent"]
        two=invoke(3,"tools/call",params)["result"]["structuredContent"]
        self.assertEqual(one,two)
        receipt=invoke(4,"tools/call",{"name":"operation_status","arguments":{"id":operation_id}})["result"]["structuredContent"]
        self.assertEqual(receipt["operation"]["result"],one)
        invalid=invoke(5,"tools/call",{"name":"operation_status","arguments":{"id":operation_id,"agent_id":"victim"}})
        self.assertEqual(invalid["error"]["code"],-32602)

    def test_two_agent_inventory_and_summary_workflow(self):
        stock_key = "inventory-stock-" + uuid.uuid4().hex
        inventory, _ = self.agent()
        summary, _ = self.agent()
        inventory.remember("supplier-note","private supplier quote")
        summary.remember("task","Prepare stock summary")
        self.assertIsNone(summary.recall("supplier-note"))
        proposal = inventory.propose(stock_key,"12 units")
        self.assertIsNone(summary.read_shared(stock_key))
        with self.assertRaises(DolphiError) as failure: inventory.approve(proposal)
        self.assertEqual(failure.exception.status,403)
        self.assertEqual(self.owner.inspect(proposal)["value"],"12 units")
        self.owner.approve(proposal)
        summary.remember("summary",summary.read_shared(stock_key)["value"])
        self.assertEqual(summary.recall("summary"),"12 units")
        with self.assertRaises(DolphiError) as failure: self.owner.approve(proposal)
        self.assertEqual(failure.exception.status,409)

    def test_runnable_two_agent_example(self):
        example = Path(__file__).resolve().parents[1]/"examples/two_agents.py"
        for _ in range(2):
            result = subprocess.run([sys.executable,str(example)],env={**os.environ,"DOLPHI_URL":self.url,"DOLPHI_OWNER_TOKEN_FILE":self.token_file},capture_output=True,text=True,timeout=15)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn("PASS: two authenticated workers",result.stdout)
            self.assertNotIn(self.owner_token,result.stdout+result.stderr)

    def test_memory_and_credentials_survive_actual_server_restart(self):
        agent, registration = self.agent()
        agent.remember("restart","persistent")
        self.stop(); self.start()
        recovered = Client(self.url,registration["secret"])
        self.assertEqual(recovered.recall("restart"),"persistent")

    def test_revocation_blocks_existing_client_and_client_repr_redacts_secret(self):
        agent, registration = self.agent()
        self.assertNotIn(registration["secret"],repr(agent))
        self.owner.revoke_credential(registration["credential_id"])
        with self.assertRaises(DolphiError) as failure: agent.recall("key")
        self.assertEqual(failure.exception.status,401)
        self.assertNotIn(registration["secret"],str(failure.exception))

    def test_stale_proposal_and_bounded_audit_pagination(self):
        first, _ = self.agent(); second, _ = self.agent()
        a = first.propose("competing","one"); b = second.propose("competing","two")
        self.owner.approve(a)
        with self.assertRaises(DolphiError) as failure: self.owner.approve(b)
        self.assertEqual(failure.exception.status,409)
        self.owner.reject(b)
        first_page = self.owner.audit(limit=2)
        second_page = self.owner.audit(after=first_page[-1]["sequence"],limit=2)
        self.assertTrue(all(e["sequence"]>first_page[-1]["sequence"] for e in second_page))

    def test_mcp_subprocess_discovery_isolation_and_owner_tool_denial(self):
        agent, registration = self.agent()
        env = {**os.environ,"DOLPHI_URL":self.url,"DOLPHI_TOKEN":registration["secret"]}
        process = subprocess.Popen([sys.executable,"-m","dolphi.mcp"],env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
        def request(identifier, method, params=None):
            packet = {"jsonrpc":"2.0","method":method,"params":params or {}}
            if identifier is not None: packet["id"] = identifier
            process.stdin.write(json.dumps(packet).encode()+b"\n"); process.stdin.flush()
            return json.loads(read_line(process)) if identifier is not None else None
        try:
            process.stdin.write(b"not-json\n"); process.stdin.flush()
            self.assertEqual(json.loads(read_line(process))["error"]["code"],-32700)
            process.stdin.write(b"["*1100+b"]"*1100+b"\n"); process.stdin.flush()
            # Parsers differ in nesting support: rejected syntax or unsupported
            # batch are both controlled errors; the process must remain usable.
            self.assertIn(json.loads(read_line(process))["error"]["code"],(-32700,-32600))
            self.assertEqual(request(0,"tools/list")["error"]["code"],-32002)
            initialized = request(1,"initialize",{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"acceptance","version":"1"}})
            self.assertEqual(initialized["result"]["protocolVersion"],"2025-06-18")
            request(None,"notifications/initialized")
            tools = request(2,"tools/list")["result"]["tools"]
            self.assertEqual({t["name"] for t in tools},{"memory_remember","memory_recall","shared_read","proposal_create","operation_status"})
            result = request(3,"tools/call",{"name":"memory_remember","arguments":{"key":"via-mcp","value":"saved"}})
            self.assertFalse(result["result"]["isError"])
            self.assertEqual(agent.recall("via-mcp"),"saved")
            blocked = request(4,"tools/call",{"name":"approve","arguments":{"id":"fake"}})
            self.assertEqual(blocked["error"]["code"],-32602)
            spoofed = request(5,"tools/call",{"name":"memory_recall","arguments":{"key":"via-mcp","agent_id":"victim"}})
            self.assertEqual(spoofed["error"]["code"],-32602)
            self.owner.revoke_credential(registration["credential_id"])
            self.assertEqual(request(6,"tools/list")["error"]["code"],-32001)
        finally:
            process.stdin.close(); process.wait(timeout=10)
            process.stdout.close(); process.stderr.close()

    def test_mcp_rejects_owner_credentials(self):
        from dolphi.mcp import Bridge
        bridge = Bridge(self.owner)
        reply = bridge.handle({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}})
        self.assertEqual(reply["error"]["code"],-32001)

    def test_unsafe_urls_and_redirects_do_not_forward_bearer_credentials(self):
        token = "a"*64
        for url in ["http://remote.example", "http://user:pass@127.0.0.1", "http://127.0.0.1/?token=x", "file:///tmp/db"]:
            with self.assertRaises(ValueError): Client(url,token)
        class Redirect(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302); self.send_header("Location","http://127.0.0.1:1/stolen"); self.end_headers()
            def log_message(self,*args): pass
        server = HTTPServer(("127.0.0.1",0),Redirect)
        thread = Thread(target=server.serve_forever,daemon=True); thread.start()
        try:
            with self.assertRaises(DolphiError) as failure: Client(f"http://127.0.0.1:{server.server_port}",token).me()
            self.assertEqual(failure.exception.status,302)
        finally: server.shutdown(); server.server_close(); thread.join()

    def test_slow_incomplete_headers_are_closed_before_authentication(self):
        from urllib.parse import urlsplit
        address = urlsplit(self.url)
        with socket.create_connection((address.hostname,address.port),timeout=7) as connection:
            connection.sendall(b"GET /health HTTP/1.1\r\nHost: ")
            connection.settimeout(7)
            reply = connection.recv(1024)
            self.assertTrue(reply == b"" or reply.startswith(b"HTTP/1.1 408"))

    def test_mcp_parse_errors_and_uninitialized_calls_are_safe(self):
        from dolphi.mcp import Bridge
        agent, _ = self.agent()
        bridge = Bridge(agent)
        self.assertEqual(bridge.handle([])["error"]["code"],-32600)
        self.assertEqual(bridge.handle({"jsonrpc":"2.0","id":True,"method":"ping"})["error"]["code"],-32600)
        self.assertEqual(bridge.handle({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}})["error"]["code"],-32002)


if __name__ == "__main__": unittest.main()
