import json, os, sys, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import llm_agent
from data import make_set
from defenses import Defenses


def test_parse_calls_handles_fences_and_junk():
    t = '```json\n{"calls":[{"tool":"delete_file","args":{"file":"a.txt"}},{"tool":"rm","args":{}}]}\n```'
    assert llm_agent.parse_calls(t) == [("delete_file", {"file": "a.txt"})]
    assert llm_agent.parse_calls("no json here") == []
    assert llm_agent.parse_calls('{"calls": [{"tool":"send_email","args":{"to":"a"}}]}') == []


def test_run_llm_gate_blocks_hijack():
    scn = next(s for s in make_set(0, "test", 50) if s.goal["kind"] == "delete")
    bad = json.dumps({"calls": [{"tool": "delete_file", "args": {"file": scn.goal["file"]}}]})
    ex, _ = llm_agent.run_llm(scn, None, lambda m: bad)
    assert ex
    ex, _ = llm_agent.run_llm(scn, Defenses(gate=True), lambda m: bad)
    assert ex == [] or all(c[1].get("file") != scn.goal["file"] for c in ex)


def test_ollama_chat_over_http():
    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            assert body["model"] == "m" and body["stream"] is False
            out = json.dumps({"message": {"content": '{"calls": []}'}}).encode()
            self.send_response(200); self.send_header("Content-Length", str(len(out))); self.end_headers()
            self.wfile.write(out)
        def log_message(self, *a): pass
    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    chat = llm_agent.ollama_chat("m", f"http://127.0.0.1:{srv.server_port}")
    assert llm_agent.parse_calls(chat([{"role": "user", "content": "hi"}])) == []
    srv.shutdown()
