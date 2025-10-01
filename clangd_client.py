import subprocess
import json
import threading
import os
import queue

# Shared queue to collect responses from clangd
responses = queue.Queue()

# LSP token legend (simplified default; clangd may override)
TOKEN_TYPES = [
    "namespace", "type", "class", "enum", "interface", "struct",
    "typeParameter", "parameter", "variable", "property",
    "enumMember", "event", "function", "method", "macro",
    "keyword", "modifier", "comment", "string", "number",
    "regexp", "operator"
]

TOKEN_MODIFIERS = [
    "declaration", "definition", "readonly", "static", "deprecated",
    "abstract", "async", "modification", "documentation",
    "defaultLibrary", "inactive"
]

def send_msg(proc, msg):
    body = json.dumps(msg)
    header = f"Content-Length: {len(body)}\r\n\r\n"
    proc.stdin.write(header.encode())
    proc.stdin.write(body.encode())
    proc.stdin.flush()

def read_msgs(proc):
    """Continuously read clangd JSON-RPC responses"""
    while True:
        # Read headers
        header = b""
        while not header.endswith(b"\r\n\r\n"):
            chunk = proc.stdout.read(1)
            if not chunk:
                return
            header += chunk
        headers = header.decode().split("\r\n")
        length = 0
        for h in headers:
            if h.lower().startswith("content-length:"):
                length = int(h.split(":")[1].strip())
        # Read body
        body = proc.stdout.read(length).decode()
        msg = json.loads(body)
        responses.put(msg)

def extract_token_text(text, token):
    lines = text.splitlines()
    line = token["line"] - 1   # convert back to 0-based
    col = token["col"] - 1     # convert back to 0-based
    length = token["length"]
    if line < len(lines) and col < len(lines[line]):
        return lines[line][col:col+length]
    return ""


def decode_semantic_tokens(data, token_types, token_modifiers):
    tokens = []
    line = 0
    char = 0
    for i in range(0, len(data), 5):
        line_delta, char_delta, length, type_idx, mod_bits = data[i:i+5]
        if line_delta == 0:
            char += char_delta
        else:
            line += line_delta
            char = char_delta
        token_type = token_types[type_idx] if type_idx < len(token_types) else f"type{type_idx}"
        modifiers = [token_modifiers[j] for j in range(len(token_modifiers)) if (mod_bits >> j) & 1]
        tokens.append({
            "line": line + 1,  # 1-based
            "col": char + 1,
            "length": length,
            "type": token_type,
            "modifiers": modifiers
        })
    return tokens

def main(filepath):
    if not os.path.isfile(filepath):
        print(f"File not found: {filepath}")
        return

    proc = subprocess.Popen(
        ["/root/.vscode-server/data/User/globalStorage/llvm-vs-code-extensions.vscode-clangd/install/20.1.8/clangd_20.1.8/bin/clangd", "--enable-config"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    # Start reader thread
    t = threading.Thread(target=read_msgs, args=(proc,), daemon=True)
    t.start()

    # 1. Initialize
    init_msg = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"processId": None, "rootUri": None, "capabilities": {}}
    }
    send_msg(proc, init_msg)

    # 2. Open file
    with open(filepath, "r") as f:
        text = f.read()
    did_open = {
        "jsonrpc": "2.0",
        "method": "textDocument/didOpen",
        "params": {
            "textDocument": {
                "uri": "file://" + os.path.abspath(filepath),
                "languageId": "c",
                "version": 1,
                "text": text
            }
        }
    }
    send_msg(proc, did_open)

    # 3. Request semantic tokens
    sem_tokens_msg = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "textDocument/documentSymbol",
        "params": {"textDocument": {"uri": "file://" + os.path.abspath(filepath)}}
    }
    send_msg(proc, sem_tokens_msg)

    # 4. Wait for response
    while True:
        msg = responses.get()

        # Handle initialize response
        if msg.get("id") == 1 and "result" in msg:
            legend = msg["result"]["capabilities"]["semanticTokensProvider"]["legend"]
            
            token_types = legend["tokenTypes"]
            token_modifiers = legend["tokenModifiers"]
            print(legend, token_modifiers, token_types)


        if msg.get("id") == 2 and "result" in msg:
            data = msg["result"]["data"]
            tokens =  decode_semantic_tokens(data, token_types, token_modifiers)
            print(tokens)
            # Filter string literals that are not inactive
            active_strings = [t for t in tokens if t["type"] == "string" and "inactive" not in t["modifiers"]]
            print("Active string literals:")
            for t in active_strings:
                # print(f"Line {t['line']} Col {t['col']}: length={t['length']} modifiers={t['modifiers']}")           
                literal = extract_token_text(text, t)
                print(f"Line {t['line']} Col {t['col']}: {literal!r} modifiers={t['modifiers']}")
            break

    proc.terminate()
    t.join(timeout=1)

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python active_strings.py <file.cpp>")
        sys.exit(1)
    main(sys.argv[1])
