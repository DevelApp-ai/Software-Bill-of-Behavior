#!/usr/bin/env python3
"""SBoB windows corpus replay driver (issue #42, lab validation).

wazuh-logtest CLI always pre-processes stdin events as syslog-format agent
events, so it cannot drive the windows eventchannel/JSON chain (the shipped
sysmon parent chain is unreachable from the CLI on 4.14.x). This driver
talks to the logtest session socket directly
(/var/ossec/queue/sockets/logtest, wazuh daemon protocol: 4-byte
little-endian length prefix + JSON) with an explicit log_format, which lets
the shipped json decoder decode the {"win":{...}} Sysmon corpus lines into
the win.system.* / win.eventdata.* rule-field map. The connection is
per-message (the daemon closes the socket after each reply); the SESSION
TOKEN is reused across messages so firedtimes accumulate exactly as in the
live engine, which is what makes the sustained (frequency 8/120s) rules
provable.

Pair with the ROOT-ANCHOR VALIDATION TRANSFORM (lab-validate.yml applies it
at install time and restores the production file afterwards): the
production bundle correctly anchors the global base rule on the shipped
sysmon parent ('<if_sid>61600</if_sid>'); for replay only, the installed
file swaps that anchor to '<decoded_as>json</decoded_as>' (validation copy,
same rule ids, file replaces the production file in place during the
replay). Everything downstream of the anchor (field conditions, PCRE2
alternations, CDB lists, sustained children) is the production artifact.

Usage:
  logtest-win-replay.py CORPUS.jsonl [location] [log_format]
    replay each jsonl line as one event in ONE logtest session
    (default session: location "sbob-win-replay", log_format "json"),
    print one line per event: 'id=<rule-id>' when a rule matched (alert or
    level-0 base), 'decoder=<name>' when only decoding occurred, 'nomatch'
    otherwise. The audit corpora also replay with log_format "syslog".
"""
import json
import socket
import struct
import sys

SOCKET = "/var/ossec/queue/sockets/logtest"
PROTOCOL = {"version": 1, "origin": {"name": "wazuh-logtest", "module": "wazuh-logtest"}}


def send_recv(sock: socket.socket, obj: dict) -> dict:
    payload = json.dumps(obj).encode()
    sock.sendall(struct.pack("<I", len(payload)) + payload)
    header = b""
    while len(header) < 4:
        header += sock.recv(4 - len(header))
    (size,) = struct.unpack("<I", header)
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("logtest socket closed mid-reply")
        data += chunk
    return json.loads(data)


def process(sock: socket.socket, event: str, token: str, location: str, log_format: str) -> dict:
    parameters = {"location": location, "log_format": log_format, "event": event}
    if token:
        parameters["token"] = token
    request = dict(PROTOCOL)
    request["command"] = "log_processing"
    request["parameters"] = parameters
    reply = send_recv(sock, request)
    if reply.get("error", 0) != 0:
        raise RuntimeError(f"logtest error: {json.dumps(reply)[:400]}")
    return reply["data"]


def main() -> int:
    corpus = sys.argv[1]
    location = sys.argv[2] if len(sys.argv) > 2 else "sbob-win-replay"
    log_format = sys.argv[3] if len(sys.argv) > 3 else "json"
    with open(corpus, "r", encoding="utf-8") as fh:
        events = [line.rstrip("\n") for line in fh if line.strip()]
    if not events:
        print("nomatch:: empty corpus", file=sys.stderr)
        return 2
    token = None
    for event in events:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(SOCKET)
        try:
            data = process(sock, event, token, location, log_format)
            token = data.get("token", token)
        finally:
            sock.close()
        if data.get("codemsg", 0) < 0:
            print(f"error: {data.get('messages')}")
            continue
        output = data.get("output") or {}
        if output.get("alert"):
            rule = (output.get("rule") or {}).get("id")
            print(f"id={rule}")
        elif output.get("rule"):
            print(f"id={output['rule'].get('id')}")
        else:
            decoder = (output.get("decoder") or {}).get("name")
            print(f"decoder={decoder}" if decoder else "nomatch")
    # close the session so repeated runs start with a clean firedtimes state
    if token:
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(SOCKET)
            request = dict(PROTOCOL)
            request["command"] = "remove_session"
            request["parameters"] = {"token": token}
            send_recv(sock, request)
            sock.close()
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
