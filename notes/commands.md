#Quick Commands (Canonical)

## Overview

Common quick commands and snippets for enumeration, service checks, and privilege escalation during OSCP-style labs.

## When to test

- Early enumeration and post-exploitation phases.

## Detection Checklist

- Use `nmap` to map services, `enum4linux`/`smbclient` for SMB, and quick OS discovery commands on shells.

## Tools

- `nmap`, `gobuster`, `enum4linux`, `smbclient`, `hydra`, `curl`, `ffuf`, `winPEAS`, `linPEAS`.

## Commands / Quick Examples

- `nmap -sC -sV -oN nmap-default.txt <target>`  
- `nmap -p- --min-rate 1000 -sV -oN nmap-full.txt <target>`  
- `smbclient -L //<target> -N`  
- `gobuster dir -u http://<target> -w /usr/share/wordlists/dirb/common.txt -x php,txt,html`

## Exploitation Primitives

- Quick enumeration leads to targeted exploitation (e.g., exposed shares → credential discovery → lateral movement).

## Mitigations / Notes for Reporting

- Include exact commands and outputs (screenshots or raw output) in reports. Note flags used and why.

## Detailed Notes / Lab Content

The original quick commands cheatsheet is preserved below for extended examples and additional checks.

````markdown
#Quick Commands Cheatsheet

## Nmap

- Quick TCP scan and default scripts:

```bash
nmap -sC -sV -oN nmap-default.txt <target>
```

- Full TCP top 1000 ports with version and scripts:

nmap -p- --min-rate 1000 -sV -sC -oN nmap-full.txt <target>

- Service/version/script scan on specific ports:

nmap -sV -p 21,22,80,139,445 -oN nmap-services.txt <target>

## SMB

- Enumerate shares and users:

```bash
smbclient -L //<target> -N
enum4linux -a <target>
```

- Mount share:

mount -t cifs //<target>/share /mnt/share -o username=guest

## SSH

- Try username/password combos using hydra:

```bash
hydra -l user -P /usr/share/wordlists/rockyou.txt ssh://<target>
```

## HTTP / Web

- Gobuster (dir brute):

```bash
gobuster dir -u http://<target> -w /usr/share/wordlists/dirb/common.txt -x php,txt,html
```

- Curl quick check:

curl -I http://<target>

## Linux Privilege Escalation (quick checks)

```bash
#kernel
uname -a
#sudo rights
sudo -l
#world writable files
find / -perm -4000 -type f 2>/dev/null
find / -writable -type d 2>/dev/null
#services
ps aux | egrep "(cron|ssh|apache|nginx|mysql)"
```

## Windows Privilege Escalation

- WinPEAS and SharpUp are useful; run from SMB share or download.

## Post-exploitation

- Get user and root flags paths, check /root/.ssh, /home/*/.ssh
- Create a stable shell (netcat reverse, python pty, socat)

````
#Quick Commands Cheatsheet

---

## Merged from archive/canonical/commands.md


## Quick Commands (Canonical) (archived)

Archived copy of `notes/canonical/commands.md`. Use `notes/commands.md` as the merged single-file topic.

