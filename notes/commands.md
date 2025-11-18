# Quick Commands Cheatsheet

## Nmap

- Quick TCP scan and default scripts:

```bash
nmap -sC -sV -oN nmap-default.txt <target>
```

- Full TCP top 1000 ports with version and scripts:

```bash
nmap -p- --min-rate 1000 -sV -sC -oN nmap-full.txt <target>
```

- Service/version/script scan on specific ports:

```bash
nmap -sV -p 21,22,80,139,445 -oN nmap-services.txt <target>
```

## SMB

- Enumerate shares and users:

```bash
smbclient -L //<target> -N
enum4linux -a <target>
```

- Mount share:

```bash
mount -t cifs //<target>/share /mnt/share -o username=guest
```

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

```bash
curl -I http://<target>
```

## Linux Privilege Escalation (quick checks)

```bash
# kernel
uname -a
# sudo rights
sudo -l
# world writable files
find / -perm -4000 -type f 2>/dev/null
find / -writable -type d 2>/dev/null
# services
ps aux | egrep "(cron|ssh|apache|nginx|mysql)"
```

## Windows Privilege Escalation

- WinPEAS and SharpUp are useful; run from SMB share or download.

## Post-exploitation

- Get user and root flags paths, check /root/.ssh, /home/*/.ssh
- Create a stable shell (netcat reverse, python pty, socat)


