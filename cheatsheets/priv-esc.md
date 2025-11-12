# Privilege Escalation Cheatsheet

## Linux quick checks

- Kernel / distro info:

```bash
uname -srv
cat /etc/os-release
```

- Sudo rights:

```bash
sudo -l
```

- Find SUID files:

```bash
find / -perm -4000 -type f 2>/dev/null
```

- Check cron jobs and systemd timers

```bash
ls -la /etc/cron.*
cat /etc/crontab
systemctl list-timers --all
```

## Windows quick checks

- Current user:

```powershell
whoami
whoami /priv
```

- Check services and permissions (PowerUp/WinPEAS helpful)


