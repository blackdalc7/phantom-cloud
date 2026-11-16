"""Emulated shell for the bastion decoy.

Nothing typed here is ever executed. Input is matched against a small set of
commands and answered from an in-memory fake filesystem, which is why it is
safe to expose to an attacker (or to the dashboard's "attacker seat").
The filesystem is seeded with per-session honeytokens as bait.
"""

from __future__ import annotations

import fnmatch
import re
import shlex
from collections.abc import Callable

from ..models import DeployedDecoy

MAX_OUTPUT = 4000
_SPLIT = re.compile(r"\s*(?:;|&&)\s*")
_REDIRECT = re.compile(r"\s*(>>?)\s*(\S+)\s*$")
_ROOT_ONLY = ("/root", "/etc/shadow", "/etc/sudoers")


class FakeShell:
    def __init__(self, hostname: str, persona: str, secrets: dict[str, str],
                 peers: Callable[[], list[DeployedDecoy]], user: str = "svc_backup") -> None:
        self.hostname, self.user, self.persona = hostname, user, persona
        self.home = f"/home/{user}"
        self.cwd = self.home
        self._peers = peers
        self._secrets = secrets
        self._history: list[str] = []
        self.fs: dict[str, str] = self._seed()

    @property
    def prompt(self) -> str:
        shown = "~" + self.cwd[len(self.home):] if self.cwd.startswith(self.home) else self.cwd
        return f"{self.user}@{self.hostname}:{shown}$"

    def _seed(self) -> dict[str, str]:
        s, home = self._secrets, self.home
        return {
            "/etc/passwd": (
                "root:x:0:0:root:/root:/bin/bash\n"
                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
                "sshd:x:105:65534::/run/sshd:/usr/sbin/nologin\n"
                "mysql:x:110:115:MySQL Server,,,:/nonexistent:/bin/false\n"
                "deploy:x:1000:1000:Deploy,,,:/home/deploy:/bin/bash\n"
                f"{self.user}:x:1001:1001:Backup Service,,,:{home}:/bin/bash\n"),
            "/etc/hostname": self.hostname + "\n",
            "/etc/os-release": 'PRETTY_NAME="Ubuntu 22.04.4 LTS"\nID=ubuntu\n'
                               'VERSION_ID="22.04"\n',
            "/etc/crontab": "17 *\t* * *\troot\tcd / && run-parts --report /etc/cron.hourly\n"
                            f"30 2\t* * *\t{self.user}\t/opt/backup/backup.sh\n",
            f"{home}/.bash_history": (
                "ls /opt/backup\n"
                "aws s3 ls s3://corp-nightly-backups --profile backup\n"
                "mysql -h fin-db -u app -p\n"
                "vim /var/www/html/config.php\n"
                "sudo systemctl restart nginx\n"),
            f"{home}/.aws/credentials": (
                "[backup]\n"
                f"aws_access_key_id = {s['access_key']}\n"
                f"aws_secret_access_key = {s['api_token']}\n"
                "region = eu-west-1\n"),
            f"{home}/.ssh/authorized_keys": "",
            f"{home}/notes.txt": f"{self.persona} - nightly backup runbook\n"
                                 "db creds are in the web config, ask Priya before rotating\n",
            "/var/www/html/index.php": "<?php require 'config.php'; include 'portal.php';\n",
            "/var/www/html/config.php": (
                "<?php\n"
                "define('DB_HOST', 'fin-db');\n"
                "define('DB_USER', 'app');\n"
                f"define('DB_PASS', '{s['db_password']}');\n"
                "define('DB_NAME', 'ledger');\n"),
            "/opt/backup/backup.sh": "#!/bin/bash\n"
                                     "mysqldump -h fin-db -u app ledger | gzip > "
                                     "/opt/backup/ledger-$(date +%F).sql.gz\n",
            "/opt/backup/ledger-2026-11-14.sql.gz": "\x1f\x8b[binary data]\n",
        }

    # -- dispatch ---------------------------------------------------------

    def run(self, line: str) -> str:
        line = line.strip()
        if not line:
            return ""
        self._history.append(line)
        if line.startswith("for "):
            return self._sweep(line)
        out = [self._one(part) for part in _SPLIT.split(line) if part]
        return "\n".join(o for o in out if o)[:MAX_OUTPUT]

    def _one(self, part: str) -> str:
        stages = [p.strip() for p in part.split("|")]
        target = None
        if m := _REDIRECT.search(stages[-1]):
            target = (m.group(1), self._abs(m.group(2)))
            stages[-1] = stages[-1][:m.start()]
        try:
            argv = shlex.split(stages[0])
        except ValueError:
            return "bash: syntax error: unexpected end of file"
        if not argv:
            return ""
        handler = getattr(self, f"_cmd_{argv[0].replace('-', '_')}", None)
        out = handler(argv[1:]) if handler else f"bash: {argv[0]}: command not found"
        for stage in stages[1:]:
            out = self._filter(stage, out)
        if target:
            return self._write(target[0], target[1], out)
        return out

    @staticmethod
    def _filter(stage: str, text: str) -> str:
        try:
            argv = shlex.split(stage)
        except ValueError:
            return text
        if argv[:1] == ["grep"] and len(argv) > 1:
            needle = argv[-1].lower()
            return "\n".join(ln for ln in text.splitlines() if needle in ln.lower())
        if argv[:1] == ["head"]:
            return "\n".join(text.splitlines()[:10])
        if argv[:1] == ["wc"]:
            return str(len(text.splitlines()))
        return text

    def _write(self, mode: str, path: str, text: str) -> str:
        if not (path.startswith(self.home) or path.startswith("/tmp/")):  # noqa: S108
            return f"bash: {path}: Permission denied"
        body = text + "\n" if text else ""
        self.fs[path] = self.fs.get(path, "") + body if mode == ">>" else body
        return ""

    # -- helpers ----------------------------------------------------------

    def _abs(self, path: str) -> str:
        if path == "~" or path.startswith("~/"):
            path = self.home + path[1:]
        elif not path.startswith("/"):
            path = f"{self.cwd.rstrip('/')}/{path}"
        parts: list[str] = []
        for seg in path.split("/"):
            if seg == "..":
                parts[:] = parts[:-1]
            elif seg and seg != ".":
                parts.append(seg)
        return "/" + "/".join(parts)

    def _is_dir(self, path: str) -> bool:
        prefix = path.rstrip("/") + "/"
        return path == "/" or any(p.startswith(prefix) for p in self.fs)

    def _children(self, path: str) -> list[str]:
        prefix = "/" if path == "/" else path.rstrip("/") + "/"
        return sorted({p[len(prefix):].split("/")[0] for p in self.fs if p.startswith(prefix)})

    @staticmethod
    def _denied(path: str) -> bool:
        return any(path == p or path.startswith(p + "/") for p in _ROOT_ONLY)

    def _peer(self, host: str) -> DeployedDecoy | None:
        for d in self._peers():
            if host in (d.ip, d.hostname) or (host == "fin-db" and d.role == "database"):
                return d
        return None

    # -- commands ---------------------------------------------------------

    def _cmd_whoami(self, _):
        return self.user

    def _cmd_id(self, _):
        return f"uid=1001({self.user}) gid=1001({self.user}) groups=1001({self.user}),1002(backup)"

    def _cmd_hostname(self, _):
        return self.hostname

    def _cmd_pwd(self, _):
        return self.cwd

    def _cmd_uname(self, args):
        if "-a" in args:
            return (f"Linux {self.hostname} 5.15.0-112-generic #122-Ubuntu SMP "
                    "x86_64 GNU/Linux")
        return "Linux"

    def _cmd_echo(self, args):
        return " ".join(args)

    def _cmd_env(self, _):
        return (f"USER={self.user}\nHOME={self.home}\nSHELL=/bin/bash\n"
                "PATH=/usr/local/bin:/usr/bin:/bin\nLANG=en_US.UTF-8")

    def _cmd_cd(self, args):
        path = self._abs(args[0] if args else "~")
        if self._denied(path):
            return f"bash: cd: {path}: Permission denied"
        if not self._is_dir(path):
            return f"bash: cd: {args[0]}: No such file or directory"
        self.cwd = path
        return ""

    def _cmd_ls(self, args):
        long = any(a.startswith("-") and "l" in a for a in args)
        hidden = any(a.startswith("-") and "a" in a for a in args)
        paths = [a for a in args if not a.startswith("-")] or ["."]
        path = self._abs(paths[0])
        if self._denied(path):
            return f"ls: cannot open directory '{path}': Permission denied"
        if path in self.fs:
            names = [path.rsplit("/", 1)[-1]]
        elif self._is_dir(path):
            names = [n for n in self._children(path) if hidden or not n.startswith(".")]
        else:
            return f"ls: cannot access '{paths[0]}': No such file or directory"
        if not long:
            return "  ".join(names)
        rows = []
        for n in names:
            full = path if path in self.fs else f"{path.rstrip('/')}/{n}"
            if full in self.fs:
                rows.append(f"-rw-r----- 1 {self.user} {self.user} {len(self.fs[full]):>5} "
                            f"Nov 14 02:30 {n}")
            else:
                rows.append(f"drwxr-x--- 2 {self.user} {self.user}  4096 Nov 14 02:30 {n}")
        return "\n".join(rows)

    def _cmd_cat(self, args):
        out = []
        for raw in (a for a in args if not a.startswith("-")):
            path = self._abs(raw)
            if self._denied(path):
                out.append(f"cat: {raw}: Permission denied")
            elif path == "/etc/hosts":
                # Generated on read so it always lists the decoys deployed right now.
                rows = ["127.0.0.1 localhost", *(f"{d.ip} {d.hostname}" for d in self._peers())]
                out.append("\n".join(rows))
            elif path in self.fs:
                out.append(self.fs[path].rstrip("\n"))
            elif self._is_dir(path):
                out.append(f"cat: {raw}: Is a directory")
            else:
                out.append(f"cat: {raw}: No such file or directory")
        return "\n".join(out)

    def _cmd_find(self, args):
        start = self._abs(args[0]) if args and not args[0].startswith("-") else self.cwd
        pattern = args[args.index("-name") + 1] if "-name" in args[:-1] else "*"
        prefix = "/" if start == "/" else start.rstrip("/") + "/"
        hits = [p for p in sorted(self.fs) if p.startswith(prefix) and not self._denied(p)
                and fnmatch.fnmatch(p.rsplit("/", 1)[-1], pattern)]
        return "\n".join(hits[:60])

    def _cmd_grep(self, args):
        words = [a for a in args if not a.startswith("-")]
        if len(words) < 2:
            return ""
        needle, root = words[0].lower(), self._abs(words[1])
        hits = []
        for path, body in sorted(self.fs.items()):
            if path.startswith(root) and not self._denied(path):
                hits += [f"{path}:{ln}" for ln in body.splitlines() if needle in ln.lower()]
        return "\n".join(hits[:40])

    def _cmd_ps(self, _):
        return ("USER         PID %CPU %MEM COMMAND\n"
                "root           1  0.0  0.1 /sbin/init\n"
                "root         612  0.0  0.3 sshd: /usr/sbin/sshd -D\n"
                "www-data     840  0.1  1.2 nginx: worker process\n"
                "root         902  0.0  0.2 /usr/sbin/cron -f\n"
                f"{self.user}  2291  0.0  0.2 -bash\n"
                f"{self.user}  2317  0.0  0.1 ps aux")

    def _cmd_ip(self, args):
        me = next((d for d in self._peers() if d.hostname == self.hostname), None)
        addr = me.ip if me else "10.13.37.10"
        if args[:1] in (["r"], ["route"]):
            return f"{addr.rsplit('.', 1)[0]}.0/24 dev eth0 proto kernel scope link src {addr}"
        return ("1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n    inet 127.0.0.1/8 scope host lo\n"
                "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
                f"    inet {addr}/24 brd {addr.rsplit('.', 1)[0]}.255 scope global eth0")

    _cmd_ifconfig = _cmd_ip

    def _cmd_netstat(self, _):
        return ("Proto Local Address    State   PID/Program\n"
                "tcp   0.0.0.0:22       LISTEN  612/sshd\n"
                "tcp   127.0.0.1:8080   LISTEN  840/nginx")

    _cmd_ss = _cmd_netstat

    def _cmd_history(self, args):
        if "-c" in args:
            self._history.clear()
            return ""
        return "\n".join(f"{i:>5}  {c}" for i, c in enumerate(self._history, 1))

    def _cmd_sudo(self, args):
        if args[:1] == ["-l"]:
            return (f"User {self.user} may run the following commands on {self.hostname}:\n"
                    "    (root) NOPASSWD: /usr/bin/systemctl restart nginx")
        return f"[sudo] password for {self.user}: \nSorry, try again."

    def _cmd_crontab(self, args):
        if "-l" in args:
            return "30 2 * * * /opt/backup/backup.sh"
        return ""

    def _cmd_wget(self, args):
        url = next((a for a in args if "://" in a), "")
        host = url.split("://", 1)[-1].split("/", 1)[0]
        # Mirrors what the real decoy network does: there is no route out.
        return f"Connecting to {host}:80... failed: Network is unreachable."

    def _cmd_curl(self, args):
        url = next((a for a in args if "://" in a), "")
        host = url.split("://", 1)[-1].split("/", 1)[0]
        return f"curl: (7) Failed to connect to {host} port 80: Network is unreachable"

    def _cmd_nc(self, args):
        words = [a for a in args if not a.startswith("-") and a != "1"]
        if len(words) < 2:
            return "usage: nc [-zv] host port"
        peer = self._peer(words[0])
        if peer and str(peer.port) == words[1]:
            return f"Connection to {words[0]} {words[1]} port [tcp/*] succeeded!"
        return f"nc: connect to {words[0]} port {words[1]} (tcp) timed out"

    def _sweep(self, line: str) -> str:
        port = m.group(1) if (m := re.search(r"\b(\d{2,5})\s*;?\s*done", line)) else "22"
        hits = [f"Connection to {d.ip} {port} port [tcp/*] succeeded!"
                for d in self._peers() if str(d.port) == port]
        return "\n".join(hits) or "(no hosts answered)"

    def _cmd_mysql(self, args):
        host = args[args.index("-h") + 1] if "-h" in args[:-1] else "localhost"
        peer = self._peer(host)
        if not peer or peer.role != "database":
            return f"ERROR 2005 (HY000): Unknown MySQL server host '{host}' (-2)"
        return ("+--------------------+\n| Database           |\n+--------------------+\n"
                "| information_schema |\n| ledger             |\n| payroll_2026       |\n"
                "+--------------------+")

    def _cmd_ssh(self, args):
        host = next((a for a in args if not a.startswith("-")), "host").split("@")[-1]
        return f"ssh: connect to host {host} port 22: Connection timed out"

    _cmd_scp = _cmd_ssh

    def _cmd_tar(self, args):
        words = [a for a in args if not a.startswith("-") and "/" in a]
        if words:
            self.fs[self._abs(words[0])] = "\x1f\x8b[archive]\n"
        return "tar: Removing leading `/' from member names"

    def _cmd_chmod(self, _):
        return ""

    def _cmd_rm(self, args):
        for raw in (a for a in args if not a.startswith("-")):
            path = self._abs(raw)
            if not (path.startswith(self.home) or path.startswith("/tmp/")):  # noqa: S108
                return f"rm: cannot remove '{raw}': Permission denied"
            self.fs.pop(path, None)
        return ""

    def _cmd_exit(self, _):
        return "logout"
