"""The policy guard is the security boundary of the project, so it gets the most tests."""

import pytest
import yaml

from phantom.compose import CATALOG, evaluate, harden
from phantom.llm.client import HOSTILE_COMPOSE

WEB = "nginxinc/nginx-unprivileged:1.27-alpine"


def compose(service_overrides=None, network=None, top=None):
    """A minimal valid plan, with optional edits to make it invalid."""
    service = {"image": WEB, "hostname": "intranet-web-01", "networks": ["corp"]}
    service.update(service_overrides or {})
    doc = {"services": {"intranet-web-01": service},
           "networks": {"corp": network if network is not None else {"internal": True}}}
    doc.update(top or {})
    return yaml.safe_dump(doc)


def rules(raw):
    return {v.rule for v in evaluate(raw).violations}


def test_clean_plan_is_accepted():
    report = evaluate(compose())
    assert report.ok
    assert [s.image for s in report.services] == [WEB]


def test_hostile_model_output_is_rejected_on_every_count():
    report = evaluate(HOSTILE_COMPOSE)
    assert not report.ok and report.services == []
    paths = {v.path.rsplit(".", 1)[-1] for v in report.violations}
    assert {"privileged", "network_mode", "pid", "volumes", "command", "image"} <= paths


@pytest.mark.parametrize("key,value", [
    ("privileged", True),
    ("volumes", ["/var/run/docker.sock:/var/run/docker.sock"]),
    ("volumes", ["/:/host:ro"]),
    ("cap_add", ["SYS_ADMIN"]),
    ("devices", ["/dev/sda:/dev/sda"]),
    ("network_mode", "host"),
    ("pid", "host"),
    ("ipc", "host"),
    ("userns_mode", "host"),
    ("ports", ["0.0.0.0:22:22"]),
    ("ports", ["8080"]),
    ("command", ["sh"]),
    ("entrypoint", "/bin/sh"),
    ("build", "."),
    ("env_file", "/etc/environment"),
    ("extra_hosts", ["metadata:169.254.169.254"]),
    ("sysctls", {"net.ipv4.ip_forward": 1}),
    ("runtime", "sysbox"),
])
def test_isolation_breaking_keys_are_forbidden(key, value):
    assert "service.forbidden" in rules(compose({key: value}))


@pytest.mark.parametrize("overrides,rule", [
    ({"image": "alpine:3.20"}, "image.allowlist"),
    ({"image": "nginxinc/nginx-unprivileged:latest"}, "image.allowlist"),   # tag not vetted
    ({"image": "evil.example/nginxinc/nginx-unprivileged:1.27-alpine"}, "image.allowlist"),
    ({"image": ["mysql:8.4"]}, "image.allowlist"),
    ({"read_only": False}, "service.read_only"),
    ({"cap_drop": ["NET_RAW"]}, "service.cap_drop"),
    ({"security_opt": ["seccomp:unconfined"]}, "service.security_opt"),
    ({"security_opt": ["apparmor:unconfined", "no-new-privileges:true"]}, "service.security_opt"),
    ({"user": "root"}, "service.user"),
    ({"user": "0:0"}, "service.user"),
    ({"restart": "always"}, "service.restart"),
    ({"tmpfs": ["/etc"]}, "service.tmpfs"),
    ({"networks": ["host-bridge"]}, "service.network"),
    ({"labels": {"phantom.managed": "false"}}, "service.labels"),
    ({"hostname": "Bad_Host;rm"}, "service.hostname"),
    ({"expose": [22]}, "service.expose"),
    ({"stdin_open": True}, "service.unknown"),
    ({"environment": {"LD_PRELOAD": "/tmp/x.so"}}, "env.key"),
])
def test_service_rules(overrides, rule):
    assert rule in rules(compose(overrides))


@pytest.mark.parametrize("network,rule", [
    ({}, "network.internal"),
    ({"internal": False}, "network.internal"),
    ({"internal": True, "external": True}, "network.key"),
    ({"internal": True, "driver": "host"}, "network.driver"),
    ({"internal": True, "driver": "macvlan"}, "network.driver"),
    ({"internal": True, "driver_opts": {"parent": "eth0"}}, "network.key"),
])
def test_networks_must_be_internal_bridges(network, rule):
    assert rule in rules(compose(network=network))


@pytest.mark.parametrize("value", [
    "${HOME}", "$AWS_SECRET_ACCESS_KEY", "$(cat /etc/shadow)", "a\nb", "x" * 200, "`id`",
])
def test_env_values_cannot_interpolate_or_inject(value):
    raw = compose({"image": "mysql:8.4", "environment": {"MYSQL_DATABASE": value}})
    assert "env.value" in rules(raw)


def test_top_level_escape_hatches_are_refused():
    assert "top.key" in rules(compose(top={"volumes": {"data": {}}}))
    assert "top.key" in rules(compose(top={"secrets": {"s": {"file": "/etc/shadow"}}}))
    assert "top.key" in rules(compose(top={"include": ["../other.yml"]}))


def test_yaml_tricks_are_refused():
    bomb = "a: &a [x, x]\nb: &b [*a, *a]\nservices: {}\n"
    assert rules(bomb) == {"yaml.feature"}
    assert rules("services: !!python/object/apply:os.system ['id']") == {"yaml.feature"}
    assert rules("services: [unclosed") == {"yaml.parse"}
    assert rules("- just\n- a list\n") == {"yaml.shape"}
    assert rules("x: " + "a" * 20_000) == {"yaml.size"}


def test_duplicate_keys_are_refused():
    # Second `image` would silently win in a lenient parser.
    raw = ("services:\n  web-01:\n    image: " + WEB + "\n    image: alpine:3.20\n"
           "networks:\n  corp:\n    internal: true\n")
    assert rules(raw) == {"yaml.parse"}


def test_service_count_and_presence():
    assert "services.missing" in rules("services: {}\n")
    many = {f"web-{i:02d}": {"image": WEB, "hostname": f"web-{i:02d}"} for i in range(5)}
    assert "services.count" in rules(yaml.safe_dump({"services": many}))


def test_duplicate_hostnames_are_refused():
    doc = {"services": {"web-01": {"image": WEB, "hostname": "same-host"},
                        "web-02": {"image": WEB, "hostname": "same-host"}}}
    assert "service.hostname" in rules(yaml.safe_dump(doc))


def test_one_bad_service_rejects_the_whole_plan():
    doc = yaml.safe_load(compose())
    doc["services"]["rogue-01"] = {"image": "alpine:3.20"}
    report = evaluate(yaml.safe_dump(doc))
    assert not report.ok and report.services == []


def test_harden_ignores_model_security_settings_and_applies_ours():
    raw = compose({"image": "mysql:8.4", "user": "1234", "mem_limit": "64g", "pids_limit": 99999,
                   "environment": {"MYSQL_ROOT_PASSWORD": "{{canary:db_password}}",
                                   "MYSQL_DATABASE": "ledger"}})
    report = evaluate(raw)
    assert report.ok
    [spec] = harden(report, "abc123", lambda kind: f"minted-{kind}")
    image = CATALOG["mysql:8.4"]
    assert spec.name == "phantom-abc123-intranet-web-01"
    assert (spec.user, spec.mem_limit, spec.pids_limit) == (image.user, image.mem_limit, 128)
    assert set(spec.tmpfs) == set(image.writable)
    assert all("noexec" in opts and "nosuid" in opts for opts in spec.tmpfs.values())
    # The model wrote a placeholder; the real honeytoken was minted on our side.
    assert spec.environment == {"MYSQL_ROOT_PASSWORD": "minted-db_password",
                                "MYSQL_DATABASE": "ledger"}


def test_harden_refuses_a_rejected_report():
    with pytest.raises(ValueError, match="rejected plan"):
        harden(evaluate(HOSTILE_COMPOSE), "abc", lambda kind: "x")
