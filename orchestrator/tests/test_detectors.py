from phantom.models import AlertKind, NetEvent, NetEventKind
from phantom.tripwire import PortScanDetector, SSHBruteForceDetector, scenario_events
from phantom.tripwire.detectors import MAX_SOURCES

SRC = "203.0.113.50"


def syn(ts, port, src=SRC):
    return NetEvent(ts=ts, src_ip=src, dst_port=port, kind=NetEventKind.SYN)


def fail(ts, user, src=SRC):
    return NetEvent(ts=ts, src_ip=src, dst_port=22, kind=NetEventKind.SSH_AUTH_FAIL, username=user)


def run(detector, events):
    return [a for ev in events if (a := detector.observe(ev))]


def test_fast_sweep_raises_one_alert():
    alerts = run(PortScanDetector(), [syn(i * 0.05, 1000 + i) for i in range(40)])
    assert len(alerts) == 1  # cooldown suppresses repeats for the same source
    assert alerts[0].kind == AlertKind.PORT_SCAN
    assert alerts[0].evidence["profile"] == "fast_sweep"
    assert "T1046" in alerts[0].techniques


def test_normal_traffic_is_ignored():
    # A client hitting the same three services repeatedly is not a scan.
    events = [syn(i * 0.1, (22, 80, 443)[i % 3]) for i in range(200)]
    assert run(PortScanDetector(), events) == []


def test_low_and_slow_scan_is_caught_by_long_window():
    # One probe every 15s never trips the 10s window.
    alerts = run(PortScanDetector(), [syn(i * 15.0, 2000 + i) for i in range(35)])
    assert len(alerts) == 1
    assert alerts[0].evidence["profile"] == "low_and_slow"


def test_banner_grabs_are_classified_as_version_detection():
    events = [syn(i * 0.05, 3000 + i) for i in range(14)]
    events.append(NetEvent(ts=1.0, src_ip=SRC, dst_port=22, kind=NetEventKind.BANNER_GRAB))
    events.append(syn(1.1, 4000))
    alerts = run(PortScanDetector(), events)
    assert alerts[0].evidence["profile"] == "version_detection"


def test_sources_are_tracked_independently():
    events = []
    for i in range(14):  # each source stays one port under the threshold
        events += [syn(i * 0.05, 1000 + i, "203.0.113.1"), syn(i * 0.05, 1000 + i, "203.0.113.2")]
    assert run(PortScanDetector(), events) == []


def test_source_table_is_bounded():
    detector = PortScanDetector()
    for i in range(MAX_SOURCES + 500):
        detector.observe(syn(i * 0.001, 80, f"10.{i >> 16 & 255}.{i >> 8 & 255}.{i & 255}"))
    assert len(detector._sources) == MAX_SOURCES


def test_password_guessing():
    alerts = run(SSHBruteForceDetector(), [fail(i * 0.5, "root") for i in range(10)])
    assert len(alerts) == 1
    assert alerts[0].evidence["variant"] == "password_guessing"
    assert alerts[0].techniques == ["T1110.001"]


def test_password_spraying():
    users = ["root", "admin", "oracle", "git", "deploy", "ubuntu"]
    alerts = run(SSHBruteForceDetector(), [fail(i * 0.5, u) for i, u in enumerate(users)])
    assert alerts[0].evidence["variant"] == "password_spraying"
    assert alerts[0].techniques == ["T1110.003"]


def test_slow_failures_do_not_alert():
    # A user fat-fingering a password every few minutes is not an attack.
    assert run(SSHBruteForceDetector(), [fail(i * 120.0, "alice") for i in range(10)]) == []


def test_success_after_bruteforce_is_flagged_once():
    events = [fail(i * 0.5, "root") for i in range(8)]
    ok = NetEvent(ts=5.0, src_ip=SRC, dst_port=22, kind=NetEventKind.SSH_AUTH_OK, username="root")
    alerts = run(SSHBruteForceDetector(), [*events, ok, ok])
    assert [a.evidence["variant"] for a in alerts] == ["password_guessing", "successful_login"]
    assert "T1078" in alerts[1].techniques


def test_plain_login_is_not_an_alert():
    ok = NetEvent(ts=1.0, src_ip=SRC, dst_port=22, kind=NetEventKind.SSH_AUTH_OK, username="bob")
    assert SSHBruteForceDetector().observe(ok) is None


def test_scenarios_trip_the_expected_detectors():
    scan, ssh = PortScanDetector(), SSHBruteForceDetector()
    kinds = []
    for ev in scenario_events("full_intrusion", SRC, t0=0.0):
        kinds += [a.evidence.get("variant") or a.evidence.get("profile")
                  for a in (scan.observe(ev), ssh.observe(ev)) if a]
    assert kinds == ["fast_sweep", "password_guessing", "successful_login"]
