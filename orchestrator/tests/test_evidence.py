from phantom.events import EventBus
from phantom.evidence import EvidenceLedger, verify_chain, verify_head


def ledger_with(n=5):
    ledger = EvidenceLedger()
    for i in range(n):
        ledger.append(ts=float(i), kind="shell.io", session_id="s1", payload={"command": f"c{i}"})
    return ledger


def test_intact_chain_verifies_and_head_is_signed():
    ledger = ledger_with()
    entries = ledger.entries()
    assert verify_chain(entries) == (True, None)
    assert verify_head(ledger.head(), entries)


def test_editing_an_entry_is_detected():
    entries = ledger_with().entries()
    entries[2] = entries[2].model_copy(update={"payload_hash": "0" * 64})
    assert verify_chain(entries) == (False, 3)


def test_deleting_an_entry_is_detected():
    entries = ledger_with().entries()
    del entries[1]
    ok, bad = verify_chain(entries)
    assert not ok and bad == 3


def test_truncated_ledger_fails_against_signed_head():
    ledger = ledger_with()
    head = ledger.head()
    # The shorter chain is internally consistent, but the signature covers the length.
    assert verify_chain(ledger.entries()[:-1])[0]
    assert not verify_head(head, ledger.entries()[:-1])


def test_forged_signature_is_rejected():
    ledger = ledger_with()
    other = EvidenceLedger()
    forged = ledger.head().model_copy(update={"public_key": other.public_key_hex})
    assert not verify_head(forged, ledger.entries())


def test_ledger_persists_as_json_lines(tmp_path):
    path = tmp_path / "evidence" / "ledger.jsonl"
    ledger = EvidenceLedger(path=path)
    ledger.append(ts=1.0, kind="k", session_id=None, payload={})
    ledger.append(ts=2.0, kind="k", session_id=None, payload={})
    assert len(path.read_text().splitlines()) == 2


async def test_bus_records_every_event_and_drops_stalled_subscribers():
    bus = EventBus()
    queue = bus.subscribe()
    for i in range(1500):  # more than a subscriber queue holds
        bus.publish("tick", n=i)
    assert bus.subscriber_count == 0          # stalled client was cut loose
    assert queue.get_nowait() is None         # and told to reconnect
    assert len(bus.ledger.entries()) == 1500  # the ledger still has everything
    assert [e.seq for e in bus.history(after=1498)] == [1499, 1500]
