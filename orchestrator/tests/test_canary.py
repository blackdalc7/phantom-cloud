import pytest

from phantom.canary import CanaryMint


def test_minted_token_is_attributed_to_its_session():
    mint = CanaryMint()
    token = mint.mint("sess-a", "access_key")
    hit = mint.lookup(token)
    assert hit and hit.session_id == "sess-a" and hit.kind == "access_key"


def test_tokens_are_unique_per_mint():
    mint = CanaryMint()
    assert len({mint.mint("s", "db_password") for _ in range(200)}) == 200


def test_lookalike_token_is_rejected():
    mint = CanaryMint()
    token = mint.mint("s", "access_key")
    flipped = token[:-1] + ("A" if token[-1] != "A" else "B")
    assert mint.lookup(flipped) is None
    assert mint.lookup("PHKA" + "A" * 16) is None
    assert mint.lookup("not-a-token") is None


def test_token_from_another_key_is_rejected():
    token = CanaryMint(b"k" * 32).mint("s", "api_token")
    assert CanaryMint(b"j" * 32).lookup(token) is None


def test_kind_is_bound_into_the_mac():
    mint = CanaryMint()
    token = mint.mint("s", "access_key")
    # Same body under a different prefix must not validate as another kind.
    assert mint.lookup("phtok_" + token[4:]) is None


def test_scan_finds_tokens_inside_commands():
    mint = CanaryMint()
    token = mint.mint("sess-b", "db_password")
    hits = mint.scan(f"mysql -h fin-db -u app -p{token} -e 'show databases'")
    assert [h.session_id for h in hits] == ["sess-b"]
    assert mint.scan("mysql -u app -pPc7AAAAAAAAAAAAAAAA") == []


def test_unknown_kind_is_refused():
    with pytest.raises(ValueError, match="unknown canary kind"):
        CanaryMint().mint("s", "ssh_key")
