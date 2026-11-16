"""Docker runtime tests against a fake SDK client: no daemon, no containers."""

import pytest

from phantom.compose import evaluate, harden
from phantom.models import ContainerSpec
from phantom.orchestrator import FALLBACK_COMPOSE
from phantom.runtime import DockerRuntime, SimulatedRuntime


class FakeContainer:
    def __init__(self, image, kwargs):
        self.image, self.kwargs = image, kwargs
        self.id = (kwargs["name"].encode().hex() + "0" * 64)[:64]
        self.labels = kwargs["labels"]
        self.removed = False
        self.attrs = {"NetworkSettings": {"Networks": {kwargs["network"]: {
            "IPAddress": "172.28.0.2"}}}}

    def reload(self):
        pass

    def remove(self, force=False):
        self.removed = force


class FakeNetwork:
    def __init__(self, name, kwargs):
        self.name, self.kwargs, self.removed = name, kwargs, False
        self.labels = kwargs.get("labels", {})

    def remove(self):
        self.removed = True


def _matches(labels, filters):
    return all(f"{k}={v}" in filters["label"] or True for k, v in labels.items()) and all(
        labels.get(sel.split("=")[0]) == sel.split("=")[1] for sel in filters["label"])


class FakeDocker:
    """Records what the runtime asks for. Pre-seeded with a container we do not own."""

    def __init__(self):
        outer = self
        self.created: list[FakeContainer] = []
        self.nets: list[FakeNetwork] = []
        self.foreign = FakeContainer("postgres:16", {"name": "users-own-db", "labels": {},
                                                     "network": "bridge"})

        class Containers:
            def run(self, image, **kwargs):
                container = FakeContainer(image, kwargs)
                outer.created.append(container)
                return container

            def list(self, all=False, filters=None):  # noqa: A002
                pool = [*outer.created, outer.foreign]
                return [c for c in pool if not c.removed and _matches(c.labels, filters)]

        class Networks:
            def list(self, names=None, filters=None):
                nets = [n for n in outer.nets if not n.removed]
                if names:
                    return [n for n in nets if n.name in names]
                return [n for n in nets if _matches(n.labels, filters)]

            def create(self, name, **kwargs):
                outer.nets.append(FakeNetwork(name, kwargs))

        self.containers, self.networks = Containers(), Networks()


@pytest.fixture
def specs():
    return harden(evaluate(FALLBACK_COMPOSE), "s1", lambda kind: "tok")


async def test_containers_start_with_fixed_isolation_settings(specs):
    client = FakeDocker()
    decoys = await DockerRuntime(client).deploy("s1", specs)

    assert len(decoys) == 2 and decoys[0].ip == "172.28.0.2"
    for container in client.created:
        k = container.kwargs
        assert k["privileged"] is False
        assert k["cap_drop"] == ["ALL"]
        assert k["security_opt"] == ["no-new-privileges:true"]
        assert k["read_only"] is True
        assert k["network"] == "phantom-s1"
        assert k["mem_limit"] == k["memswap_limit"]
        assert k["pids_limit"] == 128 and k["nano_cpus"] <= 1_000_000_000
        assert k["restart_policy"] == {"Name": "no"}
        assert k["labels"]["phantom.managed"] == "true"
        # Nothing that would touch the host is ever passed.
        assert not {"ports", "volumes", "network_mode", "pid_mode", "cap_add", "devices"} & set(k)


async def test_session_network_is_internal_and_created_once(specs):
    client = FakeDocker()
    runtime = DockerRuntime(client)
    await runtime.deploy("s1", specs[:1])
    await runtime.deploy("s1", specs[1:])  # expansion reuses the same network
    assert len(client.nets) == 1
    assert client.nets[0].kwargs["internal"] is True
    assert client.nets[0].kwargs["driver"] == "bridge"


async def test_runtime_refuses_images_outside_the_catalog():
    rogue = ContainerSpec(name="phantom-s1-x", image="alpine:3.20", role="x", hostname="x",
                          container_port=1)
    client = FakeDocker()
    with pytest.raises(PermissionError):
        await DockerRuntime(client).deploy("s1", [rogue])
    assert client.created == []


async def test_reap_only_removes_what_the_grid_started(specs):
    client = FakeDocker()
    runtime = DockerRuntime(client)
    await runtime.deploy("s1", specs)
    await runtime.deploy("s2", harden(evaluate(FALLBACK_COMPOSE), "s2", lambda kind: "tok"))

    assert await runtime.reap("s1") == 2
    assert [c.removed for c in client.created] == [True, True, False, False]
    assert await runtime.reap_all() == 2
    assert all(n.removed for n in client.nets)
    assert client.foreign.removed is False  # someone else's container is never touched


async def test_simulated_runtime_mirrors_the_interface(specs):
    runtime = SimulatedRuntime()
    decoys = await runtime.deploy("s1", specs)
    assert len({d.ip for d in decoys}) == 2
    assert all("cap_drop=ALL" in d.hardening for d in decoys)
    assert await runtime.reap("s1") == 2
    assert await runtime.reap_all() == 0
