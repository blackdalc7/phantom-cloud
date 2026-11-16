import asyncio

import pytest

from phantom.config import Settings
from phantom.orchestrator import Grid


@pytest.fixture
def settings():
    # Large time_scale: a minute of "attacker time" finishes in milliseconds.
    return Settings(_env_file=None, time_scale=5000, api_token="test-token-not-a-secret")


@pytest.fixture
async def grid(settings):
    g = Grid(settings)
    await g.start()
    yield g
    await g.shutdown()


async def wait_for(predicate, seconds=5.0):
    """Poll until predicate() is truthy; fail the test if it never is."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + seconds
    while loop.time() < deadline:
        if predicate():
            return
        await asyncio.sleep(0.01)
    raise AssertionError("condition not reached in time")
