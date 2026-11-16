"""Entry point: `python -m phantom`."""

from __future__ import annotations

import logging
import sys

import uvicorn

from .api import create_app
from .config import Settings


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    settings = Settings()
    app = create_app(settings)
    if settings.api_token is None:
        # No configured token: print the generated one once so a local
        # dashboard can be pointed at this instance.
        print(f"PHANTOM_API_TOKEN not set, using ephemeral token: {app.state.api_token}",
              file=sys.stderr)
    uvicorn.run(app, host=settings.host, port=settings.port, log_level="info",
                server_header=False)


if __name__ == "__main__":
    main()
