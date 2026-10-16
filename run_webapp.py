import os

import config
from webapp import create_app

app = create_app()

if __name__ == "__main__":
    ssl_context = None
    if getattr(config, "SSL_ENABLED", False):
        ssl_context = (config.SSL_CERT, config.SSL_KEY)

    # The Docker setup sets both: the address follows the choice made in
    # docker/setup.sh, and the port is the one the compose file publishes,
    # whatever PORT the Settings page holds.
    app.run(
        host=os.environ.get("ZSAZSA_BIND", "0.0.0.0"),
        port=int(os.environ.get("ZSAZSA_PORT") or getattr(config, "PORT", 5000)),
        debug=False,
        threaded=True,
        ssl_context=ssl_context,
    )
