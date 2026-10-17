# zsazsa in Docker

zsazsa runs in a container next to your MISP. The web app, the analyser and the IMAP collector each get their own container, and misp-scraper can run alongside. MISP itself is not part of this setup: zsazsa uses the MISP you already have, installed normally or with [misp-docker](https://github.com/MISP/misp-docker).

## Before you start

You need Docker with the compose plugin (`docker compose version` should answer). Have these at hand:

- the address of your MISP and an API key for zsazsa
- the host, port and password of MISP's Redis; zsazsa reads MISP's sessions from it for single sign-on, and uses it for misp-scraper's queue and its own background jobs
- for misp-docker: MISP running, and its Redis password (`REDIS_PASSWORD` in misp-docker's `.env`, `redispassword` unless you changed it)

If zsazsa already runs on this host without Docker, the setup can import that configuration, and it will only ask what the file does not answer.

## Setting up

From the zsazsa checkout:

```bash
bash docker/setup.sh
```

The script asks its questions first and shows a summary. Nothing is written or built until you answer yes to "Go ahead?". Building the image then takes a few minutes. At the end you get an overview of what was done, where zsazsa can be reached, and what is left to do.

Then open zsazsa as a MISP site admin and finish the setup in the setup wizard, under Settings or at `/config/setup`. It asks for your organisation, the data collection sources, AI, focus points and notifications, and you can run it again later.

Run the same command again to change an answer. Your configuration and data are kept.

## What the setup changes

The containers are described in `docker-compose.yml`. For a Redis on this host's `127.0.0.1` the setup adds `docker-compose.host.yml`, which puts the containers on the host's network; for misp-docker it adds `docker-compose.misp-docker.yml`, which joins misp-docker's network. Your answers go in `docker/.env`: which of these files to use, which optional services to run (the analyser and IMAP collector, misp-scraper), the address zsazsa listens on and misp-scraper's Redis. `env.example` explains each line. The configuration answers go in `docker/volumes/config/__init__.py`.

You can also write `.env` yourself from `env.example` and start zsazsa with `docker compose up -d`, from the `docker` folder.

## Reaching zsazsa

Analysts open zsazsa under MISP's own address, as `https://your-misp/zsazsa/`. That needs a proxy rule on MISP's web server, and single sign-on only works that way, because the browser sends MISP's session cookie only to MISP's address. The setup offers to add the rule for you: to MISP's Apache virtual host (after making a backup, with sudo if the file needs it), or to the nginx inside misp-core. For misp-docker the rule is in `docker/misp-docker/`, and misp-core applies it again on every start. If MISP runs on another host, add it there yourself; [Serving zsazsa under MISP's address](../INSTALL.md#serving-zsazsa-under-misps-address) in INSTALL.md has the lines.

zsazsa itself listens on `127.0.0.1:5000` by default, so only MISP's web server on the same host can reach it. You can choose `0.0.0.0` instead, but without single sign-on everyone who reaches that port can use zsazsa with full rights. On a Mac, port 5000 is taken by AirPlay Receiver, so pick another port there.

## Where your files are

Everything that is yours lives in `docker/volumes/`, outside the image and outside git:

| Folder | Holds |
|---|---|
| `config/` | `__init__.py`, the configuration with the API keys |
| `data/` | the databases, uploads and `analyser.log` |
| `prompts/` | the AI prompts, as edited on the Settings page |
| `scraper-config/` | misp-scraper's configuration, when it runs here |

Rebuilding or removing the containers leaves these folders alone. To back up zsazsa, copy `docker/volumes/`. The files belong to user id 1000, the user inside the container; if your own id is different, you need sudo to read or edit them.

A new release can add prompts or data files. They are copied into the folders when the containers start; a file that is already there is never replaced, so your edits stay.

## Everyday use

Run these from the `docker` folder, where Compose finds `.env`:

```bash
docker compose ps                                    # what is running
docker compose logs -f webapp                        # follow the web app
tail -f volumes/data/analyser.log                    # zsazsa's own log
docker compose restart                               # after editing the configuration
docker compose exec webapp python run_analyser.py    # run the analyser now
git pull && docker compose up -d --build             # upgrade
docker compose down                                  # stop; docker/volumes is kept
```

Most settings are changed on the Settings page, as without Docker; [Configuration](../README.md#configuration) in the README describes each one. To edit the configuration by hand, open `docker/volumes/config/__init__.py` (with sudo if needed) and restart. zsazsa never reads `docker/.env`: that file only tells Docker Compose how to run the containers, so a MISP address or Redis password changed there does not reach zsazsa. The one exception is misp-scraper, which takes its Redis from `.env`; keep its `REDIS_PASSWORD` equal to the `*_REDIS_PASSWORD` settings in the configuration.

## When something does not work

zsazsa cannot reach MISP: the containers have a localhost of their own, so a MISP address with `localhost` or `127.0.0.1` points at the container. Use the address browsers use.

`CERTIFICATE_VERIFY_FAILED` in the log: MISP's certificate comes from a CA the container does not know, such as a private one. Set `MISP_WEBAPP_VERIFYCERT = False` in `docker/volumes/config/__init__.py`, and `MISP_VERIFYCERT = False` if the scraper's MISP has the same certificate, then restart.

Single sign-on does not recognise you, and zsazsa sends you to MISP's login page, which sends you on to MISP's home page: check that zsazsa is opened under MISP's address, that the proxy rule is in place, and that MISP keeps its PHP sessions in Redis (`session.save_handler = redis`). `docker/volumes/data/analyser.log` says why a request was not recognised; `WRONGPASS` there means `MISP_SESSION_REDIS_PASSWORD` in the configuration is not the password of MISP's Redis. The Settings page has a "Test single sign-on" button.

Scraper events never reach the analyser: zsazsa recognises them by `SCRAPER_MARKER_TAG`, and misp-scraper has to set that tag. When the setup runs misp-scraper, it starts from `docker/scraper.py.zsazsa`, which sets zsazsa's default tag, and checks that the tag and the Redis channel match zsazsa's configuration. A scraper elsewhere needs the tag in its own `scraper.py`, under `misp_scraper_tags_local`.

On a Mac, Docker Desktop containers do not share the Mac's `127.0.0.1`. A MISP or Redis on the Mac itself is reached as `host.docker.internal`.

## Credits

The Docker setup builds on the work of Chris Horsley (@chorsley) and @elhoim (PR #43).
