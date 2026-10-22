# Installing zsazsa

<p align="center">
  <a href="https://zsazsa-project.org/documentation.html#install"><img alt="Quickstart: install" src="https://img.shields.io/badge/Quickstart-Install-0066cc?style=for-the-badge&logo=rocket&logoColor=white"></a>
</p>

This guide covers installing zsazsa, with Docker or as a standard installation next to MISP, and serving it under MISP's own address. The [quickstart](https://zsazsa-project.org/documentation.html) is the short path through the same steps. Once zsazsa runs, [Configuration](README.md#configuration) in the README describes every setting, and the rest of the [README](README.md) what zsazsa does and how analysts use it.

## What you need

zsazsa sits on top of MISP and requires:

- **A MISP server to store CTI program data.** This is where zsazsa saves its objects: stakeholders, PIRs, GIRs, flash intel alerts, advisories, briefings, and so on. This is the server you point `MISP_WEBAPP_URL` at. The API key zsazsa uses for it also looks up a user's role for the settings pages, so it has to be allowed to view users: a site admin key, or an org admin key when everyone using zsazsa is in that organisation.

- **A MISP server running misp-scraper (optional).** The scraper feeds threat events into a MISP instance that zsazsa polls for the data collection and the analyser pipeline. This is the server you point `MISP_URL` at. It can be the same server as above. Leave `MISP_URL` and `MISP_KEY` empty, or set `MISP_SCRAPER_ENABLED = False`, to run without one, in which case collection comes from the other MISP servers and the manual sources, and the analyser pipeline has nothing to process.

- **One or more additional MISP servers (optional, and the only collection source if you run without the scraper).** zsazsa can pull threat events from other MISP servers configured under Collection sources.

zsazsa does not install MISP or misp-scraper. Follow the installation guides for those projects first. The Docker setup can run misp-scraper for you, from its own checkout.

### Redis

zsazsa uses Redis.

| Use | Settings | Needed for |
|---|---|---|
| MISP's own session store | `MISP_SESSION_REDIS_*` (`config/__init__.py` only) | Single sign-on: reading the logged-in MISP user from MISP's session cookie. Requires PHP to store MISP's sessions in Redis (`session.save_handler = redis`) |
| Background jobs | `JOB_REDIS_*` (`config/__init__.py` only) | Running-job states |
| misp-scraper queue | `SCRAPER_REDIS_*` (Settings page) | Sending newsletter article URLs to the scraper |

All three default to `127.0.0.1:6379`, database `0`, no password, so a single local Redis instance, such as the one MISP already uses, is enough for most installs. The Docker setup asks for MISP's Redis once and sets all three.

## Docker or a standard installation

**Docker** is the quickest way in. `docker/setup.sh` asks how MISP, its Redis and misp-scraper run on the host, then builds and starts the web app, the analyser and the IMAP collector, each in a container of its own, and optionally misp-scraper. It can add the `/zsazsa` proxy to MISP's Apache or to misp-core's nginx in misp-docker. Your configuration and data stay in `docker/volumes/`.

The **standard installation** runs zsazsa from a Python virtual environment in MISP's custom directory, as MISP's web user. You add the proxy to MISP's Apache, the service to systemd and the analyser and IMAP collector to cron yourself.

Both end in the same place: zsazsa under MISP's address, as `https://misp.example.com/zsazsa`, configured from the setup wizard.

## Installing with Docker

You need Docker with the compose plugin (`docker compose version` should answer). From a checkout of zsazsa:

```bash
git clone https://github.com/zsazsa-project/zsazsa.git
cd zsazsa
bash docker/setup.sh
```

The script asks its questions first and changes nothing until you answer yes to "Go ahead?". When it is done, go on with [Configuring zsazsa](#configuring-zsazsa). [docker/README.md](docker/README.md) explains what the setup changes, where your files are, the everyday commands and what to check when something does not work.

## Standard installation

### System packages

zsazsa needs **Python 3.11** or later, with `venv` and `pip`, plus the native
libraries [WeasyPrint](https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#installation)
uses to render PDFs (every CTI product, from flash alerts and advisories to
briefings and reports, is exported through it). `pip install -r requirements.txt`
succeeds without these; WeasyPrint only fails, with an import error, the first
time a PDF is actually rendered, so install them upfront.

On Debian/Ubuntu:

```bash
sudo apt-get install python3-venv python3-pip python3-dev git \
    libcairo2 libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 \
    libffi-dev shared-mime-info
```

`python3-venv` is version-specific (e.g. `python3.12-venv`); if the command
above cannot find it, install the package matching `python3 --version`.

On Fedora/RHEL/CentOS the equivalent packages are `python3-devel`, `cairo`,
`pango`, `gdk-pixbuf2`, `libffi-devel` and `shared-mime-info`.

### Installing

Install zsazsa in the MISP custom directory and run it under the same web user as MISP. On Ubuntu this means `www-data`:

```bash
sudo mkdir -p /var/www/MISP/misp-custom
sudo chown www-data:www-data /var/www/MISP/misp-custom
cd /var/www/MISP/misp-custom
sudo -u www-data git clone https://github.com/zsazsa-project/zsazsa.git zsazsa
cd zsazsa
sudo -u www-data bash docs/install.sh
```

The installer checks the Python version, creates a `venv`, installs the dependencies from `requirements.txt`, creates `data/`, and, when `config/__init__.py` does not exist yet, copies `config/__init__.py.example` and gives it a freshly generated `SECRET_KEY`. An existing config is left alone, so the script is safe to re-run. It finishes by offering to generate a self-signed TLS certificate; answer no unless you intend to serve zsazsa's built-in server directly over HTTPS. Behind Apache, TLS is terminated by Apache and the certificate is not used.

The certificate can also be created later, or renewed, on its own:

```bash
bash docs/create_cert.sh zsazsa.example.com
```

It writes `certs/zsazsa.crt` and `certs/zsazsa.key`, the paths `SSL_CERT` and `SSL_KEY` point at by default, and refuses to run if either already exists, so an existing key is never overwritten. Set `SSL_ENABLED = True` to use it. Leave the hostname off to use this host's own name.

### The MISP connection

`config/__init__.py` has every setting the application requires, in the same layout the Settings page produces when it saves. Set at least `MISP_WEBAPP_URL` and `MISP_WEBAPP_KEY`, plus `MISP_URL` and `MISP_KEY` if you run a misp-scraper, or `MISP_SCRAPER_ENABLED = False` if you do not:

```python
MISP_WEBAPP_URL = 'https://misp.example.com'
MISP_WEBAPP_KEY = '<API key>'
MISP_WEBAPP_VERIFYCERT = True
```

If you use single sign-on, set `MISP_SESSION_REDIS_*` here as well, since the web interface does not change them. Everything else can be done from the web interface, by a MISP site admin.

### Running zsazsa

```bash
source venv/bin/activate
python run_webapp.py
```

zsazsa listens on `http://0.0.0.0:5000` by default, or on `https://` when `SSL_ENABLED` is on. `ZSAZSA_BIND` in the environment changes the address and `ZSAZSA_PORT` takes the place of `PORT`. `HOSTNAME` and `PORT` are on the Settings page (System tab); restart zsazsa after changing the port. `HOSTNAME` does not change the listener: it is kept for reference and for building links.

Run the analyser pipeline and the IMAP collector from the web user's crontab:

```bash
15 * * * * cd /var/www/MISP/misp-custom/zsazsa && venv/bin/python run_analyser.py
*/15 * * * * cd /var/www/MISP/misp-custom/zsazsa && venv/bin/python run_imap_collector.py
```

### The server zsazsa runs on

zsazsa is served by **Flask's built-in server**, in threaded mode, as a single
process. That is a deliberate choice rather than an oversight, and it is the
supported way to run it: Apache sits in front, terminates TLS and is what should
face the network. For the load a CTI team puts on it, a few analysts and a
background refresh every fifteen minutes, that is enough.

Its own listener binds to every interface, so port 5000 is reachable directly
unless you stop it. Keep that port closed on the firewall, or bind it to
`127.0.0.1` with `ZSAZSA_BIND=127.0.0.1` in its environment, as the service
template shows.

It also has to stay a single process. Several things live in this one and assume
it: the data collection cache worker, the requirement cache the collection page
matches against, and the lock that hands out the next PIR, GIR, RFI, FEED and TAP
number. Running zsazsa under gunicorn or uWSGI with more than one worker gives
you a cache refresh per worker and lets two workers allocate the same requirement
id. If you move to such a server, run exactly one worker.

## Serving zsazsa under MISP's address

zsazsa is designed to run alongside MISP and is served under a subpath of the MISP Apache virtual host, for example `https://misp.example.com/zsazsa`. The application adapts to any subpath automatically, so `/cti`, `/cti-program`, or any other value works without changing the application.

Serving zsazsa under the MISP host is also what makes single sign-on possible: the browser only sends MISP's session cookie to zsazsa when both are on the same host.

The Docker setup offers to add this proxy for you. The steps below are for the standard installation, and for a MISP on another host than zsazsa.

### 1. Systemd

Copy the service template and adjust the paths and user:

```bash
sudo cp docs/zsazsa.service.template /etc/systemd/system/zsazsa.service
# edit the file, then:
sudo systemctl daemon-reload
sudo systemctl enable --now zsazsa.service
```

For production, uncomment the `Environment=ZSAZSA_BIND=127.0.0.1` line in the service file, so zsazsa is only reachable through Apache. Leave it commented out for development if you need direct access from other machines on the network.

### 2. Enable the required Apache modules

```bash
sudo a2enmod proxy proxy_http headers
sudo systemctl reload apache2
```

### 3. Add the proxy to the MISP virtual host

Inside the existing `<VirtualHost *:443>` block in your MISP Apache configuration, add:

```apache
# zsazsa CTI application
ProxyPreserveHost On
RequestHeader set X-Forwarded-Prefix "/zsazsa"
RequestHeader set X-Forwarded-Proto "https"

ProxyPass        /zsazsa  http://127.0.0.1:5000/ timeout=300
ProxyPassReverse /zsazsa  http://127.0.0.1:5000/
```

The value in `RequestHeader set X-Forwarded-Prefix` must match the path used in `ProxyPass` and `ProxyPassReverse`. To use a different subpath, change all three occurrences. No application restart is needed for subpath changes, only an Apache reload (`systemctl reload apache2`). The application reads `X-Forwarded-Prefix` at runtime to construct links and AJAX call paths, and reads `X-Forwarded-Proto` to build correct `https://` URLs in Mattermost and Teams notifications and product preview links. When run directly without a proxy, both headers are absent and the application behaves exactly as before.

A MISP behind nginx needs the same three things: the prefix stripped from the path, `X-Forwarded-Prefix` and `X-Forwarded-Proto`. [docker/misp-docker/zsazsa-nginx.sh](docker/misp-docker/zsazsa-nginx.sh) has the `location` block the Docker setup adds to misp-core.

### 4. Single sign-on

With zsazsa under MISP's address, switch on **Require a MISP session** in the Single sign-on card of Settings > Configuration > System, save, and check it with **Test single sign-on**. PHP has to keep MISP's sessions in Redis for this to work. [Single sign-on against MISP](README.md#single-sign-on-against-misp) in the README explains the requirements and the permissions zsazsa takes from MISP.

## Configuring zsazsa

Open zsazsa as a MISP site admin. The setup wizard, under Settings or at `/config/setup`, walks you through the rest: the organisation, the data collection sources, AI, the focus points and notifications. It saves to the same settings as the Settings page and can be run again at any time. The dashboard points to it until zsazsa has a data collection source and focus points.

Everything the wizard does not cover is on Settings > Configuration and Settings > Collection sources, and described in [Configuration](README.md#configuration) in the README.

## Upgrading

Read [CHANGELOG.md](CHANGELOG.md) first: a release can come with a migration you need to run.

With Docker, from the `docker` folder:

```bash
git pull && docker compose up -d --build
```

For a standard installation, go to the installation directory and pull as the web user:

```bash
cd /var/www/MISP/misp-custom/zsazsa
sudo -u www-data git pull
sudo -u www-data venv/bin/pip install -r requirements.txt
```

Then restart the service to pick up the changes:

```bash
sudo systemctl restart zsazsa.service
```

After restarting, open Configuration > System and run any migration listed there that
you have not run before. They are dry-run first and safe to run twice. Upgrading from
a release before 1.0.0 needs **Align requirement scope and scope items**: before it, a
technology, vendor, incident or campaign was written to only one of the two places a
requirement keeps its scope, so it was either invisible on the detail page or matched
nothing.

## Optional post-installation steps

The MITRE ATT&CK technique list used in product forms and briefing stories is read from `data/mitre-attack-pattern.json`. When that file is missing the list is fetched from the MISP galaxy instead, which works but requires a query. Populate and refresh the local cache with:

```bash
venv/bin/python scripts/fetch_mitre_galaxy.py
# or, in Docker, from the docker folder:
docker compose exec webapp python scripts/fetch_mitre_galaxy.py
```

Re-run it periodically to pick up new techniques. The application notices the new file without a restart.
