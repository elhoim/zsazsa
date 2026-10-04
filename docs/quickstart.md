# Quickstart

This page takes you from nothing to a first daily threat briefing delivered to a
stakeholder. It is the short path only. [INSTALL.md](../INSTALL.md) has the full
installation and configuration reference, and [README.md](../README.md) explains
each part of the application.

## 1. What you need

- **A MISP server** where zsazsa stores its data (stakeholders, requirements,
  products), and an API key for a user on that server.
- **misp-scraper** feeding a MISP instance (optional). Without it, you add
  collection events by hand or pull them from other MISP servers.
- **Redis** on `127.0.0.1:6379`. zsazsa keeps background job state there, and
  product delivery runs as a background job. The defaults need no configuration.
- **Python 3.10 or later** (the CI runs 3.12), with `venv` and `pip`.
- **The WeasyPrint system libraries**, which zsazsa uses to render product PDFs.
  On Debian/Ubuntu:

  ```bash
  sudo apt-get install python3-venv python3-pip python3-dev git \
      libcairo2 libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 \
      libffi-dev shared-mime-info
  ```

  See "System packages" in [INSTALL.md](../INSTALL.md) for other distributions.

## 2. Install

Clone the repository and run the installer from the project root:

```bash
git clone https://github.com/zsazsa-project/zsazsa.git
cd zsazsa
bash docs/install.sh
```

The installer creates `venv/` and `data/`, installs `requirements.txt`, and
copies `config/__init__.py.example` to `config/__init__.py` with a generated
`SECRET_KEY`. Answer no to the certificate question for a first run. For the
recommended layout under the MISP custom directory, as the MISP web user, see
"Installation" in [INSTALL.md](../INSTALL.md).

## 3. Set the minimum configuration

Edit `config/__init__.py`. Only the MISP connection has to be set by hand:

```python
MISP_WEBAPP_URL = 'https://misp.example.com'
MISP_WEBAPP_KEY = '<API key>'
MISP_WEBAPP_VERIFYCERT = True   # False only for a self-signed test server
```

Then do one of these:

- **With misp-scraper:** set `MISP_URL` and `MISP_KEY` to the scraper's MISP
  instance (it can be the same server as above).
- **Without misp-scraper:** set `MISP_SCRAPER_ENABLED = False`, or set `MISP_URL`
  and `MISP_KEY` to `''`.

Everything else can be changed later from the web interface. AI support is
optional: to use it, set `OPENAI_API_KEY`, or configure a local LLM, on the AI
tab of Settings > Configuration. Without it, you write the briefing text yourself.

## 4. Start zsazsa

```bash
source venv/bin/activate
python run_webapp.py
```

Open `http://<host>:5000`. The data collection cache worker runs inside this
process, so nothing else is needed to try zsazsa. Scheduled jobs come later:
`run_analyser.py` processes scraper events into drafts, and `run_imap_collector.py`
polls newsletter mailboxes. The cron lines are in "Running zsazsa" in
[INSTALL.md](../INSTALL.md).

## 5. Who you are logged in as

zsazsa has no user accounts of its own. It reads the logged-in user from MISP's
session, which only works when zsazsa is served under the same host as MISP
(for example `https://misp.example.com/zsazsa` behind Apache).

On a direct first run on port 5000 there is no MISP session, so every request
runs as the fallback identity `admin@admin.test`. While single sign-on is not
configured, that identity can also publish, which is enough to follow this guide.

For a real deployment, put zsazsa behind Apache as described in "Production
deployment behind Apache" in [INSTALL.md](../INSTALL.md). Then, under
Settings > Configuration > System, switch on **Require a MISP session** in the
**Single sign-on** card, save, and use **Test single sign-on** to check it.
Visitors without a MISP session are then sent to MISP's login page, and
publishing needs MISP's publish permission (`perm_publish`) on the user's role.
"Single sign-on against MISP" in [INSTALL.md](../INSTALL.md) covers the Redis
requirements.

## 6. Add a notification channel

Create the channel first: the stakeholder form only lists channels that exist.

Go to Settings > Configuration > **Notifications** tab. Either:

- **Mattermost:** in **Add Mattermost channel**, enter a name and the incoming
  webhook URL, then press **Add channel**.
- **Email:** fill in the SMTP server (host, port, username, password, from
  address), press **Save configuration**, and check it with **Test connection**.
  Then, in **Add email channel**, enter a name and the recipient address and press
  **Add email channel**. The paper-plane button on the saved channel sends it a
  test email.

## 7. Add a stakeholder

Go to Stakeholders > Stakeholders and press **Add stakeholder**. Fill in:

- **Name**, and a **Role** (for example `SOC`).
- **TLP clearance**: the highest TLP this stakeholder may receive.
- **Notification channels**: tick the channel from step 6.
- **Products subscribed**: tick **Daily threat briefing**.

A daily briefing goes to every stakeholder subscribed to "Daily threat briefing"
whose TLP clearance covers the briefing's TLP. Other products also match the
stakeholder's role against the product's audience; see "Notification and
distribution flow" in [README.md](../README.md).

## 8. Get an event into data collection

A briefing is built from events on the Data collection page (Products > Data
collection).

- **With misp-scraper or another MISP server**, the events are already there once
  the cache has refreshed (every 15 minutes, or press **Refresh cache**). Other
  MISP servers are added under Settings > Collection sources, **Other MISP
  servers** card, **Add MISP server**; only published events are fetched from them.
- **Without any MISP source**, add an event by hand. Under Settings > Collection
  sources, use **Add manual source** in the **Manual sources** card. Then, on the
  Data collection page, press **Manual entry**, pick that source, give the event a
  title and some content, and press **Create event**.

## 9. Create and publish a daily briefing

1. On the Data collection page, tick one or more events. **Create product**
   becomes available. Choose **Add to daily briefing (new)**.
   (Products > Daily briefing > **New briefing** brings you to the same page.)
2. The briefing form opens with one story per event. Set the TLP, write or edit
   each story, and add a summary. With AI configured, **Draft everything** drafts
   the stories and the summary in the background.
3. Press **Save draft**. The briefing is stored in MISP as a draft.
4. On the briefing page, press **Publish briefing** in the **Publish** card.

Delivery runs in the background. The job badge in the top bar reports the result,
and Reporting > Pipeline keeps the history. The stakeholder from step 7 receives
the briefing on the channel from step 6.

## Where to go next

- **Requirements:** add PIRs and GIRs (Requirements menu) with scope, so matching
  events are highlighted in data collection.
- **Analyser:** with misp-scraper, schedule `run_analyser.py` and use **Start
  analyser** on the dashboard to get draft briefings, flash intel alerts and
  vulnerability advisories. See "What the analyser does" in
  [README.md](../README.md).
- **Other products:** flash intel alerts, vulnerability advisories, threat actor
  profiles, indicator feeds and detection engineering requests, described in
  [README.md](../README.md).
- **Configuration reference:** every setting and collection source type is in
  [INSTALL.md](../INSTALL.md). Run `venv/bin/python scripts/fetch_mitre_galaxy.py`
  to cache the MITRE ATT&CK technique list locally.
- **Upgrading:** read [CHANGELOG.md](../CHANGELOG.md) first, then follow
  "Upgrading" in [INSTALL.md](../INSTALL.md).
