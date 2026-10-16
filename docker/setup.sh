#!/usr/bin/env bash
# Sets up zsazsa in Docker: asks how MISP, its Redis and misp-scraper run here,
# writes docker/.env, builds the images, writes the configuration and starts it.
#
#   bash docker/setup.sh
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$DIR")"
VOL="$DIR/volumes"
ENV_FILE="$DIR/.env"
CONFIG_FILE="$VOL/config/__init__.py"
SCRAPER_REPO="https://github.com/cudeso/misp-scraper"

# Run from docker/, where Compose finds .env and the files it names.
dc() { (cd "$DIR" && docker compose "$@"); }

# ── Output ────────────────────────────────────────────────────────────────────

if [[ -t 1 && -t 2 && -z "${NO_COLOR:-}" ]]; then
    B=$'\033[1m' D=$'\033[2m' G=$'\033[32m' Y=$'\033[33m' R=$'\033[31m' C=$'\033[36m' N=$'\033[0m'
else
    B="" D="" G="" Y="" R="" C="" N=""
fi

say() { printf '  %s\n' "$*"; }
hint() { printf '  %s%s%s\n' "$D" "$*" "$N"; }
ok() { printf '  %s✓%s %s\n' "$G" "$N" "$*"; }
warn() { printf '  %s!%s %s\n' "$Y" "$N" "$*"; }
fail() { printf '  %s✗%s %s\n' "$R" "$N" "$*" >&2; }

heading() {
    local pad="" i
    for ((i = 0; i < 56 - ${#1}; i++)); do pad+="─"; done
    printf '\n%s── %s %s%s\n\n' "$B$C" "$1" "$pad" "$N"
}

# Runs a command quietly; its output is shown only when it fails.
step() {
    local msg="$1" log
    shift
    log=$(mktemp "${TMPDIR:-/tmp}/zsazsa.XXXXXX")
    [[ -n "$B" ]] && printf '  %s…%s %s\r' "$D" "$N" "$msg"
    if "$@" > "$log" 2>&1; then
        [[ -n "$B" ]] && printf '\033[K'
        ok "$msg"
        rm -f "$log"
    else
        [[ -n "$B" ]] && printf '\033[K'
        fail "$msg failed:"
        sed 's/^/      /' "$log" >&2
        rm -f "$log"
        exit 1
    fi
}

# What the script did and what is left to do, printed at the end.
DONE=()
NEXT=()
did() { DONE+=("$1"); }
next() { NEXT+=("$1"); }

TMP_CONFIG=""
# The arguments for configure.py, keys included, readable by this user only.
ARGS_FILE=$(umask 077 && mktemp "${TMPDIR:-/tmp}/zsazsa.XXXXXX")
cleanup() {
    rm -f "$ARGS_FILE"
    if [[ -n "$TMP_CONFIG" ]]; then rm -f "$TMP_CONFIG"; fi
}
trap cleanup EXIT

# ── Questions ─────────────────────────────────────────────────────────────────

prompt() { printf '  %s?%s %s%s: ' "$C" "$N" "$1" "${2:+ ${D}[$2]$N}" >&2; }

ask() {
    local reply
    prompt "$1" "${2:-}"
    read -r reply || { echo >&2; fail "Input ended."; exit 1; }
    printf '%s' "${reply:-${2:-}}"
}

ask_secret() {
    local reply
    prompt "$1"
    read -r -s reply || { echo >&2; fail "Input ended."; exit 1; }
    echo >&2
    printf '%s' "$reply"
}

ask_required() {
    local reply=""
    while [[ -z "$reply" ]]; do reply=$(ask "$1" "${2:-}") || exit 1; done
    printf '%s' "$reply"
}

ask_secret_required() {
    local reply=""
    while [[ -z "$reply" ]]; do reply=$(ask_secret "$1") || exit 1; done
    printf '%s' "$reply"
}

yes_no() {
    local reply shown=y/N
    [[ "$2" == Y ]] && shown=Y/n
    prompt "$1" "$shown"
    read -r reply || { echo >&2; fail "Input ended."; exit 1; }
    [[ "${reply:-$2}" =~ ^[Yy] ]]
}

choose() {
    local question="$1" n=1 reply
    shift
    printf '  %s%s%s\n' "$B" "$question" "$N" >&2
    for option in "$@"; do
        printf '    %s%d)%s %s\n' "$C" "$n" "$N" "$option" >&2
        n=$((n + 1))
    done
    while true; do
        prompt "Choice" "1"
        read -r reply || { echo >&2; fail "Input ended."; exit 1; }
        reply="${reply:-1}"
        if [[ "$reply" =~ ^[0-9]+$ ]] && (( reply >= 1 && reply <= $# )); then
            echo "$reply"
            return
        fi
    done
}

# A bare host name or IPv4 address.
ask_host() {
    local reply
    while true; do
        reply=$(ask "$1" "$2") || exit 1
        if [[ "$reply" =~ ^[0-9A-Za-z._-]+$ ]]; then
            echo "$reply"
            return
        fi
        warn "Enter a host name or an IPv4 address." >&2
    done
}

ask_port() {
    local reply
    while true; do
        reply=$(ask "$1" "$2") || exit 1
        if [[ "$reply" =~ ^[0-9]+$ ]] && (( reply >= 1 && reply <= 65535 )); then
            echo "$reply"
            return
        fi
        warn "Enter a port between 1 and 65535." >&2
    done
}

# A path as typed, made absolute: relative, docker run -v reads it as a volume
# name and Compose reads it from docker/, not from where setup.sh was started.
absolute() {
    local path="$1"
    [[ "$path" == "~/"* ]] && path="$HOME/${path#"~/"}"
    [[ "$path" == /* ]] || path="$PWD/$path"
    printf '%s' "$path"
}

# ── Reading an existing configuration ─────────────────────────────────────────

# What a config file sets a key to, without quotes, or nothing.
config_value() {
    local line sq="'" dq='"'
    line=$(sed -n "s/^$1 *= *//p" "$2" 2> /dev/null | head -1) || true
    if [[ "$line" =~ ^$sq(.*)${sq}[[:space:]]*(#.*)?$ || "$line" =~ ^$dq(.*)${dq}[[:space:]]*(#.*)?$ ]]; then
        printf '%s' "${BASH_REMATCH[1]}"
    else
        line="${line%%#*}"
        printf '%s' "${line%"${line##*[![:space:]]}"}"
    fi
}

# A config file with a MISP address of its own, not the example's.
config_is_filled() {
    [[ -f "$1" ]] || return 1
    [[ -r "$1" ]] || return 0
    [[ -n "$(config_value MISP_WEBAPP_URL "$1")" ]] && ! grep -q 'your-misp-instance' "$1"
}

# Reads a file this user cannot, through the zsazsa image.
copy_out() {
    docker image inspect zsazsa:latest > /dev/null 2>&1 || return 1
    docker run --rm --user root --entrypoint cat -v "$1:/v:ro" zsazsa:latest "/v/$2" > "$3" 2> /dev/null
}

docker_available() { docker compose version > /dev/null 2>&1; }

# Whether background jobs end up in memory because their Redis cannot be reached.
jobs_in_memory() {
    case "$JOB_HOST" in 127.0.0.1|localhost) ;; *) return 1 ;; esac
    if [[ "$NETWORK" != host ]]; then return 0; fi
    command -v nc > /dev/null || return 1
    ! nc -z -w 2 127.0.0.1 "$JOB_PORT" > /dev/null 2>&1
}

# Fills in the answers an existing configuration already holds.
read_config() {
    local f="$1" key
    for key in MISP_WEBAPP_URL MISP_WEBAPP_KEY MISP_WEBAPP_VERIFYCERT MISP_URL MISP_KEY MISP_VERIFYCERT \
               MISP_SCRAPER_ENABLED MISP_SESSION_REDIS_HOST MISP_SESSION_REDIS_PORT MISP_SESSION_REDIS_PASSWORD \
               MISP_SESSION_REDIRECT_TO_LOGIN MISP_SESSION_COOKIE_NAME SCRAPER_REDIS_HOST SCRAPER_REDIS_PORT \
               SCRAPER_REDIS_PASSWORD JOB_REDIS_HOST JOB_REDIS_PORT; do
        printf -v "CFG_$key" '%s' "$(config_value "$key" "$f")"
    done
    # The example has placeholders where a real install has its own values.
    [[ "$CFG_MISP_WEBAPP_URL" == *your-misp-instance* ]] && CFG_MISP_WEBAPP_URL=""
    [[ "$CFG_MISP_WEBAPP_KEY" == *your-misp-api-key* ]] && CFG_MISP_WEBAPP_KEY=""
    [[ "$CFG_MISP_URL" == *your-misp-instance* ]] && CFG_MISP_URL=""
    [[ "$CFG_MISP_KEY" == *your-misp-api-key* ]] && CFG_MISP_KEY=""

    MISP_URL="$CFG_MISP_WEBAPP_URL"
    MISP_KEY="$CFG_MISP_WEBAPP_KEY"
    if [[ -n "$MISP_URL" ]]; then
        VERIFY=True
        [[ "$CFG_MISP_WEBAPP_VERIFYCERT" == False ]] && VERIFY=False
    fi
    REDIS_HOST="${CFG_MISP_SESSION_REDIS_HOST:-127.0.0.1}"
    REDIS_PORT="${CFG_MISP_SESSION_REDIS_PORT:-6379}"
    REDIS_PASSWORD="$CFG_MISP_SESSION_REDIS_PASSWORD"
    SSO=False
    if [[ "$CFG_MISP_SESSION_REDIRECT_TO_LOGIN" == True || -n "$CFG_MISP_SESSION_COOKIE_NAME" ]]; then SSO=True; fi
    SCRAPER_USED=no
    if [[ "$CFG_MISP_SCRAPER_ENABLED" != False && -n "$CFG_MISP_URL" && -n "$CFG_MISP_KEY" ]]; then
        SCRAPER_USED=yes
        SCR_URL="$CFG_MISP_URL"
        SCR_KEY="$CFG_MISP_KEY"
        SCR_VERIFY=True
        [[ "$CFG_MISP_VERIFYCERT" == False ]] && SCR_VERIFY=False
    fi
    SCR_REDIS_HOST="${CFG_SCRAPER_REDIS_HOST:-$REDIS_HOST}"
    SCR_REDIS_PORT="${CFG_SCRAPER_REDIS_PORT:-$REDIS_PORT}"
    SCR_REDIS_PASSWORD="$CFG_SCRAPER_REDIS_PASSWORD"
    JOB_HOST="${CFG_JOB_REDIS_HOST:-127.0.0.1}"
    JOB_PORT="${CFG_JOB_REDIS_PORT:-6379}"
    return 0
}

# The network that reaches MISP's Redis: the host's, misp-docker's, or the default.
derive_network() {
    case "$REDIS_HOST" in
    127.0.0.1|localhost)
        NETWORK=host
        ;;
    *)
        MISP_NETWORK=$(docker inspect -f '{{range $name, $net := .NetworkSettings.Networks}}{{$name}} {{end}}' \
            "$REDIS_HOST" 2> /dev/null | awk '{print $1}' || true)
        if [[ -n "$MISP_NETWORK" ]]; then
            NETWORK=misp
            MISP_DOCKER_DIR=$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project.working_dir"}}' \
                "$REDIS_HOST" 2> /dev/null || true)
        else
            NETWORK=bridge
        fi
        ;;
    esac
}

init_answers() {
    SETTINGS=()
    CONFIG_SRC="" IMPORT="" KEEP=no
    MISP_WHERE=1 MISP_URL="" MISP_KEY="" VERIFY="" ASKED_MISP=no
    NETWORK=bridge MISP_NETWORK="" MISP_DOCKER_DIR=""
    REDIS_HOST="" REDIS_PORT="" REDIS_PASSWORD="" ASKED_REDIS=no SSO=""
    JOB_HOST="" JOB_PORT=""
    SCRAPER_USED="" SCR_URL="" SCR_KEY="" SCR_VERIFY=""
    SCR_REDIS_HOST="" SCR_REDIS_PORT="" SCR_REDIS_PASSWORD=""
    SCHEDULE=no SCRAPER=no SCRAPER_DIR="" SCRAPER_CLONE=no SCRAPER_CONFIG=""
    SCRAPER_MISP_URL="" SCRAPER_MISP_KEY="" SCRAPER_MISP_VERIFY=""
    PROXY=no VHOST="" BIND=127.0.0.1 PORT=5000 TARGET=""
}

# ── Questions: the configuration ──────────────────────────────────────────────

ask_config_source() {
    heading "Configuration"

    if config_is_filled "$CONFIG_FILE"; then
        if yes_no "Found a configuration in docker/volumes/config. Keep it?" "Y"; then
            KEEP=yes
            CONFIG_SRC="$CONFIG_FILE"
        fi
    fi

    if [[ "$KEEP" == no ]]; then
        local default=""
        [[ -f "$ROOT/config/__init__.py" ]] && default="$ROOT/config/__init__.py"
        if yes_no "Import an existing configuration (from an earlier install, Docker or not)?" "N"; then
            while true; do
                IMPORT=$(ask "Path of the config file" "$default") || exit 1
                IMPORT=$(absolute "$IMPORT")
                [[ -f "$IMPORT" ]] && break
                warn "$IMPORT does not exist."
            done
            CONFIG_SRC="$IMPORT"
        fi
    fi

    if [[ -n "$CONFIG_SRC" && ! -r "$CONFIG_SRC" ]]; then
        TMP_CONFIG=$(mktemp "${TMPDIR:-/tmp}/zsazsa.XXXXXX")
        if copy_out "$(dirname "$CONFIG_SRC")" "$(basename "$CONFIG_SRC")" "$TMP_CONFIG"; then
            CONFIG_SRC="$TMP_CONFIG"
        else
            CONFIG_SRC=""
        fi
    fi
    if [[ "$KEEP" == yes && -z "$CONFIG_SRC" ]]; then
        warn "Cannot read the existing configuration as this user."
        warn "It is kept, but the answers below are written over it."
    fi

    if [[ -n "$CONFIG_SRC" ]]; then
        read_config "$CONFIG_SRC"
        derive_network
        hint "What ${IMPORT:-the configuration} holds is not asked again."
    fi
}

# ── Questions: MISP, Redis and single sign-on ─────────────────────────────────

ask_misp() {
    if [[ -z "$MISP_URL" ]]; then
        if [[ "$NETWORK" != host && "$MISP_WHERE" != 2 ]]; then
            hint "Not localhost: the containers have a localhost of their own."
        fi
        MISP_URL=$(ask_required "MISP URL")
        ASKED_MISP=yes
    fi
    if [[ -z "$MISP_KEY" ]]; then
        MISP_KEY=$(ask_secret_required "MISP API key")
        ASKED_MISP=yes
    fi
    if [[ -z "$VERIFY" ]]; then
        VERIFY=True
        yes_no "Verify MISP's TLS certificate?" "Y" || VERIFY=False
        ASKED_MISP=yes
    fi
}

ask_redis() {
    [[ -z "$REDIS_HOST" ]] || return 0
    echo
    hint "zsazsa uses MISP's Redis for sessions, the scraper queue and background jobs."
    echo
    case "$MISP_WHERE" in
    1)
        REDIS_HOST=$(ask_host "Redis host" "127.0.0.1")
        ;;
    2)
        REDIS_HOST=${MISP_URL#*://}
        REDIS_HOST=$(ask_host "Redis host" "${REDIS_HOST%%[/:]*}")
        ;;
    3)
        NETWORK=misp
        MISP_NETWORK=$(ask "misp-docker network" \
            "$(docker network ls --format '{{.Name}}' | grep -m1 -i misp || true)")
        REDIS_HOST=$(ask "misp-docker Redis container" \
            "$(docker network inspect -f '{{range .Containers}}{{.Name}} {{end}}' "$MISP_NETWORK" 2> /dev/null \
               | tr ' ' '\n' | grep -m1 -E 'redis|valkey' || true)")
        MISP_DOCKER_DIR=$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project.working_dir"}}' \
            "$REDIS_HOST" 2> /dev/null || true)
        ;;
    esac
    if [[ "$REDIS_HOST" == localhost ]]; then REDIS_HOST=127.0.0.1; fi
    # Only containers on the host's network reach a Redis on 127.0.0.1.
    if [[ "$REDIS_HOST" == 127.0.0.1 ]]; then NETWORK=host; fi
    REDIS_PORT=$(ask_port "Redis port" "6379")
    if [[ -n "$MISP_DOCKER_DIR" && -f "$MISP_DOCKER_DIR/.env" ]]; then
        hint "misp-docker keeps REDIS_PASSWORD in $MISP_DOCKER_DIR/.env (default: redispassword)."
    fi
    REDIS_PASSWORD=$(ask_secret "Redis password (empty for none)")
    SCR_REDIS_HOST="$REDIS_HOST"
    SCR_REDIS_PORT="$REDIS_PORT"
    SCR_REDIS_PASSWORD="$REDIS_PASSWORD"
    JOB_HOST="$REDIS_HOST"
    JOB_PORT="$REDIS_PORT"
    ASKED_REDIS=yes
}

ask_sso() {
    [[ -z "$SSO" ]] || return 0
    echo
    hint "Single sign-on shows analysts under their MISP user. It needs zsazsa under MISP's own"
    hint "address, as /zsazsa (a proxy on MISP's web server, set up below), and MISP's sessions in Redis."
    SSO=False
    yes_no "Use single sign-on with MISP?" "Y" && SSO=True
    SETTINGS+=("MISP_SESSION_REDIRECT_TO_LOGIN=$SSO")
}

ask_backend() {
    heading "MISP and Redis"
    MISP_WHERE=$(choose "Where does MISP run?" \
        "On this host, installed from GitHub or RPM" \
        "On another host" \
        "On this host, in Docker (misp-docker)")
    if [[ "$MISP_WHERE" == 2 && -z "$MISP_URL" ]]; then
        echo
        ask_misp
    fi
    ask_redis
    if [[ -z "$MISP_URL" || -z "$MISP_KEY" || -z "$VERIFY" ]]; then
        echo
        ask_misp
    fi
    if [[ "$ASKED_MISP" == yes ]]; then
        SETTINGS+=("MISP_WEBAPP_URL=$MISP_URL" "MISP_WEBAPP_KEY=$MISP_KEY" "MISP_WEBAPP_VERIFYCERT=$VERIFY")
    fi
    if [[ "$ASKED_REDIS" == yes ]]; then
        local use
        for use in MISP_SESSION SCRAPER JOB; do
            SETTINGS+=("${use}_REDIS_HOST=$REDIS_HOST" "${use}_REDIS_PORT=$REDIS_PORT" "${use}_REDIS_PASSWORD=$REDIS_PASSWORD")
        done
    fi
    ask_sso
    if [[ "$NETWORK" != host && "$MISP_URL" =~ ^https?://(localhost|127\.0\.0\.1)([:/]|$) ]]; then
        warn "$MISP_URL is localhost, which the containers cannot reach. Use the address browsers use."
    fi
    if [[ "$SSO" == True ]]; then
        next "Single sign-on needs MISP's PHP sessions in Redis (session.save_handler = redis); /config has a Test single sign-on button."
    fi
}

# ── Questions: where zsazsa listens and the /zsazsa proxy ─────────────────────

ask_listen() {
    heading "Address and /zsazsa proxy"

    hint "Advised: 127.0.0.1:5000 behind MISP's web server (needed for single sign-on)."
    hint "0.0.0.0 opens zsazsa to the network: without single sign-on, anyone can use it."
    hint "On macOS, AirPlay uses port 5000."
    echo
    # A run before wrote the address and port to .env.
    local bind port
    bind=$(config_value ZSAZSA_BIND "$ENV_FILE")
    port=$(config_value ZSAZSA_PORT "$ENV_FILE")
    BIND=$(ask_host "Listen address" "${bind:-127.0.0.1}")
    [[ "$BIND" == localhost ]] && BIND=127.0.0.1
    PORT=$(ask_port "Listen port" "${port:-5000}")

    # Where MISP's web server finds zsazsa.
    local target_host=$BIND
    [[ "$BIND" == 0.0.0.0 ]] && target_host=127.0.0.1
    TARGET="$target_host:$PORT"

    echo
    hint "MISP's web server has to proxy /zsazsa to zsazsa ($TARGET). That is how analysts"
    hint "reach it under MISP's address, and single sign-on needs it."
    # misp-core's nginx can only proxy to a zsazsa on its network.
    local can_proxy=no
    [[ "$MISP_WHERE" == 1 ]] && can_proxy=yes
    [[ "$MISP_WHERE" == 3 && "$NETWORK" == misp ]] && can_proxy=yes
    if [[ "$can_proxy" == no ]]; then
        hint "MISP's web server is not one this script can change: add the proxy there yourself (INSTALL.md)."
        return 0
    fi
    local proxy_default=N
    [[ "$SSO" == True ]] && proxy_default=Y
    yes_no "Set up the /zsazsa proxy now?" "$proxy_default" && PROXY=yes
    if [[ "$PROXY" == yes && "$MISP_WHERE" == 1 ]]; then
        VHOST=$(ask "Apache config file of MISP (empty to skip)" \
            "$(grep -lE '<VirtualHost[^>]*:443>' /etc/apache2/sites-enabled/* 2> /dev/null | head -1 || true)")
        if [[ -n "$VHOST" && ! -f "$VHOST" ]]; then
            fail "$VHOST does not exist."
            exit 1
        fi
        if [[ -n "$VHOST" && ! -w "$VHOST" ]]; then
            # Now, rather than halfway through the setup.
            warn "$VHOST needs sudo to change."
            sudo -v || { fail "No sudo; add the proxy yourself."; VHOST=""; }
        fi
    fi
}

# ── Questions: the analyser and misp-scraper ──────────────────────────────────

ask_scraper() {
    if [[ -z "$SCRAPER_USED" ]]; then
        hint "misp-scraper fetches articles and feeds them to MISP as events. It is optional."
        SCRAPER_USED=no
        if yes_no "Use misp-scraper to collect events?" "Y"; then
            SCRAPER_USED=yes
            if yes_no "Does it write to this MISP (same URL and key)?" "Y"; then
                SCR_URL="$MISP_URL"
                SCR_KEY="$MISP_KEY"
                SCR_VERIFY="$VERIFY"
            else
                SCR_URL=$(ask_required "MISP URL of the scraper")
                SCR_KEY=$(ask_secret_required "API key of the scraper")
                SCR_VERIFY=True
                yes_no "Verify its TLS certificate?" "Y" || SCR_VERIFY=False
            fi
            SETTINGS+=("MISP_SCRAPER_ENABLED=True" "MISP_URL=$SCR_URL" "MISP_KEY=$SCR_KEY" "MISP_VERIFYCERT=$SCR_VERIFY")
        else
            SETTINGS+=("MISP_SCRAPER_ENABLED=False" "MISP_URL=" "MISP_KEY=")
        fi
    fi
    [[ "$SCRAPER_USED" == yes ]] || return 0

    echo
    hint "misp-scraper is a separate project. Here it can run as a Docker container."
    yes_no "Run misp-scraper in Docker on this host?" "N" || return 0
    SCRAPER=yes
    SCRAPER_DIR=$(config_value SCRAPER_DIR "$ENV_FILE")
    while true; do
        SCRAPER_DIR=$(ask "Folder of misp-scraper (cloned there if missing)" \
            "${SCRAPER_DIR:-$(cd "$ROOT/.." && pwd)/misp-scraper}") || exit 1
        [[ "$SCRAPER_DIR" != *://* && "$SCRAPER_DIR" != *@*:* ]] && break
        warn "Enter a folder on this host, not a URL. The setup clones $SCRAPER_REPO into it."
        SCRAPER_DIR=""
    done
    SCRAPER_DIR=$(absolute "$SCRAPER_DIR")
    if [[ ! -f "$SCRAPER_DIR/docker/Dockerfile" ]]; then
        if [[ -e "$SCRAPER_DIR" ]] || ! command -v git > /dev/null || ! yes_no "Not found. Clone it there?" "Y"; then
            fail "$SCRAPER_DIR/docker/Dockerfile not found."
            exit 1
        fi
        SCRAPER_CLONE=yes
    fi
    local have=no
    [[ -f "$VOL/scraper-config/scraper.py" ]] && have=yes
    if [[ "$have" == yes ]] && yes_no "Keep the scraper config in docker/volumes/scraper-config?" "Y"; then
        SCRAPER_CONFIG=keep
    else
        while true; do
            SCRAPER_CONFIG=$(ask "scraper.py to import (empty: start from docker/scraper.py.zsazsa)" "") || exit 1
            [[ -z "$SCRAPER_CONFIG" || -f "$SCRAPER_CONFIG" ]] && break
            warn "$SCRAPER_CONFIG does not exist."
        done
    fi
    if [[ -z "$SCRAPER_CONFIG" ]]; then
        SCRAPER_MISP_URL="$SCR_URL"
        SCRAPER_MISP_KEY="$SCR_KEY"
        SCRAPER_MISP_VERIFY="${SCR_VERIFY:-True}"
        [[ -n "$SCRAPER_MISP_URL" ]] || SCRAPER_MISP_URL=$(ask_required "MISP URL for the scraper")
        [[ -n "$SCRAPER_MISP_KEY" ]] || SCRAPER_MISP_KEY=$(ask_secret_required "API key for the scraper")
    fi
}

ask_pipeline() {
    heading "Analyser and misp-scraper"
    hint "The analyser drafts products from collected events; the IMAP collector reads newsletters."
    yes_no "Run the analyser (hourly) and IMAP collector (15 min) in Docker?" "Y" && SCHEDULE=yes
    echo
    ask_scraper
}

# ── The plan ──────────────────────────────────────────────────────────────────

confirm_plan() {
    heading "Summary"
    local cfg="new, in docker/volumes/config" proxy="by hand, on MISP's web server" services="webapp"
    [[ "$KEEP" == yes ]] && cfg="kept in docker/volumes/config"
    [[ -n "$IMPORT" ]] && cfg="imported from $IMPORT"
    if [[ "$PROXY" == yes && "$MISP_WHERE" == 1 ]]; then
        proxy="by hand, in Apache"
        [[ -z "$VHOST" ]] || proxy="added to $VHOST"
    elif [[ "$PROXY" == yes ]]; then
        proxy="added to misp-core's nginx"
    fi
    [[ "$SCHEDULE" == yes ]] && services+=", analyser, imap-collector"
    [[ "$SCRAPER" == yes ]] && services+=", misp-scraper"
    printf '  %-18s %s\n' "Configuration" "$cfg"
    printf '  %-18s %s\n' "MISP" "${MISP_URL:-as configured}"
    if [[ "$REDIS_HOST:$REDIS_PORT" == "$SCR_REDIS_HOST:$SCR_REDIS_PORT" && "$REDIS_HOST:$REDIS_PORT" == "$JOB_HOST:$JOB_PORT" ]]; then
        printf '  %-18s %s\n' "Redis" "$REDIS_HOST:$REDIS_PORT"
    else
        printf '  %-18s %s\n' "Redis, sign-on" "$REDIS_HOST:$REDIS_PORT"
        printf '  %-18s %s\n' "Redis, scraper" "$SCR_REDIS_HOST:$SCR_REDIS_PORT"
        printf '  %-18s %s\n' "Redis, jobs" "$JOB_HOST:$JOB_PORT"
    fi
    printf '  %-18s %s\n' "Single sign-on" "$([[ "$SSO" == True ]] && echo on || echo off)"
    printf '  %-18s %s\n' "misp-scraper" "${SCR_URL:-not used}"
    printf '  %-18s %s\n' "Listens on" "$BIND:$PORT"
    printf '  %-18s %s\n' "/zsazsa proxy" "$proxy"
    printf '  %-18s %s\n' "Containers" "$services"
    if jobs_in_memory; then
        warn "No Redis at $JOB_HOST:$JOB_PORT: background jobs are kept in memory and lost at a restart."
    fi
    echo
    yes_no "Go ahead?" "Y" || { say "Nothing was changed."; exit 0; }
}

interview() {
    init_answers
    ask_config_source
    ask_backend
    ask_listen
    ask_pipeline
}

# ── Applying the answers ──────────────────────────────────────────────────────

# The Apache proxy, in the 443 virtual host of MISP.
apply_apache() {
    if [[ -z "$VHOST" ]]; then
        next "Add the /zsazsa proxy to MISP's Apache, pointing at http://$TARGET/ (INSTALL.md)."
    elif grep -qE '^[[:space:]]*ProxyPass[[:space:]]+/zsazsa' "$VHOST"; then
        did "$VHOST already proxies /zsazsa; unchanged. It must point at http://$TARGET/."
    else
        local staging SUDO=""
        staging=$(mktemp "${TMPDIR:-/tmp}/zsazsa.XXXXXX")
        T="$TARGET" awk '
            /<VirtualHost[^>]*:443>/ { in443 = 1 }
            in443 && /<\/VirtualHost>/ && !done {
                print "    # zsazsa CTI application"
                print "    ProxyPreserveHost On"
                print "    RequestHeader set X-Forwarded-Prefix \"/zsazsa\""
                print "    RequestHeader set X-Forwarded-Proto \"https\""
                print "    ProxyPass        /zsazsa  http://" ENVIRON["T"] "/ timeout=300"
                print "    ProxyPassReverse /zsazsa  http://" ENVIRON["T"] "/"
                done = 1
            }
            { print }' "$VHOST" > "$staging"
        if ! grep -q "ProxyPass        /zsazsa" "$staging"; then
            fail "No <VirtualHost *:443> block in $VHOST."
            next "Add the /zsazsa proxy to MISP's Apache, pointing at http://$TARGET/ (INSTALL.md)."
        else
            [[ -w "$VHOST" ]] || SUDO=sudo
            $SUDO cp -p "$VHOST" "$VHOST.bak-zsazsa"
            $SUDO cp "$staging" "$VHOST"
            ok "Added the /zsazsa proxy to $VHOST"
            did "Added the /zsazsa proxy to $VHOST (backup: $VHOST.bak-zsazsa)."
            next "Reload Apache: sudo a2enmod proxy proxy_http headers && sudo apachectl configtest && sudo systemctl reload apache2"
        fi
        rm "$staging"
    fi
}

# What is left to do for a proxy this script did not set up.
proxy_notes() {
    if [[ "$PROXY" == no && "$SSO" == True ]]; then
        if [[ "$MISP_WHERE" != 2 ]]; then
            next "Proxy /zsazsa on MISP's web server to http://$TARGET/ (INSTALL.md)."
        elif [[ "$BIND" == 127.0.0.1 ]]; then
            next "zsazsa listens on 127.0.0.1, which the MISP server cannot reach. Run setup again with another address."
        else
            next "Proxy /zsazsa on the MISP server to http://${BIND/#0.0.0.0/<this host>}:$PORT/ (INSTALL.md)."
        fi
    fi
    return 0
}

# ── Overview ──────────────────────────────────────────────────────────────────

overview() {
    heading "Done"
    local line
    for line in "${DONE[@]}"; do printf '  %s✓%s %s\n' "$G" "$N" "$line"; done
    echo
    if [[ "$PROXY" == yes ]]; then
        say "Open zsazsa at ${MISP_URL%/}/zsazsa/, or at http://$TARGET/ on this host."
    else
        say "zsazsa answers at http://$TARGET/ on this host."
    fi
    say "Its configuration, data and log are in $VOL/."
    [[ "$(id -u)" == 1000 ]] || hint "They belong to user id 1000, so reading them takes sudo."
    say "Follow the containers with: cd $DIR && docker compose logs -f"
    say "Run setup.sh again to change an answer."

    next "Finish the setup in zsazsa's setup wizard (Settings, Setup wizard, or /config/setup)."
    printf '\n  %sStill to do%s\n' "$B" "$N"
    for line in "${NEXT[@]}"; do printf '  %s!%s %s\n' "$Y" "$N" "$line"; done
    echo
}

# ── Docker ────────────────────────────────────────────────────────────────────

# A Python script of zsazsa, run in the webapp container.
zpy() { dc run -T --rm --no-deps webapp python "$@"; }

# docker/.env: the network override in COMPOSE_FILE, the optional services in COMPOSE_PROFILES.
write_env() {
    local files=docker-compose.yml profiles=""
    case "$NETWORK" in
    host) files+=":docker-compose.host.yml" ;;
    misp) files+=":docker-compose.misp-docker.yml" ;;
    esac
    [[ "$SCHEDULE" == yes ]] && profiles="scheduled"
    [[ "$SCRAPER" == yes ]] && profiles="${profiles:+$profiles,}scraper"
    (
        umask 077
        cat > "$ENV_FILE" <<EOF
# Written by setup.sh from your answers; env.example explains each line.
COMPOSE_FILE=$files
COMPOSE_PROFILES=$profiles
ZSAZSA_BIND=$BIND
ZSAZSA_PORT=$PORT
MISP_NETWORK=$MISP_NETWORK
SCRAPER_DIR=$SCRAPER_DIR
REDIS_HOST=$SCR_REDIS_HOST
REDIS_PORT=$SCR_REDIS_PORT
REDIS_PASSWORD=$SCR_REDIS_PASSWORD
ANALYSER_INTERVAL=3600
IMAP_COLLECTOR_INTERVAL=900
SCRAPER_CRON_INTERVAL=3600
EOF
    )
}

docker_apply() {
    if [[ "$(uname -s)" == Darwin && "$NETWORK" == host ]]; then
        next "On macOS, Docker Desktop containers do not share the Mac's 127.0.0.1: MISP or Redis on this Mac need host.docker.internal instead."
    fi
    mkdir -p "$VOL/config" "$VOL/data" "$VOL/prompts"
    if [[ "$SCRAPER" == yes ]]; then mkdir -p "$VOL/scraper-config"; fi

    write_env
    ok "Wrote .env"
    did "Wrote docker/.env with your answers (readable by you only)."

    if [[ "$SCRAPER_CLONE" == yes ]]; then
        step "Cloning misp-scraper" git clone --depth 1 "$SCRAPER_REPO" "$SCRAPER_DIR"
    fi
    step "Building the images (takes a few minutes)" dc build < /dev/null
    did "Built the images."
    write_docker_config
    # The container user has id 1000, whoever owns the folders on this host.
    step "Preparing docker/volumes" \
        dc run -T --rm --no-deps --user root --entrypoint sh webapp \
            -c 'chown -R 1000:1000 /app/config /app/data /app/zsazsaprompts' < /dev/null
    if [[ "$SCRAPER" == yes ]]; then write_scraper_config; fi

    step "Starting the containers" dc up -d < /dev/null
    did "Started: $(dc ps --format '{{.Service}}' | tr '\n' ',' | sed 's/,$//; s/,/, /g')."
}

write_docker_config() {
    # As root, to read the imported file whoever owns it. The arguments go in on standard
    # input: as arguments, the keys among them are visible to every user of the host.
    local mounts args
    mounts=()
    args=()
    if [[ -n "$IMPORT" ]]; then
        mounts+=(-v "$IMPORT:/import.py:ro,z")
        args+=(--import /import.py)
    fi
    args+=(${SETTINGS[@]+"${SETTINGS[@]}"})
    printf '%s\0' ${args[@]+"${args[@]}"} > "$ARGS_FILE"
    step "Writing the configuration" \
        dc run -T --rm --no-deps --user root ${mounts[@]+"${mounts[@]}"} webapp python docker/configure.py - \
            < "$ARGS_FILE"
    if [[ -n "$IMPORT" ]]; then
        did "Configuration imported from $IMPORT (the old one is __init__.py.backup)."
    elif [[ "$KEEP" == yes ]]; then
        did "Configuration kept in docker/volumes/config."
    else
        did "Configuration created in docker/volumes/config, with MISP at ${MISP_URL}."
    fi
}

# misp-scraper's configuration: kept, imported, or scraper.py.zsazsa with its MISP filled in.
write_scraper_config() {
    local staging
    if [[ "$SCRAPER_CONFIG" != keep ]]; then
        staging=$(mktemp -d "${TMPDIR:-/tmp}/zsazsa.XXXXXX")
        if [[ -n "$SCRAPER_CONFIG" ]]; then
            cp "$SCRAPER_CONFIG" "$staging/scraper.py"
        else
            U="$SCRAPER_MISP_URL" K="$SCRAPER_MISP_KEY" V="$SCRAPER_MISP_VERIFY" awk '
                /^misp_url = / { print "misp_url = \"" ENVIRON["U"] "\""; next }
                /^misp_key = / { print "misp_key = \"" ENVIRON["K"] "\""; next }
                /^misp_verifycert = / { print "misp_verifycert = " ENVIRON["V"]; next }
                { print }' "$DIR/scraper.py.zsazsa" > "$staging/scraper.py"
        fi
        cp "$SCRAPER_DIR/feedlist.json" "$staging/"
        step "Writing misp-scraper's configuration" copy_scraper_files "$staging"
        rm -r "$staging"
    fi
    check_scraper_config
}

# Into docker/volumes/scraper-config, owned by the scraper's user.
copy_scraper_files() {
    tar -C "$1" -cf - scraper.py feedlist.json \
        | dc run -T --rm --no-deps --user root --entrypoint sh scraper-subscribe \
            -c 'tar -xf - -C /config && chown -R 1000:1000 /config && chmod 600 /config/scraper.py'
}

# The scraper has to use zsazsa's SCRAPER_MARKER_TAG and SCRAPER_REDIS_CHANNEL.
check_scraper_config() {
    local marker channel matches
    { read -r marker; read -r channel; } < <(zpy -c \
        'import config; print(config.SCRAPER_MARKER_TAG); print(config.SCRAPER_REDIS_CHANNEL)' \
        < /dev/null | tail -2)
    matches=$(dc run -T --rm --no-deps --entrypoint python scraper-subscribe -c \
        'import sys, scraper; print(sys.argv[1] in scraper.misp_scraper_tags_local and scraper.redis_channel == sys.argv[2])' \
        "$marker" "$channel" < /dev/null 2> /dev/null | tail -1)
    if [[ "$matches" == True ]]; then
        did "misp-scraper is configured: events tagged $marker, channel '$channel'."
    else
        next "Make misp-scraper tag its events $marker (misp_scraper_tags_local) and listen on '$channel' (redis_channel), in docker/volumes/scraper-config/scraper.py."
    fi
}

# The /zsazsa proxy in misp-core's nginx, installed through the container (its data folder is root's).
apply_nginx() {
    local core
    core=$(docker ps --filter "network=$MISP_NETWORK" --format '{{.Names}}' | grep -m1 misp-core || true)
    if [[ -z "$core" ]]; then
        next "No misp-core container on $MISP_NETWORK. Start MISP and run setup again, or copy docker/misp-docker/ to misp-docker's custom/files."
        return 0
    fi
    docker exec "$core" mkdir -p /custom/files
    docker cp -q "$DIR/misp-docker/zsazsa-nginx.sh" "$core:/custom/files/zsazsa-nginx.sh"
    if ! docker exec "$core" test -f /custom/files/customize_misp.sh; then
        docker cp -q "$DIR/misp-docker/customize_misp.sh" "$core:/custom/files/customize_misp.sh"
    elif ! docker exec "$core" grep -q zsazsa-nginx.sh /custom/files/customize_misp.sh; then
        next "misp-docker has its own customize_misp.sh; add this line to it: /custom/files/zsazsa-nginx.sh"
    fi
    if docker exec "$core" /custom/files/zsazsa-nginx.sh > /dev/null 2>&1; then
        ok "misp-core proxies /zsazsa to zsazsa"
        did "misp-core ($core) proxies /zsazsa to zsazsa, now and on every start."
    else
        next "misp-core ($core) rejected the /zsazsa proxy; check its nginx configuration."
    fi
}

main() {
    if ! docker_available; then
        fail "This needs Docker with the compose plugin (docker compose)."
        exit 1
    fi
    printf '\n%s  zsazsa%s  Docker setup\n\n' "$B" "$N"
    hint "Nothing is changed until the last question. Enter accepts the [default]."
    interview
    confirm_plan
    heading "Setting up"
    docker_apply
    if [[ "$PROXY" == yes && "$MISP_WHERE" == 1 ]]; then
        apply_apache
    elif [[ "$PROXY" == yes && "$MISP_WHERE" == 3 ]]; then
        apply_nginx
    fi
    proxy_notes
    overview
}

# Sourced by the tests, which call the functions one by one.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main
fi
