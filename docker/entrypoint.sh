#!/bin/sh
# Entrypoint of every zsazsa container: copies the files a release adds into
# the volumes, never over one already there, and creates a missing config.
set -eu

for dir in config data zsazsaprompts; do
    cp -rn "/opt/zsazsa/$dir/." "/app/$dir/"
done

python docker/configure.py

exec "$@"
