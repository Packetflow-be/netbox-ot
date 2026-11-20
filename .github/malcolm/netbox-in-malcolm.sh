#!/bin/bash
# Runs inside Malcolm's NetBox image, with netbox-ot mounted under /opt/netbox-custom-plugins/netbox-ot the way a
# Malcolm user drops a plugin into ./netbox/custom-plugins/. Installs it with Malcolm's own installer (which also
# adds it to PLUGINS and migrates), then loads the demo plant and runs the checks and the test suite.
set -euo pipefail
PY=/opt/netbox/venv/bin/python
cd /opt/netbox/netbox

echo "NetBox $(grep -m1 '^version:' release.yaml | cut -d' ' -f2 | tr -d '"')"
echo "Plugins Malcolm ships: $(grep -E '^PLUGINS' /etc/netbox/config/plugins.py || echo none)"

# A fresh database: NetBox's own migrations first, as Malcolm's entrypoint does on first start
$PY manage.py migrate --no-input >/dev/null

python3 /usr/local/bin/netbox_install_plugins.py
grep -q "'netbox_ot'" /etc/netbox/config/plugins.py || { echo "netbox_ot was not added to PLUGINS"; exit 1; }
echo "PLUGINS after Malcolm's installer: $(grep -E '^PLUGINS' /etc/netbox/config/plugins.py)"

if ! $PY manage.py check >/tmp/check.log 2>&1; then
  cat /tmp/check.log
  # Malcolm's own netbox_healthcheck_plugin (django-health-check) reads EMAIL_BACKEND, which Django 6.1 (NetBox 4.7)
  # refuses once MAILERS is set: NetBox does not start at all. That is Malcolm's to fix before it moves to 4.7, not
  # netbox-ot's; the job built on 4.7 sets DROP_BROKEN_MALCOLM_PLUGINS to go on without it and say so.
  if [ "${DROP_BROKEN_MALCOLM_PLUGINS:-}" = 1 ] && grep -q 'health_check' /tmp/check.log; then
    echo "::warning::Malcolm's netbox_healthcheck_plugin breaks NetBox 4.7 (EMAIL_BACKEND with MAILERS); removed from PLUGINS for this test"
    sed -i "s/'netbox_healthcheck_plugin', *//; s/, *'netbox_healthcheck_plugin'//" /etc/netbox/config/plugins.py
    grep -E '^PLUGINS' /etc/netbox/config/plugins.py
    $PY manage.py check
  else
    exit 1
  fi
fi
$PY manage.py migrate --no-input >/dev/null
$PY manage.py showmigrations netbox_ot
$PY manage.py ot_demo
$PY manage.py ot_check --fail-on never | tail -1
$PY manage.py collectstatic --no-input >/dev/null

# The full suite beside Malcolm's own plugins. Query counts differ with other plugins installed, so they are
# recorded instead of asserted (needs a serial run), as on the other NetBox versions in ci.yml.
UPDATE_QUERY_COUNTS=1 $PY manage.py test netbox_ot --noinput
