#!/bin/bash
# run.sh IMAGE: run netbox-in-malcolm.sh in a Malcolm NetBox image, against the job's PostgreSQL and Redis services.
# The plugin is copied (pip builds in the directory) into what Malcolm mounts as ./netbox/custom-plugins/.
set -euo pipefail
image=$1
root=$(cd "$(dirname "$0")/../.." && pwd)
plugins=$(mktemp -d)
mkdir -p "$plugins/requirements"
cp -r "$root" "$plugins/netbox-ot"
rm -rf "$plugins/netbox-ot/.git"

docker run --rm --network host \
  -e DB_HOST=localhost -e DB_PORT=5432 -e DB_NAME=netbox -e DB_USER=netbox -e DB_PASSWORD=netbox \
  -e REDIS_HOST=localhost -e REDIS_CACHE_HOST=localhost \
  -e DROP_BROKEN_MALCOLM_PLUGINS="${DROP_BROKEN_MALCOLM_PLUGINS:-}" \
  -e SECRET_KEY="ci-only-not-a-secret-$(printf 'x%.0s' {1..40})" \
  -e API_TOKEN_PEPPER_1="ci-only-not-a-secret-$(printf 'y%.0s' {1..40})" \
  -v "$plugins:/opt/netbox-custom-plugins" \
  -v "$root/.github/malcolm/netbox-in-malcolm.sh:/netbox-in-malcolm.sh:ro" \
  --entrypoint /bin/bash "$image" /netbox-in-malcolm.sh
