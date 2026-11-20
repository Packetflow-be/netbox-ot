#!/bin/bash
# zeek.sh IMAGE WORKDIR: download the bench captures (datasets.json), check their SHA-256 and run each capture
# through Malcolm's Zeek image the way Malcolm processes an uploaded PCAP (zeek-offline -r <capture> local, in an
# empty directory, Malcolm's local.zeek with its ICSNPP parsers). Logs land in WORKDIR/logs/<dataset>/ as
# <stream>.<n>.log, one <n> per capture, which is how the importer reads several captures of one site.
set -euo pipefail
image=$1
work=$(realpath -m "$2")
here=$(cd "$(dirname "$0")" && pwd)
mirror=$(jq -r .mirror "$here/datasets.json")
mkdir -p "$work/download" "$work/pcap" "$work/logs"

docker pull -q "$image" >/dev/null
docker run --rm --entrypoint /usr/local/zeek/bin/zeek-offline "$image" --version | tee "$work/zeek-version.txt"

jq -r '.datasets[] | [.id, .asset, .sha256] | @tsv' "$here/datasets.json" | while IFS=$'\t' read -r id asset sha; do
  file="$work/download/$asset"
  [ -f "$file" ] || curl -sfL --retry 3 -o "$file" "$mirror/$asset"
  echo "$sha  $file" | sha256sum -c --quiet
  rm -rf "${work:?}/pcap/$id" "${work:?}/logs/$id"
  mkdir -p "$work/pcap/$id" "$work/logs/$id"
  tar xf "$file" -C "$work/pcap/$id" --strip-components=1
  find "$work/pcap/$id" -name '*.gz' -exec gunzip -f {} +

  n=0
  while IFS= read -r -d '' pcap; do
    n=$((n + 1))
    run="$work/run/$id-$n"
    rm -rf "$run"; mkdir -p "$run"
    cp "$pcap" "$run/capture"
    # Zeek writes its logs into the working directory; the container runs as the runner's user so they stay ours
    docker run --rm --network none --user "$(id -u):$(id -g)" -v "$run:/work" -w /work \
      --entrypoint /usr/local/zeek/bin/zeek-offline "$image" -r /work/capture local >"$run/zeek.out" 2>&1 \
      || echo "::warning::zeek exited non-zero on $id/$(basename "$pcap") (see the zeek-logs artifact)"
    for log in "$run"/*.log; do
      [ -e "$log" ] || continue
      mv "$log" "$work/logs/$id/$(basename "$log" .log).$n.log"
    done
    rm -f "$run/capture"
  done < <(find "$work/pcap/$id" -type f \( -name '*.pcap' -o -name '*.pcapng' -o -name '*.cap' \) -print0 | sort -z)
  echo "$id: $n capture(s), $(ls "$work/logs/$id" | wc -l) log file(s)"
done
