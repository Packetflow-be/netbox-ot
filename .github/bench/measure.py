# Bench measurement, run inside NetBox (manage.py shell -c "exec(open('.../measure.py').read())").
#
# For each dataset in datasets.json whose Zeek logs zeek.sh wrote to $BENCH_WORK/logs/<id>/:
#   parse   what the importer reads from the logs, before any zone: requests per protocol, per access class, and
#           the functions no table classifies (the ones that matter most first). This is where a Zeek or ICSNPP
#           format change shows up (a doubled count, a log the importer no longer reads).
#   import  for datasets with a zone map: a real import into a site of its own, then the flows between zones and
#           the ot_check findings.
# The result is compared with expected/<id>.json; BENCH_RECORD=1 writes the expected files instead.
# Every result also lands in $BENCH_WORK/results/ (uploaded as an artifact) with the import output.
import difflib
import io
import json
import os
from collections import Counter, defaultdict
from contextlib import redirect_stdout
from pathlib import Path

from django.core.management import call_command
from django.db.models import Q

from dcim.models import Site
from users.models import User

from netbox_ot.importers import zeek
from netbox_ot.importers.functions import UNCLASSIFIED, classify
from netbox_ot.importers.observations import protocol_value
from netbox_ot.models import Flow

BENCH = Path(os.environ['BENCH_DIR'])
WORK = Path(os.environ['BENCH_WORK'])
RECORD = os.environ.get('BENCH_RECORD') == '1'
TOP_UNCLASSIFIED = 15

results_dir = WORK / 'results'
results_dir.mkdir(parents=True, exist_ok=True)
manifest = json.loads((BENCH / 'datasets.json').read_text())


def parse(logdir):
    _, flows, _ = zeek.to_observations(zeek.read_logs(logdir), zeek.ZoneMap(networks={'0.0.0.0/0': 'All'}))
    protocols = defaultdict(lambda: {'requests': 0, 'access': Counter(), 'unclassified': Counter()})
    for f in flows:
        proto = protocol_value(f['proto']) or f['proto']
        func = f.get('func') or ''
        access = f.get('access') or (classify(proto, func) if func else '')
        p = protocols[proto]
        p['requests'] += f['count']
        p['access'][access or 'no function'] += f['count']
        if access == UNCLASSIFIED and func:
            p['unclassified'][func] += f['count']
    return {
        proto: {
            'requests': p['requests'],
            'access': dict(sorted(p['access'].items())),
            'unclassified': dict(sorted(p['unclassified'].most_common(TOP_UNCLASSIFIED),
                                        key=lambda kv: (-kv[1], kv[0]))),
        }
        for proto, p in sorted(protocols.items())
    }


def write_observations(dataset, logdir):
    # The same logs and zone map as observation files (assets, flows, summary): aggregated requests, no packets. This
    # is what the capture demo (netbox_ot/data/demo/<id>/, ot_demo --capture) is made from.
    zone_map = zeek.ZoneMap.from_csv(BENCH / dataset['import']['zone_map'])
    assets, flows, summary = zeek.to_observations(zeek.read_logs(logdir), zone_map, captures=[dataset['title']])
    out = results_dir / f"{dataset['id']}.observations"
    out.mkdir(exist_ok=True)
    for name, data in (('assets', assets), ('flows', flows), ('summary', summary)):
        (out / f'{name}.json').write_text(json.dumps(data, indent=1, sort_keys=True) + '\n')


def import_and_check(dataset, logdir):
    write_observations(dataset, logdir)
    spec = dataset['import']
    site, _ = Site.objects.get_or_create(slug=f"bench-{dataset['id']}", defaults={'name': f"bench {dataset['id']}"})
    args = {'site': site.slug, 'zone_map': str(BENCH / spec['zone_map'])}
    if spec.get('split_all'):
        args['split_all'] = True
    out = io.StringIO()
    with redirect_stdout(out):
        call_command('ot_import', str(logdir), stdout=out, **args)
        check = io.StringIO()
        call_command('ot_check', site=site.slug, json=True, fail_on='never', stdout=check)
    (results_dir / f"{dataset['id']}.import.txt").write_text(out.getvalue())
    flows = sorted(
        f"{f.source_zone} -> {f.destination_zone}: {f.protocol or '-'} "
        f"[{', '.join(f.access) or 'no class'}] {', '.join(f.port_mappings)}".rstrip()
        for f in Flow.objects.filter(Q(conduit__site=site) | Q(source_zone__site=site) | Q(destination_zone__site=site))
        .distinct().select_related('source_zone', 'destination_zone')
    )
    findings = Counter(f"{f['severity']} {f['check']}" for f in json.loads(check.getvalue()))
    return {'flows': flows, 'findings': dict(sorted(findings.items()))}


if not User.objects.filter(is_superuser=True).exists():
    User.objects.create_superuser('bench', 'bench@example.invalid', None)

failed, summary = [], []
for dataset in manifest['datasets']:
    logdir = WORK / 'logs' / dataset['id']
    result = {'parse': parse(logdir)}
    if dataset.get('import'):
        result['import'] = import_and_check(dataset, logdir)
    text = json.dumps(result, indent=2) + '\n'
    (results_dir / f"{dataset['id']}.json").write_text(text)

    total = sum(p['requests'] for p in result['parse'].values())
    unclassified = sum(p['access'].get(UNCLASSIFIED, 0) for p in result['parse'].values())
    findings = sum(result.get('import', {}).get('findings', {}).values()) if dataset.get('import') else '-'
    expected_path = BENCH / 'expected' / f"{dataset['id']}.json"
    if RECORD:
        expected_path.write_text(text)
        status = 'recorded'
    elif not expected_path.exists():
        status = 'no expected file'
        failed.append(dataset['id'])
    elif expected_path.read_text() == text:
        status = 'as expected'
    else:
        status = 'CHANGED'
        failed.append(dataset['id'])
        print(f"::group::{dataset['id']}: differs from expected/{dataset['id']}.json")
        print(''.join(difflib.unified_diff(expected_path.read_text().splitlines(True), text.splitlines(True),
                                           f"expected/{dataset['id']}.json", 'this run')))
        print('::endgroup::')
    summary.append(f"| {dataset['id']} | {total:,} | {unclassified:,} | {findings} | {status} |")

table = '\n'.join(['| Dataset | Requests | Unclassified | Findings | Result |', '|---|---:|---:|---:|---|'] + summary)
print(table)
if os.environ.get('GITHUB_STEP_SUMMARY'):
    with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as fh:
        fh.write('## Malcolm bench\n\n' + (WORK / 'zeek-version.txt').read_text() + '\n' + table + '\n')
if failed:
    print(f"\nChanged: {', '.join(failed)}. If the change is intended (a fix, a new Malcolm release), re-record: run "
          "the Malcolm workflow with record=true and commit the expected files from its bench-results artifact.")
    raise SystemExit(1)
