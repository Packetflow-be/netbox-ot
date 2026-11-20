# Malcolm bench

Public ICS captures run through Malcolm's Zeek image the way Malcolm processes an uploaded PCAP, then read by the
importer. Run by the `bench` job of [malcolm.yml](../workflows/malcolm.yml). It catches what unit tests with
hand-made log lines miss: a new Zeek or ICSNPP release that changes a log format (Zeek 8 once doubled every
Modbus count), a parser that starts or stops logging a protocol, a function the tables do not classify.

| File | What |
|---|---|
| `datasets.json` | The captures: source, licence, credit, SHA-256, and a zone map for the ones that get a full import |
| `zeek.sh` | Downloads and checks the captures, runs Malcolm's Zeek image over each one |
| `measure.py` | Runs inside NetBox: what the importer reads per protocol, and for datasets with a zone map a real import and `ot_check` |
| `zones/` | Zone maps |
| `expected/` | The recorded results the job compares with |

## The captures

All come from the [`data-v1` release](https://github.com/SackOfHacks/ICS-PCAP-Challenges/releases/tag/data-v1) of
SackOfHacks/ICS-PCAP-Challenges, which mirrors them unmodified under their own licences. They are downloaded when
the job runs and checked against the SHA-256 in `datasets.json`; netbox-ot does not redistribute them.

| Dataset | Credit | Licence |
|---|---|---|
| DFRWS 2023 Forensic Challenge, *The Troubled Elevator* | DFRWS; SAFE Lab, Virginia Commonwealth University ([source](https://github.com/dfrws/dfrws2023-challenge)) | Apache-2.0 |
| CybICS training platform, incident modules | Matthias Niedermaier ([source](https://github.com/mniedermaier/CybICS)) | MIT |
| ICSNPP parser test traces | CISA and Idaho National Laboratory ([source](https://github.com/cisagov/ICSNPP)) | BSD-3-Clause |
| IEC 60870-5-104 testbed traffic | Peter Maynard, Queen's University Belfast ([doi:10.6084/m9.figshare.6133457.v1](https://doi.org/10.6084/m9.figshare.6133457.v1)) | CC BY 4.0 |
| Industroyer2 IEC-104 traffic | Netresec, Erik Hjelmvik ([source](https://www.netresec.com/?page=Blog&month=2022-04&post=Industroyer2-IEC-104-Analysis)) | CC BY 4.0 |

Thanks to the SackOfHacks/ICS-PCAP-Challenges project for collecting and mirroring them.

## When the result changes

The job fails when a result differs from `expected/` and prints the difference. If the change is intended (an
importer fix, a new Malcolm release):

1. Run the *Malcolm* workflow by hand with **record** ticked (Actions → Malcolm → Run workflow, on your branch).
2. Download its `bench-results` artifact and copy `results/<dataset>.json` over `expected/<dataset>.json`.
3. Commit the expected files with the change, so the review shows what moved.

To add a capture: add it to `datasets.json` (licence that allows the use, SHA-256 of the mirrored archive), and
a zone map under `zones/` if it should get a full import.
