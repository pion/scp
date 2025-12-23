<h1 align="center">
  <br>
   SCTP Compliance & Performance
  <br>
</h1>
<h4 align="center">SCTP Test & Performance Tool</h4>
<p align="center">
  <a href="https://pion.ly"><img src="https://img.shields.io/badge/pion-scp-gray.svg?longCache=true&colorB=brightgreen" alt="Pion scp"></a>
  <a href="https://discord.gg/PngbdqpFbt"><img src="https://img.shields.io/badge/join-us%20on%20discord-gray.svg?longCache=true&logo=discord&colorB=brightblue" alt="join us on Discord"></a> <a href="https://bsky.app/profile/pion.ly"><img src="https://img.shields.io/badge/follow-us%20on%20bluesky-gray.svg?longCache=true&logo=bluesky&colorB=brightblue" alt="Follow us on Bluesky"></a>  <br>
  <img alt="GitHub Workflow Status" src="https://img.shields.io/github/actions/workflow/status/pion/scp/test.yaml">
  <a href="https://pkg.go.dev/github.com/pion/scp"><img src="https://pkg.go.dev/badge/github.com/pion/scp.svg" alt="Go Reference"></a>
  <a href="https://codecov.io/gh/pion/scp"><img src="https://codecov.io/gh/pion/scp/branch/master/graph/badge.svg" alt="Coverage Status"></a>
  <a href="https://goreportcard.com/report/github.com/pion/scp"><img src="https://goreportcard.com/badge/github.com/pion/scp" alt="Go Report Card"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
</p>
<h6 align="center">Any connection between this project name and the SCP Foundation is purely coincidental… or not. 👀</h6>
<br>

🚧 Under construction, come back soon! 🚧

THis is currently made and optimized to test RACK, (Stream Schedulers and User Message Interleaving)RFC-8260, and compatiblity testing with older clients

This project is a tool that tests Pion's SCTP implementations across revisions. It can:
- Test *any* Pion SCTP version or local checkout
- Simulate network conditions such as dynamic RTT, loss, and reordering
- Run cross-version compatibility and regression scenarios

### Usage

Run the CLI directly with Go:

```bash
go run ./cmd/scp <command> [flags]
```

Global flags:
- `--verbose` enable verbose logging
- `--dry-run` show actions without writing results

#### Resolve references

Resolve ref selectors into `.scp/manifest.json` and `.scp/lock.json`:

Selectors:
- `tag:v1.8.0`
- `branch:master` (supports wildcards: `branch:release/*`)
- `commit:deadbeef`
- `pr:1234`
- `path:/absolute/path` or `path:./relative/path`
- `range:>=1.9,<1.10` (semver constraint, expands to matching tags)

Flags:
- `--refs` comma-separated selector list (may repeat, or pass selectors as args)
- `--repo` repository URL to mirror (default: `https://github.com/pion/sctp`)
- `--cache` cache directory for mirrors and checkouts (default: `.scp/cache`)
- `--include-pre` include prerelease tags when resolving ranges
- `--out-manifest` output path for manifest JSON (default: `.scp/manifest.json`)
- `--out-lock` output path for lock JSON (default: `.scp/lock.json`)
- `--freeze-at` RFC3339 timestamp to pin moving refs
- `--local-allow-dirty` permit path selectors with local modifications

#### Update lock entries

Refresh lock entries for floating selectors in the manifest:

```bash
go run ./cmd/scp update --manifest .scp/manifest.json --lock .scp/lock.json
```

Flags:
- `--manifest` path to manifest.json
- `--lock` path to lock.json to update
- `--only` comma-separated entry names to refresh
- `--freeze-at` RFC3339 timestamp to pin moving refs

#### Generate harness code

Generate wrappers, runners, and harness code into `generated/`:

```bash
go run ./cmd/scp generate --lock .scp/lock.json --out generated
```

Flags:
- `--lock` path to lock.json
- `--features` path to features.yaml
- `--out` output directory for generated code
- `--package` name of generated API package
- `--runner-proto` runner transport protocol (`stdio-json` or `rpc`)
- `--modmode` module resolve mode (`remote` or `local-cache`)
- `--license` optional license header file path
- `--only` comma-separated list of lock entries to generate

#### Run tests

Run cross-revision scenarios (this generates and runs the harness under `generated/`):

```bash
go run ./cmd/scp test --lock .scp/lock.json --pairs matrix --cases max-burst --repeat 3
```

Flags:
- `--lock` path to lock.json
- `--pairs` pair selection mode: `adjacent` (default), `latest-prev`, `matrix`, `explicit`, `self`
- `--include` include only these entries (comma-separated)
- `--exclude` exclude these entries (comma-separated)
- `--explicit` explicit pairs when `--pairs=explicit` (comma-separated `A:B`, use names from lock.json)
- `--cases` scenario IDs to run (comma-separated)
- `--timeout` overall timeout for each pair (default: `2m`)
- `--seed` base seed (0 = default)
- `--out` path to write JUnit XML results
- `--out-dir` directory to write run artifacts
- `--interleaving` override interleaving mode (`auto`, `on`, `off`)
- `--pprof-cpu` path to write CPU profile
- `--pprof-heap` path to write heap profile
- `--pprof-allocs` path to write allocs profile
- `--repeat` number of times to run each pair (>=1)

Scenario IDs (with default network profiles):
- `max-burst` (default) — baseline burst with no induced delay/loss/reordering
- `handshake` — handshake-only scenario with baseline network settings
- `unordered-late-low-rtt` — min delay 10ms, jitter 10ms, unordered, 0% loss
- `unordered-late-high-rtt` — min delay 180ms, jitter 60ms, unordered, 0% loss
- `unordered-late-dynamic-rtt` — min delay 40ms, jitter 180ms, unordered, 0% loss
- `congestion` — min delay 60ms, jitter 40ms, ordered, 2% loss
- `retransmission` — min delay 40ms, jitter 20ms, ordered, 5% loss
- `reorder-low` — min delay 15ms, jitter 25ms, unordered, 1.5% loss
- `reorder-high` — min delay 140ms, jitter 120ms, unordered, 2.5% loss
- `burst-loss` — min delay 50ms, jitter 50ms, unordered, 4% loss
- `fragmentation` — oversized payloads to trigger fragmentation/reassembly
- `interleaving` — oversized payloads with interleaving enabled (RFC 8260)
- `media-hevc` — one-way 4 Mbps RTP-like HEVC pattern with B-frames (3% loss)
- `fault-checksum` — corrupts every 7th data chunk checksum (negative case)
- `fault-bad-chunk-len` — corrupts every 7th data chunk length (negative case)
- `fault-nonzero-padding` — corrupts every 7th data chunk padding (negative case)

Examples:

```bash
go run ./cmd/scp resolve --refs "tag:v1.8.0,branch:master"
go run ./cmd/scp test --lock .scp/lock.json
```

```bash
go run ./cmd/scp test --pairs explicit --explicit "branch_master_abcdef0:tag_v1_8_0_1234567"
```

```bash
go run ./cmd/scp test --cases "congestion,retransmission" --out .scp/out/results.xml
```

#### Artifacts

- `.scp/manifest.json` resolved selector list
- `.scp/lock.json` pinned revisions
- `.scp/cache/` git mirrors and checkouts
- `generated/` harness module and wrappers
- `--out` JUnit XML report
- `--out-dir` per-run artifacts (config.json, results.json, seed.txt, packets/<case>/<pair>_iter_<n>.jsonl)
- `--pprof-*` optional CPU/heap/allocs profiles

### Community
Pion has an active community on the [Discord](https://discord.gg/PngbdqpFbt).

Follow the [Pion Bluesky](https://bsky.app/profile/pion.ly) or [Pion Twitter](https://twitter.com/_pion) for project updates and important WebRTC news.

We are always looking to support **your projects**. Please reach out if you have something to build!
If you need commercial support or don't want to use public methods you can contact us at [team@pion.ly](mailto:team@pion.ly)

### Contributing
Check out the [contributing wiki](https://github.com/pion/webrtc/wiki/Contributing) to join the group of amazing people making this project possible

### License
MIT License - see [LICENSE](LICENSE) for full text
