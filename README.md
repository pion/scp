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
<br>

🚧 Under construction, come back soon! 🚧

The current focus is testing RACK, stream schedulers and user message interleaving (RFC 8260), and compatibility with older clients.

This project is a tool that tests Pion's SCTP implementations across revisions.
### Usage

Run the CLI directly with Go:

```bash
go run ./cmd/scp <command> [flags]
```


### Development

Run the unit tests and static checks from the repository root:

```bash
go test ./...
go test -race ./...
go vet ./...
```

### Contributing
Check out the [contributing wiki](https://github.com/pion/webrtc/wiki/Contributing) to join the group of amazing people making this project possible

### License
MIT License - see [LICENSE](LICENSE) for full text
