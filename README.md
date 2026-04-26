# ghsecretman

A tool for managing GitHub Actions secrets, Actions variables, and Dependabot secrets across an organization. Reads a YAML file describing the desired state at three scopes — organization-level, per-repo, and fan-out-to-all-repos — and reconciles it against GitHub via three subcommands: `audit` (read-only diff), `apply` (write managed values), and `enforce` (apply plus delete unlisted values, with `--dry-run`).

See the design and full requirements in [PRD #1](https://github.com/schmidtw/ghsecretman/issues/1).

## Install

Pre-built binaries for darwin and linux on amd64 and arm64 are attached to each release on the [Releases page](https://github.com/schmidtw/ghsecretman/releases). Each release also publishes a `*-checksums.txt` file with SHA-512 sums of every artifact.

```sh
# Pick the asset that matches your platform, then:
tar xzf ghsecretman-<version>-<os>-<arch>.tar.gz
sudo install ghsecretman-<version>-<os>-<arch>/ghsecretman /usr/local/bin/
```

To build from source:

```sh
go install github.com/schmidtw/ghsecretman/cmd/ghsecretman@latest
```

`ghsecretman version` prints the version, commit, and build date stamped in at release time.

## Quick Start

`ghsecretman` authenticates with a personal access token from `GITHUB_TOKEN` (preferred) or `GH_TOKEN`. The token needs the scopes required to read and write the secrets/variables you list in the YAML.

A minimal config (`secrets.yml`) for an `audit` against one repo:

```yaml
github.com:
  example-org:
    per-repo:
      example-repo:
        managed:
          vars:
            APP_ENV:
              value: production
```

Run a read-only audit:

```sh
export GITHUB_TOKEN=ghp_...
ghsecretman audit --config secrets.yml --org example-org --repo example-repo
```

`audit` exits non-zero if any drift is found, so it is safe to run from CI as a drift detector. To write managed values, use `apply`; to also delete unlisted values, use `enforce` (which requires `--yes` for the destructive path or supports `--dry-run` for review).

Omit `--repo` to iterate every repo in the org concurrently; `--concurrency` bounds the worker pool.

## Configuration

The full YAML schema (`org`, `per-repo`, `all-repos`, `managed`, `ignored`, value sources, precedence rules, `org`-level `scope`/`repos`) is documented in [PRD #1](https://github.com/schmidtw/ghsecretman/issues/1). A complete annotated example lives in [`internal/schema/example.yml`](internal/schema/example.yml), and the same content is embedded in the binary — run `ghsecretman example` to print it, or `ghsecretman example -o secrets.yml` to write a starter config.

Top-level keys other than `github.com:` are ignored, so the same file can carry sections owned by other tools.

**Repo iteration is opt-in.** ghsecretman only enumerates an org's repositories when the YAML has either an `all-repos:` block or a `per-repo:` block for that repo. Without either, repo-level secrets/variables are invisible to the tool. If you only intend to manage org-level objects but also want existing repo-level cruft cleaned up, include an empty `all-repos:` block (empty `managed` maps and empty `ignored` lists). With nothing under `managed`, every existing repo-level entry is reported as `extra` by `audit` and deleted by `enforce`. Run `ghsecretman enforce --dry-run` first to confirm the list before letting deletes fire.

## License

Apache-2.0. See [LICENSE](LICENSE).
