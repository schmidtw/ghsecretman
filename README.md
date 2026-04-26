# ghsecretman

A tool for managing GitHub Actions secrets, Actions variables, and Dependabot secrets across an organization. Reads a YAML file describing the desired state at three scopes — organization-level, per-repo, and fan-out-to-all-repos — and reconciles it against GitHub via three subcommands: `audit` (read-only diff), `apply` (write managed values), and `enforce` (apply plus delete unlisted values, with `--dry-run`).

See the design and full requirements in [PRD #1](https://github.com/schmidtw/ghsecretman/issues/1).

## License

Apache-2.0. See [LICENSE](LICENSE).
