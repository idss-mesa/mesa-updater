# GitHub Apps and access

The automation acts through three GitHub Apps, a handful of secrets, and
rules on who may change `main`. This page says what each one is for and what
it can and cannot do. It contains no secret values; those exist only where
the last column of each table says.

## Why GitHub Apps

A workflow gets a token of its own from GitHub, but that token is limited to
the repository the workflow runs in, and it is deliberately restricted: in
these repos it may not open or approve a pull request, and most of what it
does starts no other workflow. Three jobs need more than that, and each got
its own
**GitHub App**: an identity with a fixed, minimal set of permissions,
installed only on the repositories it needs, that is not tied to any
person's account.

| App | What it is for | Permissions | Installed on | Where its private key lives |
|---|---|---|---|---|
| `mesa-updater` | Opening the daily update pull request (planned), so that the pull-request check runs on it without anyone starting it. A workflow's own token is not allowed to open pull requests in these repos, and where it is allowed, the check on such a pull request waits until someone with write access approves the run | Contents, Pull requests, Workflows, Actions: read and write | the five image repos | An organisation secret, available to the five image repos |
| `mesa-gpu-dispatch` | Letting an image repo's release ask the builder for a GPU build | Actions: read and write | the builder repo only | A secret of the `gpu-dispatch` environment in each image repo, which only runs on `main` can read |
| `mesa-gpu-runner` | Registering the single-job runner on the GPU server | Administration: read and write | the builder repo only | A file on the GPU server readable only by root. It is not stored on GitHub |

What each App **cannot** do matters as much:

- `mesa-updater` is not installed on the builder repo, and must never be.
  It can change files and workflows wherever it is installed, and its key
  is available to workflows in public repos.
- `mesa-gpu-dispatch` can start, cancel and re-run workflow runs in the
  builder repo and read or delete their logs and artifacts. It cannot push
  code, change a workflow, read secrets or touch runners. So it can ask for
  builds and disturb them, but not change what a build does: every build
  goes through the builder's own checks ([GPU builds](gpu-builds.md)).
- `mesa-gpu-runner` can administer the builder repo, which registering a
  runner requires. That is why its key never leaves the GPU server and the
  runner's own account cannot read it.

No other App with permission to change code or workflows may be installed on
the builder repo.

## Secrets and variables

| Name | Kind | Where | Used by |
|---|---|---|---|
| `HARBOR_USERNAME`, `HARBOR_PASSWORD` | secrets | the image repos; separately in the builder repo | pushing images and attestations to the registry |
| `MESA_GPU_DISPATCH_PRIVATE_KEY` | secret | environment `gpu-dispatch` of each image repo | the release's `gpu` job |
| `MESA_GPU_DISPATCH_APP_ID` | variable | the same environment | the same job |
| `MESA_UPDATER_PRIVATE_KEY` | secret | organisation, for the five image repos | the daily update check (planned) |
| `MESA_UPDATER_APP_ID` | variable | organisation, for the five image repos | the same |

Signing needs no stored secret at all. The SBOM attestations are signed
"keyless": for each run GitHub issues a short-lived identity token, and
[Sigstore](https://www.sigstore.dev) turns it into a certificate that names
the workflow, repository, branch and commit and is valid for minutes. There
is no signing key to steal or rotate.

Secrets are passed to scripts through standard input or environment files,
never on a command line, where other users of a shared machine could see
them.

## The `gpu-dispatch` environment

A GitHub *environment* is a named set of secrets with rules about which runs
may use them. Each image repo has one, `gpu-dispatch`, with a single rule:
only runs on the branch `main`.

That is what keeps the key away from branches. A secret stored on the
repository or the organisation can be read by a workflow on *any* branch,
and anyone with write access can push a branch. A secret in this
environment can only be read by code that is already on `main`.

## Branch rules

`main` of the five image repos and of this repo is protected by a ruleset:

- changes arrive only through a pull request;
- the pull request needs an approval from someone other than the person who
  pushed last, and new commits dismiss earlier approvals;
- no force pushes, and `main` cannot be deleted.

Organisation owners may merge a pull request without the second approval;
they still cannot push to `main` directly.

This is the foundation of everything else: "the code on `main`" is what the
release builds, what the GPU server runs, and what the signing certificate
vouches for.

## Who can do what

| Action | Who |
|---|---|
| Open a pull request | anyone |
| Run the pull-request check on a pull request from a fork | automatic for anyone who already has a commit or pull request merged in that repo; for everyone else, someone with write access approves each run |
| Push a branch to an image repo | members of the organisation's developer team |
| Merge to `main` | a team member, after an approving review from another account with write access (see [Limits](#limits-to-know-about)); or an organisation owner |
| Start a release | whoever merges a change to `VERSION`; or a team member, by hand, on `main` |
| Start a test run | a team member |
| Push anything to the builder repo | organisation owners only |
| Change the Apps, secrets, environments or rulesets | organisation owners and repo administrators |

## Limits to know about

- **A registry tag alone proves nothing.** The registry credentials are
  ordinary secrets of the image repos, so a workflow on any branch can use
  them. Someone with write access could move a rolling tag or create a
  `vX.Y.Z` tag directly. What they cannot do is produce the attestation: an
  image is a release only together with a signature from the release
  workflow on `main`. [Verifying an image](verifying-an-image.md) checks
  exactly that. Moving the registry credentials behind a `main`-only
  environment would close this and is not done yet.
- **Release tags are to be immutable in the registry.** The pipeline never
  moves a `v*` tag. A registry rule that stops anyone else from moving one
  is being set up with the first release; until it is confirmed, treat the
  attestation, not the tag, as the proof.
- **Owners can bypass the review.** That is a deliberate choice for a small
  team; it means "on `main`" reads as "approved by a second account with
  write access, or merged by an owner".
- **The second approval is not guaranteed to be a person.** The ruleset
  counts an approving review from any account with write access other than
  the last pusher, and that includes a GitHub App with Pull requests:
  write. The `mesa-updater` key is an organisation secret that a workflow on
  any branch of an image repo can read, so someone with write access could
  use it to approve their own pull request. Keeping that key in an
  environment limited to `main`, as the dispatch key is, closes this and is
  not done yet.

The remaining known gaps of the release workflow are listed in
[`ci/README.md`](../ci/README.md#release).
