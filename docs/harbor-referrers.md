# SBOM attestations on Harbor 2.9.0

Measured on 2026-11-12 against `harbor.cyverse.org` (Harbor v2.9.0) with
cosign v3.1.4, oras 1.3.6 and crane 0.22.1, using a scratch image.

## What works

- Harbor accepts manifests with a `subject` (OCI 1.1 referrers) and lists them
  under the image as accessories (`GET /api/v2.0/projects/<p>/repositories/<r>/artifacts/<digest>/accessories`).
- `oras attach` of a 4 MB CycloneDX file, `cosign attest --type cyclonedx` with
  a 4 MB and an 18 MB predicate (24 MB bundle), and `cosign sign` all upload.

## What does not

`GET /v2/<repo>/referrers/<digest>` returns the referrers, but

- with `Content-Type: application/json` instead of
  `application/vnd.oci.image.index.v1+json`, and
- with every descriptor's `artifactType` set to the referrer's *config* media
  type (`application/vnd.oci.empty.v1+json`) instead of its own `artifactType`.

`oras` and `cosign` treat that as "no referrers API" and look for the fallback
tag `sha256-<hex of the subject digest>` defined by the OCI distribution spec.
Nothing wrote that tag (Harbor had accepted the pushes as referrers), so
`cosign verify-attestation`, `cosign verify`, `cosign tree` and `oras discover`
all report nothing.

## Workaround used by the release

After attaching, push a correct OCI image index to the fallback tag
(`ci/referrers_index.py`, `ci/attach_sbom.sh`). With it in place all four
commands above work unchanged, and they keep working after Harbor is upgraded
to a release whose referrers API is correct.

## Deleting

With the fallback tag in place Harbor refuses every delete through the
registry API (`VIOLATE_FOREIGN_KEY_CONSTRAINT`): the index references the
referrers, and the referrers are accessories of the image. Order that works:

1. give each referrer a tag (`crane tag <repo>@<referrer digest> tmp-N`);
2. delete the fallback index by digest;
3. delete the image by digest (Harbor removes its accessories and their tags).

## Not yet measured

Keyless signing (GitHub OIDC, Fulcio, Rekor) can only run inside a workflow.
The offline tests used a throwaway key with a signing config that has no
transparency log (`cosign signing-config create --out f`) and
`--insecure-ignore-tlog` on verify.
