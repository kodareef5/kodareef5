## Koda Reef

Security research. Custom tooling, machine scale, hand validation.

| 43 | 34 | 34 | 32 | 26 |
|:---:|:---:|:---:|:---:|:---:|
| advisories | organizations | CVEs | sole reporter | High or Critical |

Verifiable in GitHub's advisory database —
[all](https://github.com/advisories?query=credit%3Akodareef5) ·
[critical](https://github.com/advisories?query=credit%3Akodareef5+severity%3Acritical) ·
[high](https://github.com/advisories?query=credit%3Akodareef5+severity%3Ahigh)

| Severity | | | Ecosystem | |
|---|--:|---|---|--:|
| Critical | 3 | `███` | Go | 24 |
| High | 23 | `███████████████████████` | Python | 7 |
| Medium | 13 | `█████████████` | PHP | 4 |
| Low | 4 | `████` | JavaScript | 4 |
| | | | Rust | 4 |

Severity as published in each advisory. February 2026 to present.
Two further advisories are pending credit correction
([CVE-2026-5366](https://nvd.nist.gov/vuln/detail/CVE-2026-5366),
[CVE-2026-42048](https://nvd.nist.gov/vuln/detail/CVE-2026-42048)) and are
not counted above.

## Volume

| | |
|---|---:|
| Reports submitted, all channels | **337** |
| Repositories reviewed | **114** |
| Security contacts corresponded with | **34** |
| Advisory threads participated in | **221** |
| Vendor confirmations on record | **9** |
| Findings awaiting triage | **21** |

## Coverage

| | |
|---|---|
| **Cryptography** | [Ed25519 signature malleability](https://github.com/advisories/GHSA-x3ff-w252-2g7j) · [variable-time HMAC](https://github.com/advisories/GHSA-r854-jrxh-36qx) · [`secure_link` timing](https://nginx.org/en/CHANGES) · ZKP verifiers accepting identity-point proofs (Fireblocks) · PRF state leak reversing proactive key refresh (Fireblocks) · ICS23 Go/Rust proof divergence (Cosmos) · missing curve validation in MPC blob deserializers (Coinbase) |
| **Identity and trust** | [OIDC client binding](https://github.com/advisories/GHSA-xqxv-4jc2-x56x) · [attestation verification](https://github.com/advisories/GHSA-w6c6-c85g-mmv6) · [`FORBID_TAGS` bypass](https://github.com/advisories/GHSA-h7mw-gpvr-xq4m) · [SAML NameID truncation](https://docs.goauthentik.io/security/cves/CVE-2026-40165) · [delegation matching](https://github.com/advisories/GHSA-qp9x-wp8f-qgjj) · [email domain bypass](https://github.com/advisories/GHSA-c5c4-8r6x-56w3) · [password reset token theft](https://github.com/advisories/GHSA-x3f4-v83f-7wp2) |
| **Platform and isolation** | [Helm impersonation bypass](https://github.com/advisories/GHSA-765j-qfrp-hm3j) · [symlink policy subversion](https://github.com/advisories/GHSA-q49m-57vm-c8cc) · [WireGuard key exposure](https://github.com/advisories/GHSA-gj49-89wh-h4gj) · [Lua injection](https://github.com/advisories/GHSA-x4mj-7f9g-29h4) · [DNS secret exfiltration](https://github.com/advisories/GHSA-r2pg-r6h7-crf3) · virtio-net TOCTOU ([Firecracker](https://github.com/firecracker-microvm/firecracker)) · Zuul canonicalization and hop-by-hop headers ([Netflix](https://github.com/Netflix/zuul)) |
| **AI and ML** | [command injection](https://github.com/advisories/GHSA-fgv4-6jr3-jgfw) · [template injection](https://github.com/advisories/GHSA-frv4-x25r-588m) · pickle deserialization and sandbox escape across ONNX, MLflow, PyTorch Lightning, Keras, Triton · [PoCs](https://huggingface.co/kodareef5) |
| **Supply chain** | [Perforce command injection](https://github.com/advisories/GHSA-gqw4-4w2p-838q) · [submodule validation](https://github.com/advisories/GHSA-p3hw-mv63-rf9w) · [tar path traversal](https://github.com/advisories/GHSA-73h3-mf4w-8647) · [`GIT_CONFIG_COUNT` injection](https://github.com/steveukx/git-js/blob/main/simple-git/CHANGELOG.md) |
| **Edge and proxy** | [BasicAuth timing oracle](https://github.com/advisories/GHSA-6x2q-h3cr-8j2h) · [email domain bypass](https://github.com/advisories/GHSA-c5c4-8r6x-56w3) · [collector auth bypass](https://github.com/advisories/GHSA-w5cv-pw74-4rxc) · Zuul canonicalization and hop-by-hop headers (Netflix) |

Coinbase · Netflix · AWS · NVIDIA · Bitcoin Core · Google · Swiss Post ·
Binance · Fireblocks · OpenSea · Pinterest · Cosmos

## Selected findings

**[CVE-2026-34976](https://nvd.nist.gov/vuln/detail/CVE-2026-34976) — Dgraph, 10.0.**
`restoreTenant` was absent from the middleware config map while its
neighbour `restore` had full coverage, so it ran with no authentication, no
IP allowlist and no audit logging. Chained to database overwrite, SSRF and
file read pre-auth. The proofs needed no credentials: anonymous S3 flags,
`file://` probing that enumerated the filesystem through error differences,
and Vault parameters reaching the Kubernetes service account token. The fix
was one line.

**[CVE-2026-41050](https://nvd.nist.gov/vuln/detail/CVE-2026-41050) — Rancher Fleet, 9.9.**
Two Helm execution paths kept `cluster-admin` credentials during
impersonated operations: the `lookup` template function, and `valuesFrom`
secret references read through the same client. Patched across five Rancher
trains.

**[CVE-2026-41520](https://nvd.nist.gov/vuln/detail/CVE-2026-41520) — Cilium, 7.9.**
`cilium-bugtool` and sysdump archives carried the WireGuard node key out of
the cluster. The key is static and never rotates, so an archived support
bundle decrypts node traffic and permits node impersonation until someone
rotates it by hand.

**ICS23 — Cosmos.** The Rust verifier skipped `MaxDepth` enforcement
whenever `min_depth` was zero, which is the case for both TendermintSpec
and SmtSpec, so Go and Rust disagreed on the same proof bytes. A prior
professional audit had found the same class and its remediation shipped
**Go-only** — `git show 1363533 -- rust/src/verify.rs` produces an empty
diff. The released Rust crate still carried it.

**Fireblocks MPC.** Schnorr and Diffie-Hellman-Log verifiers accepted
trivial zero proofs for the identity point, so a party could contribute
nothing to a key and still pass proof-of-knowledge. Separately, leaked
`prf` state allowed reversal of proactive key refresh, defeating the
guarantee that compromising two cosigners in different epochs is not
enough.

## Patch bypasses

[CVE-2026-41263](https://github.com/advisories/GHSA-6x2q-h3cr-8j2h) — Traefik
had already shipped a fix for a BasicAuth timing side-channel. The patch
looked up a bcrypt hash as if it were a username, so the constant-time
fallback secret was always empty and password checks failed in
microseconds instead of running bcrypt. The reported path was closed. The
class was not. Measured at a 130x timing ratio against the shipped binary.

| | |
|---|---|
| [BentoML](https://github.com/advisories/GHSA-fgv4-6jr3-jgfw) | advisory titled *"Incomplete fix for CVE-2026-33744"* |
| [Gotenberg](https://github.com/advisories/GHSA-qmwh-9m9c-h36m) | incomplete fix for an ExifTool arbitrary file write |
| NATS Server | three advisories, all incomplete fixes to one earlier batch |
| Cosmos ICS23 | remediation shipped Go-only; the released Rust crate still carried it |
| ClearML | incomplete fix for CVE-2024-24591 |
| PyTorch Lightning | `_instantiator` bypass, then an incomplete fix for that bypass |
| dtale | incomplete fix for CVE-2026-27194 |

## Credited upstream

| | |
| --- | --- |
| [nginx](https://nginx.org/en/CHANGES) | 1.31.2 — *"constant time `secure_link` hash comparison. Thanks to kodareef5."* |
| [Node.js](https://github.com/nodejs/node/blob/main/deps/cares/RELEASE-NOTES.md) | credited in vendored [c-ares](https://github.com/c-ares/c-ares.github.io/blob/main/changelog.md) |
| [vim](https://github.com/vim/vim) | fix shipped in v9.2.0271 and v9.2.0272 |
| [libevent](https://github.com/libevent/libevent/blob/master/ChangeLog) | HTTP header parsing restricted to prevent request smuggling |
| [libzip](https://github.com/nih-at/libzip/blob/main/THANKS) | THANKS |
| [DOMPurify](https://github.com/cure53/DOMPurify) | acknowledgements |
| [CloudNativePG](https://github.com/cloudnative-pg/cloudnative-pg/pull/10515) | escape layer, plus [admission validation](https://github.com/cloudnative-pg/cloudnative-pg/pull/10565); credited on [#10506](https://github.com/cloudnative-pg/cloudnative-pg/issues/10506) and [#10571](https://github.com/cloudnative-pg/cloudnative-pg/issues/10571) |
| [Red Hat](https://access.redhat.com/security/cve/CVE-2026-40938) | five errata across OpenShift product lines |

## Assessments

| | |
|---|---|
| *"exceptional additional detail on the exploitation path and demonstrates the full impact through comprehensive test cases"* | **Coinbase** |
| *"Your research clearly shows the severity of this vulnerability class."* | **Coinbase** |
| *"the comprehensive test cases demonstrating the HD wallet poisoning attack chain"* | **Coinbase** |
| *"comprehensive analysis with 27 test cases documenting multiple bypass vectors"* | **Netflix** |
| *"the comprehensive technical analysis you provided, including unit tests and wire-level documentation"* | **Netflix** |
| *"Your testing methodology and proof of concept demonstrate excellent security research skills."* | **Netflix** |
| *"excellent technical depth and comprehensive test cases"* | **Netflix** |
| *"Thank you for your report and the detailed analysis."* | **Anthropic** |

Press: [GBHackers](https://gbhackers.com/critical-dgraph-database-flaw/) ·
[Cybersecurity News](https://cybersecuritynews.com/dgraph-database-vulnerability/)
on the Dgraph 10.0.

## Advisories

| Advisory | CVE | Project | Class | Severity | Published |
| --- | --- | --- | --- | --- | --- |
| [GHSA-xqxv-4jc2-x56x](https://github.com/advisories/GHSA-xqxv-4jc2-x56x) | [CVE-2026-55672](https://nvd.nist.gov/vuln/detail/CVE-2026-55672) | **zitadel/zitadel** | Missing identity binding | High | 2026-06-18 |
| [GHSA-w5cv-pw74-4rxc](https://github.com/advisories/GHSA-w5cv-pw74-4rxc) | [CVE-2026-55701](https://nvd.nist.gov/vuln/detail/CVE-2026-55701) | **open-telemetry/opentelemetry-collector-contrib** | Logic flaw | Medium | 2026-06-18 |
| [GHSA-w5pp-99ch-qj29](https://github.com/advisories/GHSA-w5pp-99ch-qj29) | — | **go-git/go-git** | Denial of service | Medium | 2026-05-29 |
| [GHSA-qp9x-wp8f-qgjj](https://github.com/advisories/GHSA-qp9x-wp8f-qgjj) | — | **theupdateframework/python-tuf** | Delegation confusion | Medium | 2026-05-28 |
| [GHSA-765j-qfrp-hm3j](https://github.com/advisories/GHSA-765j-qfrp-hm3j) | [CVE-2026-41050](https://nvd.nist.gov/vuln/detail/CVE-2026-41050) | **rancher/fleet** | Impersonation bypass | Critical | 2026-05-07 |
| [GHSA-x494-mj8g-cj27](https://github.com/advisories/GHSA-x494-mj8g-cj27) | — | **GitoxideLabs/gitoxide** | Denial of service | High | 2026-05-05 |
| [GHSA-p3hw-mv63-rf9w](https://github.com/advisories/GHSA-p3hw-mv63-rf9w) | — | **GitoxideLabs/gitoxide** | Path traversal | High | 2026-05-05 |
| [GHSA-mm2q-qcmx-gw4w](https://github.com/advisories/GHSA-mm2q-qcmx-gw4w) | — | **rustfs/rustfs** | Missing authorization | High | 2026-05-05 |
| [GHSA-q49m-57vm-c8cc](https://github.com/advisories/GHSA-q49m-57vm-c8cc) | [CVE-2026-41326](https://nvd.nist.gov/vuln/detail/CVE-2026-41326) | **kata-containers/kata-containers** | Policy subversion | High | 2026-05-04 |
| [GHSA-gj49-89wh-h4gj](https://github.com/advisories/GHSA-gj49-89wh-h4gj) | [CVE-2026-41520](https://nvd.nist.gov/vuln/detail/CVE-2026-41520) | **cilium/cilium** | Information disclosure | High | 2026-04-25 |
| [GHSA-x4mj-7f9g-29h4](https://github.com/advisories/GHSA-x4mj-7f9g-29h4) | [CVE-2026-41246](https://nvd.nist.gov/vuln/detail/CVE-2026-41246) | **projectcontour/contour** | Code injection | High | 2026-04-24 |
| [GHSA-6x2q-h3cr-8j2h](https://github.com/advisories/GHSA-6x2q-h3cr-8j2h) | [CVE-2026-41263](https://nvd.nist.gov/vuln/detail/CVE-2026-41263) | **traefik/traefik** | Timing side-channel | Medium | 2026-04-24 |
| [GHSA-88gm-j2wx-58h6](https://github.com/advisories/GHSA-88gm-j2wx-58h6) | [CVE-2026-41321](https://nvd.nist.gov/vuln/detail/CVE-2026-41321) | **withastro/astro** | SSRF | Low | 2026-04-23 |
| [GHSA-pfcq-4gjr-6gjm](https://github.com/advisories/GHSA-pfcq-4gjr-6gjm) | [CVE-2026-40937](https://nvd.nist.gov/vuln/detail/CVE-2026-40937) | **rustfs/rustfs** | Missing authorization | High | 2026-04-22 |
| [GHSA-h7mw-gpvr-xq4m](https://github.com/advisories/GHSA-h7mw-gpvr-xq4m) | [CVE-2026-41240](https://nvd.nist.gov/vuln/detail/CVE-2026-41240) | **cure53/DOMPurify** | Validation bypass | Medium | 2026-04-22 |
| [GHSA-73h3-mf4w-8647](https://github.com/advisories/GHSA-73h3-mf4w-8647) | [CVE-2026-41140](https://nvd.nist.gov/vuln/detail/CVE-2026-41140) | **python-poetry/poetry** | Path traversal | Low | 2026-04-22 |
| [GHSA-wjxp-xrpv-xpff](https://github.com/advisories/GHSA-wjxp-xrpv-xpff) | [CVE-2026-40161](https://nvd.nist.gov/vuln/detail/CVE-2026-40161) | **tektoncd/pipeline** | Information disclosure | High | 2026-04-21 |
| [GHSA-rx35-6rhx-7858](https://github.com/advisories/GHSA-rx35-6rhx-7858) | [CVE-2026-40923](https://nvd.nist.gov/vuln/detail/CVE-2026-40923) | **tektoncd/pipeline** | Validation bypass | Medium | 2026-04-21 |
| [GHSA-94jr-7pqp-xhcq](https://github.com/advisories/GHSA-94jr-7pqp-xhcq) | [CVE-2026-40938](https://nvd.nist.gov/vuln/detail/CVE-2026-40938) | **tektoncd/pipeline** | Logic flaw | High | 2026-04-21 |
| [GHSA-4jjr-vmv7-wh4w](https://github.com/advisories/GHSA-4jjr-vmv7-wh4w) | [CVE-2026-41175](https://nvd.nist.gov/vuln/detail/CVE-2026-41175) | **statamic/cms** | Unsafe method invocation | High | 2026-04-16 |
| [GHSA-c5c4-8r6x-56w3](https://github.com/advisories/GHSA-c5c4-8r6x-56w3) | [CVE-2026-40574](https://nvd.nist.gov/vuln/detail/CVE-2026-40574) | **oauth2-proxy/oauth2-proxy** | Authorization bypass | Medium | 2026-04-15 |
| [GHSA-gqw4-4w2p-838q](https://github.com/advisories/GHSA-gqw4-4w2p-838q) | [CVE-2026-40261](https://nvd.nist.gov/vuln/detail/CVE-2026-40261) | **composer/composer** | Command injection | High | 2026-04-14 |
| [GHSA-4x48-cgf9-q33f](https://github.com/advisories/GHSA-4x48-cgf9-q33f) | — | **novuhq/novu** | SSRF | High | 2026-04-14 |
| [GHSA-r2pg-r6h7-crf3](https://github.com/advisories/GHSA-r2pg-r6h7-crf3) | [CVE-2026-34984](https://nvd.nist.gov/vuln/detail/CVE-2026-34984) | **external-secrets/external-secrets** | Data exfiltration | High | 2026-04-13 |
| [GHSA-w95v-4h65-j455](https://github.com/advisories/GHSA-w95v-4h65-j455) | [CVE-2026-40107](https://nvd.nist.gov/vuln/detail/CVE-2026-40107) | **siyuan-note/siyuan** | SSRF | High | 2026-04-10 |
| [GHSA-r854-jrxh-36qx](https://github.com/advisories/GHSA-r854-jrxh-36qx) | [CVE-2026-40194](https://nvd.nist.gov/vuln/detail/CVE-2026-40194) | **phpseclib/phpseclib** | Timing side-channel | Low | 2026-04-10 |
| [GHSA-5f5r-95pg-xrpm](https://github.com/advisories/GHSA-5f5r-95pg-xrpm) | [CVE-2026-40077](https://nvd.nist.gov/vuln/detail/CVE-2026-40077) | **henrygd/beszel** | IDOR | Low | 2026-04-10 |
| [GHSA-3crg-w4f6-42mx](https://github.com/advisories/GHSA-3crg-w4f6-42mx) | [CVE-2026-40260](https://nvd.nist.gov/vuln/detail/CVE-2026-40260) | **py-pdf/pypdf** | Resource exhaustion | Medium | 2026-04-10 |
| [GHSA-w6c6-c85g-mmv6](https://github.com/advisories/GHSA-w6c6-c85g-mmv6) | [CVE-2026-39395](https://nvd.nist.gov/vuln/detail/CVE-2026-39395) | **sigstore/cosign** | Verification bypass | Medium | 2026-04-08 |
| [GHSA-v9w4-gm2x-6rvf](https://github.com/advisories/GHSA-v9w4-gm2x-6rvf) | [CVE-2026-35604](https://nvd.nist.gov/vuln/detail/CVE-2026-35604) | **filebrowser/filebrowser** | Permission inheritance | High | 2026-04-08 |
| [GHSA-hfvc-g4fc-pqhx](https://github.com/advisories/GHSA-hfvc-g4fc-pqhx) | [CVE-2026-39883](https://nvd.nist.gov/vuln/detail/CVE-2026-39883) | **open-telemetry/opentelemetry-go** | Logic flaw | High | 2026-04-08 |
| [GHSA-7526-j432-6ppp](https://github.com/advisories/GHSA-7526-j432-6ppp) | [CVE-2026-35607](https://nvd.nist.gov/vuln/detail/CVE-2026-35607) | **filebrowser/filebrowser** | Permission inheritance | High | 2026-04-08 |
| [GHSA-67cg-cpj7-qgc9](https://github.com/advisories/GHSA-67cg-cpj7-qgc9) | [CVE-2026-35606](https://nvd.nist.gov/vuln/detail/CVE-2026-35606) | **filebrowser/filebrowser** | Information disclosure | Medium | 2026-04-08 |
| [GHSA-5q48-q4fm-g3m6](https://github.com/advisories/GHSA-5q48-q4fm-g3m6) | [CVE-2026-35605](https://nvd.nist.gov/vuln/detail/CVE-2026-35605) | **filebrowser/filebrowser** | Access control bypass | Medium | 2026-04-08 |
| [GHSA-qmwh-9m9c-h36m](https://github.com/advisories/GHSA-qmwh-9m9c-h36m) | — | **gotenberg/gotenberg** | Policy subversion | High | 2026-04-07 |
| [GHSA-x3f4-v83f-7wp2](https://github.com/advisories/GHSA-x3f4-v83f-7wp2) | — | **authorizerdev/authorizer** | Missing authorization | High | 2026-04-06 |
| [GHSA-7gvf-3w72-p2pg](https://github.com/advisories/GHSA-7gvf-3w72-p2pg) | [CVE-2026-35459](https://nvd.nist.gov/vuln/detail/CVE-2026-35459) | **pyload/pyload** | SSRF | Critical | 2026-04-04 |
| [GHSA-4744-96p5-mp2j](https://github.com/advisories/GHSA-4744-96p5-mp2j) | [CVE-2026-35464](https://nvd.nist.gov/vuln/detail/CVE-2026-35464) | **pyload/pyload** | Arbitrary file write | High | 2026-04-04 |
| [GHSA-fgv4-6jr3-jgfw](https://github.com/advisories/GHSA-fgv4-6jr3-jgfw) | [CVE-2026-35043](https://nvd.nist.gov/vuln/detail/CVE-2026-35043) | **bentoml/BentoML** | Command injection | High | 2026-04-03 |
| [GHSA-p5rh-vmhp-gvcw](https://github.com/advisories/GHSA-p5rh-vmhp-gvcw) | [CVE-2026-34976](https://nvd.nist.gov/vuln/detail/CVE-2026-34976) | **dgraph-io/dgraph** | SSRF | Critical | 2026-04-02 |
| [GHSA-x3ff-w252-2g7j](https://github.com/advisories/GHSA-x3ff-w252-2g7j) | — | **StableLib/stablelib** | Signature malleability | Medium | 2026-04-01 |
| [GHSA-frv4-x25r-588m](https://github.com/advisories/GHSA-frv4-x25r-588m) | [CVE-2026-34172](https://nvd.nist.gov/vuln/detail/CVE-2026-34172) | **Giskard-AI/giskard-oss** | Template injection | High | 2026-03-27 |
| [GHSA-f359-r3pv-2phf](https://github.com/advisories/GHSA-f359-r3pv-2phf) | [CVE-2026-33766](https://nvd.nist.gov/vuln/detail/CVE-2026-33766) | **WWBN/AVideo** | SSRF | Medium | 2026-03-26 |

Severity as published in each advisory.
Machine-readable: [advisories.csv](advisories.csv)

---

[kodareef5@gmail.com](mailto:kodareef5@gmail.com) · [@kodareef5](https://github.com/kodareef5)
