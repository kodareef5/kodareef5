<div align="center">

# Koda Reef

**Systematic vulnerability research. Custom tooling, manually verified findings.**

![advisories](https://img.shields.io/badge/advisories-50-8b0000?style=flat-square)
![organizations](https://img.shields.io/badge/organizations-39-8b0000?style=flat-square)
![CVEs](https://img.shields.io/badge/CVEs-41-8b0000?style=flat-square)
![sole reporter](https://img.shields.io/badge/sole_reporter-38-8b0000?style=flat-square)
![high or critical](https://img.shields.io/badge/high_or_critical-30-8b0000?style=flat-square)

</div>

Independently indexed, February 2026 to present.

**43** are searchable in GitHub's global advisory database:
[all](https://github.com/advisories?query=credit%3Akodareef5) ·
[critical](https://github.com/advisories?query=credit%3Akodareef5+severity%3Acritical) ·
[high](https://github.com/advisories?query=credit%3Akodareef5+severity%3Ahigh).
**7 more** are repository advisories that carry a CVE but were never
published to that database, so the search does not reach them. Each is
linked individually in the table below.

**Positive Technologies** indexes the record independently and ranks it
[**#1,066 of 54,969** researchers](https://dbugs.ptsecurity.com/researchers/Kodareef5),
202.2 total CVSS.

### Credited in

[![Traefik](https://img.shields.io/badge/Traefik-24A1C1?style=for-the-badge&logo=traefikproxy&logoColor=white)](https://github.com/advisories/GHSA-6x2q-h3cr-8j2h)
[![Cilium](https://img.shields.io/badge/Cilium-F8C517?style=for-the-badge&logo=cilium&logoColor=black)](https://github.com/advisories/GHSA-gj49-89wh-h4gj)
[![Rancher](https://img.shields.io/badge/Rancher-0075A8?style=for-the-badge&logo=rancher&logoColor=white)](https://github.com/advisories/GHSA-765j-qfrp-hm3j)
[![Composer](https://img.shields.io/badge/Composer-885630?style=for-the-badge&logo=composer&logoColor=white)](https://github.com/advisories/GHSA-gqw4-4w2p-838q)
[![Sigstore](https://img.shields.io/badge/Sigstore-003366?style=for-the-badge&logo=sigstore&logoColor=white)](https://github.com/advisories/GHSA-w6c6-c85g-mmv6)
[![Tekton](https://img.shields.io/badge/Tekton-42A5F5?style=for-the-badge&logo=tekton&logoColor=white)](https://github.com/advisories/GHSA-94jr-7pqp-xhcq)
[![OpenTelemetry](https://img.shields.io/badge/OpenTelemetry-425CC7?style=for-the-badge&logo=opentelemetry&logoColor=white)](https://github.com/advisories/GHSA-hfvc-g4fc-pqhx)
[![ZITADEL](https://img.shields.io/badge/ZITADEL-3AB8BF?style=for-the-badge)](https://github.com/advisories/GHSA-xqxv-4jc2-x56x)
[![Kata Containers](https://img.shields.io/badge/Kata_Containers-1E2761?style=for-the-badge)](https://github.com/advisories/GHSA-q49m-57vm-c8cc)
[![Dgraph](https://img.shields.io/badge/Dgraph-E50695?style=for-the-badge)](https://github.com/advisories/GHSA-p5rh-vmhp-gvcw)
[![DOMPurify](https://img.shields.io/badge/DOMPurify-CC0000?style=for-the-badge)](https://github.com/advisories/GHSA-h7mw-gpvr-xq4m)
[![Poetry](https://img.shields.io/badge/Poetry-60A5FA?style=for-the-badge&logo=poetry&logoColor=white)](https://github.com/advisories/GHSA-73h3-mf4w-8647)
[![Astro](https://img.shields.io/badge/Astro-BC52EE?style=for-the-badge&logo=astro&logoColor=white)](https://github.com/advisories/GHSA-88gm-j2wx-58h6)
[![go-git](https://img.shields.io/badge/go--git-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://github.com/advisories/GHSA-w5pp-99ch-qj29)
[![gitoxide](https://img.shields.io/badge/gitoxide-CE422B?style=for-the-badge&logo=rust&logoColor=white)](https://github.com/advisories/GHSA-p3hw-mv63-rf9w)
[![BentoML](https://img.shields.io/badge/BentoML-000000?style=for-the-badge)](https://github.com/advisories/GHSA-fgv4-6jr3-jgfw)
[![python-tuf](https://img.shields.io/badge/python--tuf-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://github.com/advisories/GHSA-qp9x-wp8f-qgjj)
[![External Secrets](https://img.shields.io/badge/External_Secrets-326CE5?style=for-the-badge&logo=kubernetes&logoColor=white)](https://github.com/advisories/GHSA-r2pg-r6h7-crf3)
[![OneUptime](https://img.shields.io/badge/OneUptime-000000?style=for-the-badge)](https://github.com/OneUptime/oneuptime/security/advisories/GHSA-6wc5-rhvj-cx7f)
[![NATS](https://img.shields.io/badge/NATS-27AAE1?style=for-the-badge&logo=natsdotio&logoColor=white)](https://github.com/nats-io/nats-server/security/advisories/GHSA-3g5q-cfh2-cq67)
[![Coolify](https://img.shields.io/badge/Coolify-8B5CF6?style=for-the-badge)](https://github.com/coollabsio/coolify/security/advisories/GHSA-mh8x-fppq-cp77)
[![authentik](https://img.shields.io/badge/authentik-FD4B2D?style=for-the-badge&logo=authentik&logoColor=white)](https://github.com/goauthentik/authentik/security/advisories/GHSA-4v4x-x5pr-8gp2)

Every badge links to a published advisory. Twenty-two of thirty-nine
organizations. The [full list](#advisories) is below.

### Upstream, outside the advisory system

Work that produced a fix or an acknowledgement but no advisory. Verified
2026-07-26; every row links to the primary source.

**Patches I wrote that were merged**

| Project | What | Credit |
|---|---|---|
| [Apache HTTP Server](https://github.com/apache/httpd/commit/d11e440) | Integer overflow guards in four core escaping functions | *"Submitted by: Koda Reef"* |
| [c-ares](https://github.com/c-ares/c-ares/pull/1094) | Overflow checks in `ares_buf_ensure_space()` | Merged, [downstream in Node.js](https://github.com/nodejs/node/blob/main/deps/cares/RELEASE-NOTES.md) |
| [protoc-gen-validate](https://github.com/bufbuild/protoc-gen-validate/pull/1379) | Malformed UTF-8 undercounted, bypassing length constraints | Merged |
| [DOMPurify](https://github.com/cure53/DOMPurify/pull/1230) | The fix for my own [CVE-2026-41240](https://github.com/advisories/GHSA-h7mw-gpvr-xq4m) | Merged |
| [File Browser](https://github.com/filebrowser/filebrowser/pulls?q=is%3Apr+author%3Akodareef5) | The fixes for all four of my own File Browser advisories | 4 merged |

**Credited in someone else's fix**

| Project | What | Credit |
|---|---|---|
| [jsrsasign](https://github.com/kjur/jsrsasign/releases) 11.1.2 | **HIGH**, DSA universal signature forgery, FIPS 186-4 §4.7 boundary check | *reported by Koda Reef, Nicholas Carlini and @Kr0emer* |
| [jsrsasign](https://github.com/kjur/jsrsasign/releases) 11.1.2 | **HIGH**, ASN.1 parser infinite loop in `getChildIdx` | *reported by Koda Reef*, sole |
| [nginx](https://nginx.org/en/CHANGES) 1.31.2 | Constant time `secure_link` hash comparison | *"Thanks to kodareef5"* |
| [GNOME GLib](https://github.com/GNOME/glib/commit/578a488) | D-Bus message length integer arithmetic | *"Based on a report by Koda Reef"* |
| [CloudNativePG](https://github.com/cloudnative-pg/cloudnative-pg/commit/d65da47) | Escaping in PostgreSQL config values | *"Reported-by: Koda Reef"* |
| [CloudNativePG](https://github.com/cloudnative-pg/cloudnative-pg/commit/caf2077) | Tightened recovery target validation | *"Suggested-by: Koda Reef"* |
| [lighttpd](https://github.com/lighttpd/lighttpd1.4/commit/904a267) | `mod_maxminddb` snprintf return bound | *"(thx kodareef5)"* |
| [Headlamp](https://github.com/kubernetes-sigs/headlamp/releases/tag/v0.42.0) v0.42.0 | Host header validation | *"thanks to Koda Reef for reporting"* |
| [NATS Server](https://github.com/nats-io/nats-server/releases) 2.14.3 | Non-CVE fixes in the same release | Named in contributors |
| [vim](https://github.com/vim/vim/commit/3c0f800) | Buffer underflow in `vim_fgets()` | v9.2.0271 and v9.2.0272 |
| [libjpeg-turbo](https://github.com/libjpeg-turbo/libjpeg-turbo/issues/877) | Signed overflow in JNI array size across six paths | Fixed |
| [libevent](https://github.com/libevent/libevent/blob/master/ChangeLog) | HTTP header parsing restricted against request smuggling | Release notes |
| [libzip](https://github.com/nih-at/libzip/blob/main/THANKS) | | THANKS |
| [simple-git](https://github.com/steveukx/git-js/blob/main/simple-git/CHANGELOG.md) | `GIT_CONFIG_COUNT` injection | Changelog |
| [authentik](https://docs.goauthentik.io/security/cves/CVE-2026-40165) | SAML NameID truncation | Vendor CVE page |
| [Red Hat](https://access.redhat.com/security/cve/CVE-2026-40938) | Five errata across OpenShift product lines | Downstream |

One advisory credits me in prose but not in metadata:
[go-git `GHSA-crhj-59gh-8x96`](https://github.com/go-git/go-git/security/advisories/GHSA-crhj-59gh-8x96)
reads *"Thanks to @kodareef5, @AyushParkara and @N0zoM1z0 for reporting this to
the go-git project in three separate reports."* The structured credits list
the other two. It is not counted in the 50.

### Selected findings

<table>
<tr>
<td width="50%">

**Dgraph** · [CVE-2026-34976](https://nvd.nist.gov/vuln/detail/CVE-2026-34976)
`CRITICAL 10.0`

`restoreTenant` was absent from the middleware config map while its
neighbour `restore` had full coverage, so it ran with no authentication,
no IP allowlist and no audit logging. Chained to database overwrite, SSRF
and file read pre-auth, no credentials needed. The fix was one line.
[Press](https://gbhackers.com/critical-dgraph-database-flaw/).

</td>
<td width="50%">

**Rancher Fleet** · [CVE-2026-41050](https://nvd.nist.gov/vuln/detail/CVE-2026-41050)
`CRITICAL 9.9`

Two Helm execution paths kept `cluster-admin` credentials during
impersonated operations: the `lookup` template function, and `valuesFrom`
secret references read through the same client. Patched across five
Rancher trains.

</td>
</tr>
<tr>
<td width="50%">

**Cilium** · [CVE-2026-41520](https://nvd.nist.gov/vuln/detail/CVE-2026-41520)
`HIGH 7.9`

`cilium-bugtool` and sysdump archives carried the WireGuard node key out
of the cluster. The key is static and never rotates, so an archived
support bundle decrypts node traffic and permits node impersonation until
someone rotates it by hand.

</td>
<td width="50%">

**Traefik** · [CVE-2026-41263](https://github.com/advisories/GHSA-6x2q-h3cr-8j2h)
`PATCH BYPASS`

A BasicAuth timing fix had already shipped. The patch looked up a bcrypt
hash as if it were a username, so the constant-time fallback secret was
always empty and password checks failed in microseconds instead of running
bcrypt. Reported path closed; class not. Measured at 130x against the
shipped binary.

</td>
</tr>
<tr>
<td width="50%">

**nginx** · [1.31.2](https://nginx.org/en/CHANGES) `UPSTREAM CREDIT`

The `secure_link` module compared its security hash without constant-time
semantics. Fixed upstream and credited by name in the official changelog:

> *"constant time `secure_link` hash comparison. Thanks to kodareef5."*

</td>
<td width="50%">

**Composer** · [CVE-2026-40261](https://github.com/advisories/GHSA-gqw4-4w2p-838q)
`HIGH 8.8`

Command injection through the Perforce source handler, reachable from
package metadata, so the untrusted input is the package itself, which is
the whole trust model of a dependency manager. Sole reporter. Red Hat
shipped [errata](https://access.redhat.com/security/cve/CVE-2026-40261).

</td>
</tr>
<tr>
<td width="50%">

**OneUptime** · [CVE-2026-34759](https://github.com/OneUptime/oneuptime/security/advisories/GHSA-6wc5-rhvj-cx7f)
`CRITICAL 9.2`

Notification API endpoints were registered without auth middleware while
every neighbouring endpoint had it. An unauthenticated caller could buy phone
numbers on the victim's Twilio account, delete existing alert numbers, and
reach SMTP credentials. A `projectId` leaking from the public status-page API
made it reachable from nothing. Sole reporter.

</td>
<td width="50%">

**NATS Server** · three advisories `ALL INCOMPLETE FIXES`

One batch, three advisories, each titled by the maintainers as an incomplete
fix for an earlier CVE.
[Leafnode handshake crash](https://github.com/nats-io/nats-server/security/advisories/GHSA-3g5q-cfh2-cq67)
(High 8.6) survived **two** prior fixes, CVE-2026-29785 and CVE-2026-33218.
[MQTT ACL bypass](https://github.com/nats-io/nats-server/security/advisories/GHSA-4g68-3pwx-5vfj)
and
[trace-permission bypass](https://github.com/nats-io/nats-server/security/advisories/GHSA-p3j5-5hrq-p75h)
each survived one. Sole reporter on all three.

</td>
</tr>
</table>

### The data

**Severity**, as published in each advisory

| Critical | High | Medium | Low |
|:--:|:--:|:--:|:--:|
| 4 | 26 | 16 | 4 |
| `████` | `██████████████████████████` | `████████████████` | `████` |

**Ecosystem**

| Go | Python | PHP | JavaScript | Rust |
|:--:|:--:|:--:|:--:|:--:|
| 27 | 8 | 6 | 5 | 4 |
| `███████████████████████████` | `████████` | `██████` | `█████` | `████` |

**Most common classes.** SSRF ×7 · then six classes at three each: denial of
service, authorization bypass, command injection, logic flaws, validation
bypass, missing authorization, information disclosure. Then a tail of two:
path traversal, policy subversion, timing side-channels, permission
inheritance.

### Fixes that did not hold

Ten cases where a patch had already shipped and the bug class survived it.
The BentoML advisory is titled *"Incomplete fix for CVE-2026-33744"*, the
maintainers' own words, not mine.

| | |
|---|---|
| [BentoML](https://github.com/advisories/GHSA-fgv4-6jr3-jgfw) | advisory titled *"Incomplete fix for CVE-2026-33744"* |
| [Gotenberg](https://github.com/advisories/GHSA-qmwh-9m9c-h36m) | incomplete fix for an ExifTool arbitrary file write |
| NATS Server | three advisories, all incomplete fixes to one earlier batch |
| Merkle proof verifier | a prior audit's remediation shipped in one language binding only; the other still carried the flaw |
| ClearML | incomplete fix for CVE-2024-24591 |
| PyTorch Lightning | `_instantiator` bypass, then an incomplete fix for that bypass |
| dtale | incomplete fix for CVE-2026-27194 |
| [NATS Server](https://github.com/nats-io/nats-server/security/advisories/GHSA-3g5q-cfh2-cq67) | leafnode handshake crash, incomplete fix for **two** CVEs at once |
| [NATS Server](https://github.com/nats-io/nats-server/security/advisories/GHSA-4g68-3pwx-5vfj) | MQTT subscribe ACL bypass, incomplete fix for CVE-2026-33217 |
| [NATS Server](https://github.com/nats-io/nats-server/security/advisories/GHSA-p3j5-5hrq-p75h) | trace-destination permission bypass, incomplete fix for CVE-2026-33249 |

### Coverage by class

| | |
|---|---|
| **Cryptography** | [Ed25519 signature malleability](https://github.com/advisories/GHSA-x3ff-w252-2g7j) · [variable-time HMAC](https://github.com/advisories/GHSA-r854-jrxh-36qx) · [`secure_link` timing](https://nginx.org/en/CHANGES) · identity-point proof acceptance in zero-knowledge verifiers · PRF state leak reversing proactive key refresh · cross-language proof-verification divergence · missing curve validation in MPC blob deserializers |
| **Identity and trust** | [OIDC client binding](https://github.com/advisories/GHSA-xqxv-4jc2-x56x) · [attestation verification](https://github.com/advisories/GHSA-w6c6-c85g-mmv6) · [`FORBID_TAGS` bypass](https://github.com/advisories/GHSA-h7mw-gpvr-xq4m) · [SAML NameID truncation](https://docs.goauthentik.io/security/cves/CVE-2026-40165) · [delegation matching](https://github.com/advisories/GHSA-qp9x-wp8f-qgjj) · [email domain bypass](https://github.com/advisories/GHSA-c5c4-8r6x-56w3) · [password reset token theft](https://github.com/advisories/GHSA-x3f4-v83f-7wp2) |
| **Platform and isolation** | [Helm impersonation bypass](https://github.com/advisories/GHSA-765j-qfrp-hm3j) · [symlink policy subversion](https://github.com/advisories/GHSA-q49m-57vm-c8cc) · [WireGuard key exposure](https://github.com/advisories/GHSA-gj49-89wh-h4gj) · [Lua injection](https://github.com/advisories/GHSA-x4mj-7f9g-29h4) · [DNS secret exfiltration](https://github.com/advisories/GHSA-r2pg-r6h7-crf3) · virtio-net TOCTOU ([Firecracker](https://github.com/firecracker-microvm/firecracker)) · reverse-proxy path canonicalization and hop-by-hop header forwarding |
| **AI and ML** | [command injection](https://github.com/advisories/GHSA-fgv4-6jr3-jgfw) · [template injection](https://github.com/advisories/GHSA-frv4-x25r-588m) · pickle deserialization and sandbox escape across ONNX, MLflow, PyTorch Lightning, Keras, Triton · [PoCs](https://huggingface.co/kodareef5) |
| **Supply chain** | [Perforce command injection](https://github.com/advisories/GHSA-gqw4-4w2p-838q) · [submodule validation](https://github.com/advisories/GHSA-p3hw-mv63-rf9w) · [tar path traversal](https://github.com/advisories/GHSA-73h3-mf4w-8647) · [`GIT_CONFIG_COUNT` injection](https://github.com/steveukx/git-js/blob/main/simple-git/CHANGELOG.md) |
| **Edge and proxy** | [BasicAuth timing oracle](https://github.com/advisories/GHSA-6x2q-h3cr-8j2h) · [email domain bypass](https://github.com/advisories/GHSA-c5c4-8r6x-56w3) · [collector auth bypass](https://github.com/advisories/GHSA-w5cv-pw74-4rxc) · reverse-proxy path canonicalization and hop-by-hop header forwarding |

### Confirmations during coordinated disclosure

Named engineers at the affected organizations, by direct email. Technical
confirmations of a finding, not endorsements and not customer references.

| | |
|---|---|
| *"We validated that the TOCTOU condition you described exists in Firecracker's codebase"* | **AWS Security** |
| *"We've confirmed the vulnerability, the analysis is accurate"* | **Red Hat**, Tekton maintainer |
| *"I have reproduced the issue and can confirm the Lua injection vulnerability"* | **Contour** maintainer |
| *"I can confirm this is a real vulnerability"* | **oauth2-proxy** maintainer |
| *"I can confirm reception and have created an advisory"* | **Composer**, Jordi Boggiano |
| *"On the parser-level finding: your observation is correct"* | **CloudNativePG**, EnterpriseDB |
| *"We will credit you in the advisory and inform when it's public"* | **SUSE** Rancher security |

Press: [GBHackers](https://gbhackers.com/critical-dgraph-database-flaw/) ·
[Cybersecurity News](https://cybersecuritynews.com/dgraph-database-vulnerability/)
on the Dgraph 10.0.

### Advisories

Plus **[CVE-2026-5366](https://www.cve.org/CVERecord?id=CVE-2026-5366)**.
Critical, git argument injection in Prefect deployment pull steps via an
unsanitized `commit_sha`, across four injection points. Reported and
CVE-assigned through
[huntr](https://huntr.com/bounties/e2e88a0f-a8f6-49c9-94c5-e98dc385f07a);
[fixed upstream](https://github.com/PrefectHQ/prefect/commit/6a9d9918716ce4ee0297b69f3046f7067ef1faae).
Not among the 50 below, which are advisory credits only. A second Critical,
[CVE-2026-42048](https://nvd.nist.gov/vuln/detail/CVE-2026-42048), is
awaiting a credit correction and is also not counted.

| Advisory | CVE | Project | Class | Severity | Published |
| --- | --- | --- | --- | --- | --- |
| [GHSA-3g5q-cfh2-cq67](https://github.com/nats-io/nats-server/security/advisories/GHSA-3g5q-cfh2-cq67) | [CVE-2026-58250](https://www.cve.org/CVERecord?id=CVE-2026-58250) | **nats-io/nats-server** | Denial of service | High | 2026-07-08 |
| [GHSA-p3j5-5hrq-p75h](https://github.com/nats-io/nats-server/security/advisories/GHSA-p3j5-5hrq-p75h) | [CVE-2026-58254](https://www.cve.org/CVERecord?id=CVE-2026-58254) | **nats-io/nats-server** | Authorization bypass | Medium | 2026-07-08 |
| [GHSA-4g68-3pwx-5vfj](https://github.com/nats-io/nats-server/security/advisories/GHSA-4g68-3pwx-5vfj) | [CVE-2026-58214](https://www.cve.org/CVERecord?id=CVE-2026-58214) | **nats-io/nats-server** | Authorization bypass | Medium | 2026-07-08 |
| [GHSA-mh8x-fppq-cp77](https://github.com/coollabsio/coolify/security/advisories/GHSA-mh8x-fppq-cp77) | [CVE-2026-34168](https://www.cve.org/CVERecord?id=CVE-2026-34168) | **coollabsio/coolify** | Command injection | High | 2026-07-07 |
| [GHSA-xqxv-4jc2-x56x](https://github.com/advisories/GHSA-xqxv-4jc2-x56x) | [CVE-2026-55672](https://nvd.nist.gov/vuln/detail/CVE-2026-55672) | **zitadel/zitadel** | Missing identity binding | High | 2026-06-18 |
| [GHSA-w5cv-pw74-4rxc](https://github.com/advisories/GHSA-w5cv-pw74-4rxc) | [CVE-2026-55701](https://nvd.nist.gov/vuln/detail/CVE-2026-55701) | **open-telemetry/opentelemetry-collector-contrib** | Logic flaw | Medium | 2026-06-18 |
| [GHSA-4v4x-x5pr-8gp2](https://github.com/goauthentik/authentik/security/advisories/GHSA-4v4x-x5pr-8gp2) | [CVE-2026-41577](https://www.cve.org/CVERecord?id=CVE-2026-41577) | **goauthentik/authentik** | Validation bypass | Medium | 2026-06-02 |
| [GHSA-w5pp-99ch-qj29](https://github.com/advisories/GHSA-w5pp-99ch-qj29) | None | **go-git/go-git** | Denial of service | Medium | 2026-05-29 |
| [GHSA-qp9x-wp8f-qgjj](https://github.com/advisories/GHSA-qp9x-wp8f-qgjj) | None | **theupdateframework/python-tuf** | Delegation confusion | Medium | 2026-05-28 |
| [GHSA-765j-qfrp-hm3j](https://github.com/advisories/GHSA-765j-qfrp-hm3j) | [CVE-2026-41050](https://nvd.nist.gov/vuln/detail/CVE-2026-41050) | **rancher/fleet** | Impersonation bypass | Critical | 2026-05-07 |
| [GHSA-x494-mj8g-cj27](https://github.com/advisories/GHSA-x494-mj8g-cj27) | None | **GitoxideLabs/gitoxide** | Denial of service | High | 2026-05-05 |
| [GHSA-p3hw-mv63-rf9w](https://github.com/advisories/GHSA-p3hw-mv63-rf9w) | None | **GitoxideLabs/gitoxide** | Path traversal | High | 2026-05-05 |
| [GHSA-mm2q-qcmx-gw4w](https://github.com/advisories/GHSA-mm2q-qcmx-gw4w) | None | **rustfs/rustfs** | Missing authorization | High | 2026-05-05 |
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
| [GHSA-4x48-cgf9-q33f](https://github.com/advisories/GHSA-4x48-cgf9-q33f) | None | **novuhq/novu** | SSRF | High | 2026-04-14 |
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
| [GHSA-qmwh-9m9c-h36m](https://github.com/advisories/GHSA-qmwh-9m9c-h36m) | None | **gotenberg/gotenberg** | Policy subversion | High | 2026-04-07 |
| [GHSA-x3f4-v83f-7wp2](https://github.com/advisories/GHSA-x3f4-v83f-7wp2) | None | **authorizerdev/authorizer** | Missing authorization | High | 2026-04-06 |
| [GHSA-7gvf-3w72-p2pg](https://github.com/advisories/GHSA-7gvf-3w72-p2pg) | [CVE-2026-35459](https://nvd.nist.gov/vuln/detail/CVE-2026-35459) | **pyload/pyload** | SSRF | Critical | 2026-04-04 |
| [GHSA-4744-96p5-mp2j](https://github.com/advisories/GHSA-4744-96p5-mp2j) | [CVE-2026-35464](https://nvd.nist.gov/vuln/detail/CVE-2026-35464) | **pyload/pyload** | Arbitrary file write | High | 2026-04-04 |
| [GHSA-fgv4-6jr3-jgfw](https://github.com/advisories/GHSA-fgv4-6jr3-jgfw) | [CVE-2026-35043](https://nvd.nist.gov/vuln/detail/CVE-2026-35043) | **bentoml/BentoML** | Command injection | High | 2026-04-03 |
| [GHSA-p5rh-vmhp-gvcw](https://github.com/advisories/GHSA-p5rh-vmhp-gvcw) | [CVE-2026-34976](https://nvd.nist.gov/vuln/detail/CVE-2026-34976) | **dgraph-io/dgraph** | SSRF | Critical | 2026-04-02 |
| [GHSA-6wc5-rhvj-cx7f](https://github.com/OneUptime/oneuptime/security/advisories/GHSA-6wc5-rhvj-cx7f) | [CVE-2026-34759](https://www.cve.org/CVERecord?id=CVE-2026-34759) | **OneUptime/oneuptime** | Missing authentication | Critical | 2026-04-02 |
| [GHSA-x3ff-w252-2g7j](https://github.com/advisories/GHSA-x3ff-w252-2g7j) | None | **StableLib/stablelib** | Signature malleability | Medium | 2026-04-01 |
| [GHSA-c9v3-4c59-x5q2](https://github.com/freescout-help-desk/freescout/security/advisories/GHSA-c9v3-4c59-x5q2) | [CVE-2026-34443](https://www.cve.org/CVERecord?id=CVE-2026-34443) | **freescout-help-desk/freescout** | SSRF | High | 2026-03-31 |
| [GHSA-frv4-x25r-588m](https://github.com/advisories/GHSA-frv4-x25r-588m) | [CVE-2026-34172](https://nvd.nist.gov/vuln/detail/CVE-2026-34172) | **Giskard-AI/giskard-oss** | Template injection | High | 2026-03-27 |
| [GHSA-f359-r3pv-2phf](https://github.com/advisories/GHSA-f359-r3pv-2phf) | [CVE-2026-33766](https://nvd.nist.gov/vuln/detail/CVE-2026-33766) | **WWBN/AVideo** | SSRF | Medium | 2026-03-26 |

Machine-readable: [advisories.csv](advisories.csv)

<div align="center">

**137 repositories reviewed · 39 organizations · 34 security contacts · 7 vendor confirmations · 21 findings awaiting triage**

[kodareef5@gmail.com](mailto:kodareef5@gmail.com) · [@kodareef5](https://github.com/kodareef5)

</div>
