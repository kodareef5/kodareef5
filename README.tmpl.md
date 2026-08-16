<div align="center">

# Koda Reef

**Systematic vulnerability research. Custom tooling, manually verified findings.**

{{STAT_BADGES}}

</div>

Published record, March 2026 to present.

{{GLOBAL_N}} are searchable in GitHub's global advisory database:
[all](https://github.com/advisories?query=credit%3Akodareef5) ·
[critical](https://github.com/advisories?query=credit%3Akodareef5+severity%3Acritical) ·
[high](https://github.com/advisories?query=credit%3Akodareef5+severity%3Ahigh).
{{REPO_N}} more are repository advisories that were never
published to that database, so the search does not reach them. Each is
linked individually in the table below.

### Credited in

{{ORG_BADGES}}

### Upstream, outside the advisory system

| Project | What | Credit |
|---|---|---|
| [Apache HTTP Server](https://github.com/apache/httpd/commit/d11e440) | Integer overflow guards in four core escaping functions | *"Submitted by: Koda Reef"* |
| [c-ares](https://github.com/c-ares/c-ares/pull/1094) | Overflow checks in `ares_buf_ensure_space()` | Merged, [downstream in Node.js](https://github.com/nodejs/node/blob/main/deps/cares/RELEASE-NOTES.md) |
| [protoc-gen-validate](https://github.com/bufbuild/protoc-gen-validate/pull/1379) | Malformed UTF-8 undercounted, bypassing length constraints | Merged |
| [DOMPurify](https://github.com/cure53/DOMPurify/pull/1230) | Fix for [CVE-2026-41240](https://github.com/advisories/GHSA-h7mw-gpvr-xq4m) | Merged |
| [File Browser #5888](https://github.com/filebrowser/filebrowser/pull/5888) | Share owner permissions checked on public share access | Merged |
| [File Browser #5889](https://github.com/filebrowser/filebrowser/pull/5889) | Directory boundary enforced in rule path matching | Merged |
| [File Browser #5890](https://github.com/filebrowser/filebrowser/pull/5890) | Default permissions restricted for proxy-auth auto-provisioned users | Merged |
| [File Browser #5891](https://github.com/filebrowser/filebrowser/pull/5891) | Download permission checked in the resource handler | Merged |
| [bitbang-cli #10](https://github.com/richlegrand/bitbang-cli/pull/10) | `GO-2026-5942` reachable from the mDNS resolver, not just present in the module graph — a malformed `.local` responder panics the CLI | Merged |

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
| [vim](https://github.com/vim/vim/commit/3c0f800) | Buffer underflow in `vim_fgets()` | *"Solution: Ensure size is always greater than 1 (Koda Reef)"*, v9.2.0271 |
| [libevent](https://github.com/libevent/libevent/blob/master/ChangeLog) | HTTP header parsing restricted against request smuggling | Release notes |
| [libzip](https://github.com/nih-at/libzip/blob/main/THANKS) | | THANKS |
| [simple-git](https://github.com/steveukx/git-js/blob/main/simple-git/CHANGELOG.md) | `GIT_CONFIG_COUNT` injection | Changelog |
| [authentik](https://docs.goauthentik.io/security/cves/CVE-2026-40165) | SAML NameID truncation | Vendor CVE page |
| [Red Hat](https://access.redhat.com/security/cve/CVE-2026-40938) | Five errata across OpenShift product lines | Downstream |

[libjpeg-turbo #877](https://github.com/libjpeg-turbo/libjpeg-turbo/issues/877)
sits outside both tables. The signed-overflow diagnosis was reported there and
the maintainer wrote the fix across three commits, each closing with
`Fixes #877` — provenance by linkage, with no named credit.

One advisory carries the credit in prose but not in metadata:
[go-git `GHSA-crhj-59gh-8x96`](https://github.com/go-git/go-git/security/advisories/GHSA-crhj-59gh-8x96)
(CVE-2026-45571)
reads *"Thanks to @kodareef5, @AyushParkara and @N0zoM1z0 for reporting this to
the go-git project in three separate reports."* The structured credits list
the other two. It is not counted in the {{TOTAL}}.

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

**in-toto / witness** · [GHSA-ggg4-v8vp-jxqh](https://github.com/in-toto/witness/security/advisories/GHSA-ggg4-v8vp-jxqh)
`CRITICAL`

`initConfig` auto-loads `.witness.yaml` from the working directory before
every command, so a file committed to the repository can redirect
`archivista-server` and clear `env-disable-default-sensitive-vars`. An
untrusted pull request against a pipeline running `witness run` exfiltrates
`GITHUB_TOKEN` and cloud credentials. in-toto is a CNCF project.

</td>
<td width="50%">

**pyLoad** · [CVE-2026-35459](https://nvd.nist.gov/vuln/detail/CVE-2026-35459)
`CRITICAL 9.3` `INCOMPLETE FIX`

The fix for CVE-2026-33992 validated the initial download URL. pycurl was
still configured with `FOLLOWLOCATION=1` and ten redirects, none of them
revalidated, so a redirect to `169.254.169.254` walks straight past the new
check. The advisory carries the maintainers' own title: *"Incomplete fix for
CVE-2026-33992"*.

</td>
</tr>
<tr>
<td width="50%">

**Tekton Pipelines** · [CVE-2026-40938](https://nvd.nist.gov/vuln/detail/CVE-2026-40938)
`HIGH 7.5`

The git resolver passed `revision` to `git fetch` as a positional argument, so
`--upload-pack=<binary>` parsed as a flag, and `validateRepoURL` accepted local
filesystem paths. The `tekton-pipelines-resolvers` ServiceAccount holds
cluster-wide read on **every Secret**, so a tenant able to submit
`ResolutionRequest` objects reaches all of them.

</td>
<td width="50%">

**NASA** · [GHSA-fvwj-92vj-fg8c](https://github.com/nasa/spacewasm/security/advisories/GHSA-fvwj-92vj-fg8c)
`CRITICAL 9.0`

A result-typed `if` with no `else` is accepted whenever the then-arm ends
`unreachable`, so the validator counts a result the interpreter never pushes.
Repeat it and the operand stack walks off the runtime stack pointer by an
attacker-chosen offset — host pointers disclosed, writes landing in another
module's private linear memory. Second stack-desync class in the same
interpreter, after [GHSA-r5f5-cv78-6qv8](https://github.com/nasa/spacewasm/security/advisories/GHSA-r5f5-cv78-6qv8).

</td>
</tr>
<tr>
<td width="50%">

**Contour** · [CVE-2026-41246](https://nvd.nist.gov/vuln/detail/CVE-2026-41246)
`HIGH 8.1`

`pathRewrite.value` under `cookieRewritePolicies` is interpolated into the
Envoy Lua filter through Go `text/template` with no escaping. Code runs inside
a proxy shared by other tenants, reaching xDS client credentials on disk —
their TLS keys, not just the attacker's own route.

</td>
<td width="50%">

**nginx** · [1.31.2](https://nginx.org/en/CHANGES) `UPSTREAM CREDIT`

The `secure_link` module compared its security hash without constant-time
semantics. Fixed upstream and credited by name in the official changelog:

> *"constant time `secure_link` hash comparison. Thanks to kodareef5."*

</td>
</tr>
<tr>
<td width="50%">

**Composer** · [CVE-2026-40261](https://github.com/advisories/GHSA-gqw4-4w2p-838q)
`HIGH 8.8`

Command injection through the Perforce source handler, reachable from
package metadata, so the untrusted input is the package itself, which is
the whole trust model of a dependency manager. Sole reporter. Red Hat
shipped [errata](https://access.redhat.com/security/cve/CVE-2026-40261).

</td>
<td width="50%">

**Coolify** · [CVE-2026-34168](https://nvd.nist.gov/vuln/detail/CVE-2026-34168)
`HIGH 8.8`

`LocalPersistentVolume.name` is interpolated straight into `docker volume`
shell commands with no argument escaping, so shell metacharacters in a storage
name execute when the resource is deleted. Any authenticated user with an API
token reaches command execution on every managed server.

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
<tr>
<td width="50%">

**Authorizer** · [CVE-2026-35511](https://github.com/advisories/GHSA-29rf-f4vv-pvq6)
`ZERO-CLICK ATO`

OAuth identities link to an existing account by email without checking that
the owner ever verified it, and the pre-existing password is never
invalidated. Register the victim's address, never confirm it, and their
ordinary Google login hands you persistent password access — no unusual
action by the victim, no notification that a provider was linked.

</td>
<td width="50%">

**systemd** · [GHSA-m8q3-73v4-wvg7](https://github.com/systemd/systemd/security/advisories/GHSA-m8q3-73v4-wvg7)
`LOCAL ROOT` `INCOMPLETE FIX`

The earlier fix validated `ID_SCSI_SERIAL` for control characters and stopped
there. `ID_WWN` and its two siblings come from the same untrusted VPD page 83
copy, so a newline still injects a line into `scsi_id --export`, udev imports
it as a device property, and `SYSTEMD_WANTS=` starts a root unit. Patched
across four stable series.

</td>
</tr>
</table>

### The data

**Severity**, as published in each advisory

{{SEVERITY_TABLE}}

**Ecosystem**

{{ECOSYSTEM_TABLE}}

**Weaknesses**, as classified by the maintainers in each advisory

{{CWE_TABLE}}

### Incomplete fixes

A patch shipped, and the bug class survived it. Every row below is titled or
described as an incomplete fix by the maintainers themselves.

| | |
|---|---|
| [NATS Server](https://github.com/nats-io/nats-server/security/advisories/GHSA-3g5q-cfh2-cq67) | *"Pre-auth server crash via double INFO in leafnode handshake — incomplete fix for CVE-2026-29785 **and** CVE-2026-33218"* |
| [NATS Server](https://github.com/nats-io/nats-server/security/advisories/GHSA-4g68-3pwx-5vfj) | *"MQTT subscribe ACL bypass via `$MQTT.deliver.pubrel` prefix (incomplete fix for CVE-2026-33217)"* |
| [NATS Server](https://github.com/nats-io/nats-server/security/advisories/GHSA-p3j5-5hrq-p75h) | *"Incomplete fix for CVE-2026-33249: Leaf node connections bypass Nats-Trace-Dest permission check"* |
| [pyLoad](https://github.com/advisories/GHSA-7gvf-3w72-p2pg) | *"SSRF filter bypass via HTTP redirect in BaseDownloader (Incomplete fix for CVE-2026-33992)"* |
| [pyLoad](https://github.com/advisories/GHSA-4744-96p5-mp2j) | *"Unprotected `storage_folder` enables arbitrary file write to Flask session store and code execution (Incomplete fix for CVE-2026-33509)"* |
| [Gotenberg](https://github.com/advisories/GHSA-qmwh-9m9c-h36m) | *"Gotenberg has incomplete fix for ExifTool arbitrary file write: case-insensitive bypass and missing HardLink/SymLink tags"* |
| [File Browser](https://github.com/advisories/GHSA-7526-j432-6ppp) | Proxy-auth auto-provisioned users inherit Execute permission — the advisory describes it as an incomplete fix for the earlier signup restriction |
| [systemd](https://github.com/systemd/systemd/security/advisories/GHSA-m8q3-73v4-wvg7) | *"The fix for GHSA-vpfq-8p5f-jcqx added newline/control-character validation before printing `ID_SCSI_SERIAL`, but equivalent validation was not added for `ID_WWN`"* — same VPD page 83 source, same export interface |

One of these — the NATS leafnode crash — survived **two** prior CVE fixes.

### Coverage

> *"Security researcher Koda Reef discovered that the exposed `restoreTenant`
> endpoint ran with no authentication, no IP allowlist and no audit logging."*
> — [GBHackers](https://gbhackers.com/critical-dgraph-database-flaw/), on the Dgraph 10.0

| Finding | |
|---|---|
| **Dgraph** CVE-2026-34976 | [GBHackers](https://gbhackers.com/critical-dgraph-database-flaw/) · [Cybersecurity News](https://cybersecuritynews.com/dgraph-database-vulnerability/) |
| **Rancher Fleet** CVE-2026-41050 | [GBHackers](https://gbhackers.com/critical-vulnerability-in-rancher-fleet/) · [CyberPress](https://cyberpress.org/rancher-fleet-flaw/) · [Lyrie Research](https://lyrie.ai/research/research/2026-05-07-rancher-fleet-multitenant-secret-leak) |
| **pyLoad** CVE-2026-35459 | [SANS AtRisk XXVI-14](https://www.sans.org/newsletters/at-risk/xxvi-14) |
| **Contour** CVE-2026-41246 | [ZeroPath](https://zeropath.com/blog/cve-2026-41246-contour-lua-code-injection) |
| **Tekton** CVE-2026-40938 | [CVEReports](https://cvereports.com/reports/CVE-2026-40938) |

### Advisories

Plus **[CVE-2026-5366](https://www.cve.org/CVERecord?id=CVE-2026-5366)**.
Critical, git argument injection in Prefect deployment pull steps via an
unsanitized `commit_sha`, across four injection points. Reported and
CVE-assigned through
[huntr](https://huntr.com/bounties/e2e88a0f-a8f6-49c9-94c5-e98dc385f07a);
[fixed upstream](https://github.com/PrefectHQ/prefect/commit/6a9d9918716ce4ee0297b69f3046f7067ef1faae).
Not among the {{TOTAL}} below, which are advisory credits only.

{{ADVISORY_TABLE}}

Machine-readable: [advisories.csv](https://github.com/kodareef5/kodareef5/blob/main/advisories.csv) · [upstream.csv](https://github.com/kodareef5/kodareef5/blob/main/upstream.csv)

<div align="center">

{{FOOTER_STATS}}

[kodareef5@gmail.com](mailto:kodareef5@gmail.com) · [@kodareef5](https://github.com/kodareef5)

</div>
