1.5.39 (09/10/2026)
All:
   * Updated the vcpkg baseline to 2026-10-08 and the ws-vcpkg-registry baseline to match, which moves Boost to 1.92.0, spdlog to 1.17.0 and fmt to 12.2.0. ADVobfuscator stays pinned to its 2020-06-26 version, because 2.x is a C++20 rewrite with a different API. Boost.Process 1.92.0 is patched to keep using the default locale on Linux, since its new `std::locale("")` throws when `LC_ALL` or `LANG` names a locale that is not installed, which failed every process launch, including ICMP pings.


1.5.38 (05/10/2026)
   * Updated ws-vcpkg-registry baseline to pick up OpenSSL 4.0.3 port.


1.5.37 (25/09/2026)
All:
   * Added `WSNetBridgeAPI::checkIp`, a GET of the node's `v1/ip/check` that answers with the tunnel's own exit addresses as `{"ipv4":"...","ipv6":"..."}`, an unavailable family omitted. It is signed with the same session token as the other bridge calls and is not queued behind one: a node that cannot mint a token (non-pro), a token it no longer honours (403) and an assignment it cannot report (503) all come back as a failure so the caller falls back to another source, rather than the tunnel being torn down and rebuilt just to learn an IP. Note that a bridge request suppressed by advanced parameters is completed locally with an empty body and `kSuccess`, so the address must be read out of the payload rather than inferred from the return code.
   * Added `WSNetTunnelTest` (`WSNet::tunnelTest()`), which checks that a freshly established tunnel carries traffic and reports its exit IPs through `start(isBridgeAllowed, callback)` as `(isSuccess, ipv4, ipv6)`. One run fits in ~14 s. The tunnel-test hostname must resolve through the system resolver first. After that the node's `checkIp` is preferred, with ~6 s for it and retries on transport errors. Otherwise the exit IP is fetched over HTTPS, with IPv4 deciding the result and IPv6 filled in only if it answers within ~0.5 s of IPv4. Pass `isBridgeAllowed = false` for a tunnel that does not end on a Windscribe node (a custom config). The schedule is the same for every protocol: a protocol that needs time to settle after connecting (OpenVPN) must be waited out by the caller before `start()`. Cancel the returned callback as soon as the tunnel goes down, since a result that arrives later describes a tunnel that no longer exists.
   * Breaking API change: `WSNetServerAPI::pingTest` is removed. Use `WSNetTunnelTest` instead.
   * Breaking API change: added `WSNetHttpRequest::setIpFamily` / `ipFamily` (`kIpv4` by default). DNS is queried only for that family and the request connects only over it.
   * Bridge API requests (`pinIp`, `rotateIp`, `checkIp`) that fail at the transport level, without reaching the node, now return `kNetworkError` instead of `kBridgeApiError`, so they can be told apart from an error the node actually returned and retried. `kBridgeApiError` now means only an answer from the node.
   * The primary tunnel-test endpoint is now `checkip.windscribe.net` instead of `checkip.windscribe.com`.


1.5.36 (03/09/2026)
Linux:
   * ICMP pings no longer fail under a non-English system locale. The system ping utility was launched with the user's locale, and its translated output (`tempo=` for `time=`, and `icmp_seq=` in some translations) did not match the parser, so every ICMP ping failed for users with a translated locale. Child processes now run with `LC_ALL=C.UTF-8` and without `LANGUAGE`, so their output is untranslated while non-ASCII text still survives.


1.5.35 (01/09/2026)
All:
   * Bridge API session tokens are now keyed by server node id instead of the node's hostname. A token lives in the issuing node's own store, scoped to the tunnel source IP, and no other node honours it; a hostname stopped naming one node once every server in a datacenter could answer to a single protocol-level record, so the cache would have offered one node's token to another. Breaking API change: `WSNetBridgeAPI::setCurrentHost(host)` is replaced by `setCurrentNodeId(nodeId)`, with 0 meaning "no API node" (a custom config), whose token is now kept for the live connection only instead of being persisted in a bucket every other nodeless connection read back. Tokens persisted under the old hostname keys are dropped on load.
   * A reply that arrives after the tunnel it was sent on has gone is no longer applied to the connection that replaced it. Requests now carry the connection they were issued under, so a token answering for a node we have already left is discarded instead of being stored under the current node's id and used to sign its requests -- the cross-node mix-up the node-id keying exists to prevent, reachable through a reconnect that beat a 5-second request timeout.
   * A queued pinIp request is no longer failed while the token retry it is waiting on is still in flight. A node that rejects the token we present makes the client ask for a fresh one, which usually succeeds -- but the pin was being answered with kNoToken a moment before that landed, surfacing as a failed IP pin on a connection that was about to work.


1.5.34 (27/08/2026)
All:
   * Exposed the server id on parsed serverlist-v2 nodes so clients can correlate server nodes with API ids.


1.5.33 (26/08/2026)
All:
   * Exposed serverlist-v2 force-disconnect nodes (`fd: 1`) through inventory parsing and server locations, so clients can avoid new connections to draining nodes and evacuate existing connections. #39


1.5.32 (18/08/2026)
All:
   * Scoped retries, backoff and failover to invalid JSON, timeouts and 5xx responses. A non-2xx response carrying the API's JSON envelope (`errorCode` and/or `data`) -- a failed captcha answers HTTP 403, a throttled caller HTTP 429 -- is now delivered to the app as a valid answer instead of being retried or replacing the failover route. Requests that do not return JSON (ServerConfigs) still require a 2xx.
   * Fixed curl debug log redaction treating domains and IPs as regex, which injected MD5 hashes into timeout values and other numbers when the host was an IP literal.
   * Fixed IPv6-literal hosts leaking into curl debug logs. A URL host is serialized as [2001:db8::1] while curl logs the bare address, so the redaction never matched it.


1.5.31 (12/08/2026)
All:
   * Replaced ApiResourcesManager's fixed 1-second failed-request retry delay with bounded per-resource exponential backoff (1s doubling to a 5-minute cap, with jitter), so clients no longer retry large resources such as /Inventory/servers and /Inventory/locations at a fixed 1 Hz rate during API outages. Offline answers keep the quick fixed retry since they never reach the API.
   * Applied the same bounded exponential backoff to the login/session/signup network-error retry loops (previously fixed 1-second) and to the auth-token retry, which previously re-issued immediately with no delay at all. A new user-initiated login attempt resets the backoff, goes out immediately, and cancels the previously scheduled retry, so a stale retry can no longer re-submit old credentials on top of the new attempt. These interactive flows cap their retry delay at 1 minute instead of 5: their retries are silent, so the user is watching a spinner the whole time, and they are a small share of outage traffic next to the resource fetches.
   * Non-2xx API responses are no longer parsed as success: previously an error page whose body happened to look like our JSON envelope could be stored as a fetched resource for 24 hours, win a failover probe (so a broken route kept being selected), or be reported as the device's IP by the myIP diagnostic. A 429/5xx now means "the API is temporarily unavailable": the request is retried on the same failover, paced by the retry backoff above, while any other status (a redirect, 4xx -- the usual signature of a fronting CDN or middlebox) replaces the route. A failover that answers nothing but HTTP errors for over 5 minutes is treated as broken and re-probed.
   * Removed the unused SpeedRating API.


1.5.30 (31/07/2026)
All:
   * Fixed logout being undone by an in-flight request whose answer restored the auth hash, logging the user back in on the next launch.


1.5.29 (13/07/2026)
All:
   * Fixed TLS verification failing on Linux distros without a Debian-style CA bundle path (e.g. openSUSE): the embedded CA bundle is now supplied via CURLOPT_CAINFO_BLOB, so cURL 8.21's compile-time default CA file path is never loaded.


1.5.28 (09/07/2026)
All:
   * Hardened URL construction and various components in response to a security audit. #32


1.5.27 (07/07/2026)
All:
   * Updated dependencies: cURL 8.21.0, OpenSSL 4.0.1, c-ares 1.34.7.
   * Fixed the CURLOPT_ECH option prefix ("ECL:" -> "ecl:"); curl only accepts the lowercase form, so ECH was silently not applied on previous curl versions and caused request timeouts with cURL 8.21.


1.5.26 (29/06/2026)
All:
   * Added an advanced parameter to suppress automatic Bridge API `/v1/token` requests and no-op Bridge API calls while token fetching is suppressed. #31


1.5.25 (16/06/2026)
All:
   * Changed the account cancellation request parameter from `sso_token` to `token`.


1.5.24 (15/06/2026)
All:
   * Added SSO token plumbing for account cancellation requests. #29


1.5.23 (12/06/2026)
All:
   * Added Windows compiler/linker security settings.
   * Updated Windows SDK floor target to Windows 10 2004 to match desktop app.


1.5.22 (11/06/2026)
All:
   * Added an installer param to signup, token signup, and SSO requests for clients to self-report their install source (Play Store vs sideload) during attestation data collection. An empty value is normalized to the "none" sentinel inside the library so the param is always present on signup requests.


1.5.21 (08/06/2026)
All:
   * Replaced sequential failover with a parallel myIP probe and persisted-UID fast path, adding a TTL probe cache and failover metrics logging. #10


1.5.20 (08/06/2026)
All:
   * Fixed malformed persistent settings handling for non-string AmneziaWG config IDs and synchronized BridgeAPI session-token state. #26


1.5.19 (05/06/2026)
All:
   * Use curve set, signature algorithms, and ec_point_formats exactly as Ubuntu 26.04 / Debian 13 / AltLinux Sisyphus. #25


1.5.18 (26/05/2026)
All:
   * Added signup attestation token plumbing for signup, token signup, and SSO requests.


1.5.17 (22/05/2026)
All:
   * Removed custom TLS curves list. OpenSSL 4.0 proposes post-quantum groups by default, and a custom list is a fingerprintable signature.


1.5.16 (21/05/2026)
All:
   * Force-disable custom TLS curves for ExtraPadding and CDN.


1.5.15 (19/05/2026)
All:
   * Added ipv6 support.
   * Removed test/coverage flags from build.


1.5.14 (30/04/2026)
All:
   * Added RapidJSON type safety checks across all JSON parsers to prevent assertion failures on unexpected value types. Hardens pingmethod_http, persistentsettings, serverlocations_request, echfailover, accessipsfailover, dynamicdomainfailover, and sessionstatus against malformed or tampered responses.
   * Added amneziawg_config_id tracking from the server inventory API.


1.5.13 (24/04/2026)
All:
   * Fixed IS_BUILD_TESTS CMake flag not being honored; tests were always built regardless of the flag's value. Tests now build only when IS_BUILD_TESTS is truthy.


1.5.12 (22/04/2026)
All:
   * Fixed Bridge API session tokens not being cleared during logout and persistent settings cleanup.
   * Fixed use-after-free crash when API handles outlive global WSNet teardown.


1.5.11 (20/04/2026)
All:
  * Replace the hostname with the IP-address for HTTP ping.
iOS:
  * Generate dsyms alongside frameworks so we can have sybolication in crash reports.


1.5.10 (17/04/2026)
All:
   * Fixed ALC purchased locations shown as disabled after app launch.


1.5.9 (16/04/2026)
All:
   * Added continent field to ServerLocation and InventoryLocation, parsed from the /Inventory/locations API response.


1.5.8 (15/04/2026)
All:
   * Fixed missing `errno.h` include on non-Windows platforms in requesterror.cpp, required for POSIX error constants (EHOSTUNREACH, ENETUNREACH, ENETDOWN).
   * Fixed macOS linking by adding the SystemConfiguration framework dependency, required for SCDynamicStore DNS config functions.
   * Updated OpenSSL to 4.0.0. ECH is now supported natively upstream, removing the need for our custom ECH patch.


1.5.7 (13/04/2026)
All:
   * Updated OpenSSL to 3.6.2.


1.5.6 (11/04/2026)
All:
   * Expose inventory datacenter `status` in server locations (`ServerGroup::status` on desktop; `status` and per-datacenter `p2p` on each group in `locationsJson()` on mobile).


1.5.5 (07/04/2026)
All:
   * Added generateRandomUsername() and generateRandomPassword() methods to ServerAPI for signup flow credential generation.
   * Fixed a bug in the call to ares_init_options.
   * Fixed c-ares regression by downgrading back to 1.34.5 and applying the security patch in the portfile.
   * Removed client-side datacenter status filter from server list parsing, now handled server-side.


1.5.4 (31/03/2026)
All:
   * Updated openSSL (3.6.1), cURL (8.19.0), c-ares (1.34.6)
Android:
   * Revert WhitelistSocketFds callback functionality.


1.5.2 (30/03/2026)
All:
   * Moved p2p field from ServerLocation to ServerGroup for per-datacenter granularity.


1.5.0 (23/03/2026)
All:
   * Updated v2 server list field names, added tri-state backup parameter, and AmneziaWG login-readiness gating.


1.4.9 (09/03/2026)
All:
   * Added a PowerShell script for syncing a tagged release to ones local GitHub wsnet repo. #9
   * Added support for the new server list v2 API (inventory-based).


1.4.8 (24/02/2026)
All:
   * Initial release after separation from client-desktop (Desktop-App) repo.
