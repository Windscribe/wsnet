1.5.20 (08/06/2026)
All:
   * Fixed malformed persistent settings handling for non-string AmneziaWG config IDs and synchronized BridgeAPI session-token state.


1.5.19 (05/06/2026)
All:
   * Use curve set, signature algorithms, and ec_point_formats exactly as Ubuntu 26.04 / Debian 13 / AltLinux Sisyphus.


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
   * Added a PowerShell script for syncing a tagged release to ones local GitHub wsnet repo.
   * Added support for the new server list v2 API (inventory-based).


1.4.8 (24/02/2026)
All:
   * Initial release after separation from client-desktop (Desktop-App) repo.
