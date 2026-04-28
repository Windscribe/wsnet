1.5.6.3 (22/04/2026)
All:
   * Fixed Bridge API session tokens not being cleared during logout and persistent settings cleanup.
   * Fixed use-after-free crash when API handles outlive global WSNet teardown.


1.5.6.2 (20/04/2026)
All:
   * Replace the hostname with the IP-address for HTTP ping.


1.5.6.1 (17/04/2026)
All:
   * Fixed ALC purchased locations shown as disabled after app launch.


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
