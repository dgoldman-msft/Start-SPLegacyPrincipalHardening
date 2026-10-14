# Start-SPLegacyPrincipalHardening

**Read-only** security review of a Microsoft 365 tenant's exposure to the legacy SharePoint add-in / Azure ACS model and the first-party **SharePoint Online Client Extensibility Web Application Principal** (and its WebShell/Helper siblings). Built for incident response (phished user + mass SharePoint download) and for periodic review.

The module **never changes the tenant**: it requests read-only Graph scopes, sends only `GET` requests to Microsoft Graph (enforced in `Invoke-GraphWithRetry`), and calls only read cmdlets in PnP.PowerShell. Every result is a recommendation, grounded in Microsoft Learn, for the customer to carry out themselves. The deliverable is a single HTML report.

Public functions live in `functions\`, every helper in `internal\functions\`, and all logging goes through `Write-ToLogFile`.

* PowerShell 7.4 or later (required by PnP.PowerShell 3.x)
* Modules are **installed from the PowerShell Gallery (current user) and imported automatically** if missing: `Microsoft.Graph.Authentication`, `PnP.PowerShell`
* Existing Graph and PnP sessions are **reused** when the tenant / admin URL matches and the Graph scopes are sufficient
* An Entra app registration for PnP interactive sign-in (see [PnP sign-in](#pnp-sign-in)); sign-in is interactive, so expect a browser prompt for Graph and one for SharePoint admin

## Quick start

```powershell
Import-Module .\1.0\Start-SPLegacyPrincipalHardening.psd1

# Optional: sign in ahead of time (also done automatically by the main command)
Connect-SPLegacyTenant -TenantId contoso.onmicrosoft.com -PnPClientId '<app-id>'

# Review all eight areas and write Recommendations_<timestamp>.html
Start-SPLegacyPrincipalHardening -TenantId contoso.onmicrosoft.com -PnPClientId '<app-id>'

# Rebuild the HTML report from an earlier run's findings
New-SPLegacyRecommendationReport -FindingsCsv .\Findings_20261014_124258.csv
```

## The eight checks

| # | `-Task` | What is checked (read-only) |
|---|---------|-----------------------------|
| 1 | `AcsInventory` | ACS/add-in principals (`Get-PnPAzureACSPrincipal`, tenant scope) with expiry, redirect URI, matching Entra service principal. |
| 2 | `LegacyAddInSettings` | `DisableCustomAppAuthentication`, the tenant "SharePoint Online Client" service principal, and the Microsoft first-party *Client Extensibility* principals with their consented grants. |
| 3 | `AppOnlyPermissions` | Every app holding `Sites.FullControl.All` / `Manage` / `ReadWrite` / `Read.All`, `Files.*.All`, `AllSites.*` on SharePoint or Graph; flags secret-only credentials. |
| 4 | `CustomScript` | Sites where `DenyAddAndCustomizePages` is not enforced. |
| 5 | `SignInMonitoring` | Entra sign-ins for the legacy principals (queried one day at a time): volume spikes, new country vs. baseline, one user in several countries, risky and legacy-protocol sign-ins. Writes ready-to-deploy KQL (Sentinel rule + Defender mass-download hunt). |
| 6 | `IdentityProtection` | ID Protection / Defender for Cloud Apps licensing, risky users and detections, Defender for Cloud Apps alerts, risk-based CA coverage, user-consent policy, third-party OAuth grants, recent "Consent to application" events. |
| 7 | `LegacyAuthBlock` | Conditional Access policy blocking Exchange ActiveSync/"other" clients; `LegacyAuthProtocolsEnabled`. |
| 8 | `EnterpriseAppReview` | Full enterprise-app inventory: owners, secrets/certs, expired / long-lived secrets, broad permissions, apps created in the last `-NewAppDays`, apps with no sign-in for `-StaleAppDays`. |

Run a subset with `-Task AcsInventory, LegacyAuthBlock`.

### Safety model

* There is no remediation mode. There are no `-Mode`, `-DryRun`, `-Force` or remediation parameters, and no write permissions are ever requested.
* Recommendations are written for the customer's administrators to review and perform. Where a command is quoted (for example `Set-SPOTenant -DisableCustomAppAuthentication $true`), it is text in the report, not something the module runs.
* Before removing a tenant-wide role from an app, grant it `Sites.Selected` on the sites it needs, or the app loses access.

## Output

Everything goes to `-OutputPath` (default `Documents\SPLegacyPrincipalHardening\<timestamp>`):

* `Recommendations_<ts>.html` - **the customer report**: summary, scorecard, "Fix first (P1)" table, detail per area with steps, Microsoft Learn links, and a references list. Self-contained (no external files); also flags clearly when the review is incomplete (for example no PnP app).
* `SPLegacyPrincipalHardening_<ts>.log` - timestamped log (all output goes through `Write-ToLogFile`)
* `Findings_<ts>.csv` - every finding: Task, Severity, Status (`Compliant`, `NonCompliant`, `Info`, `Manual`, `Failed`, `Skipped`), Resource, Finding, Detail, Recommendation, Reference (Microsoft Learn URLs)
* `Summary_<ts>.json` - counts by status/severity
* Per-task datasets: `AcsPrincipals`, `AppOnlyPermissions`, `CustomScriptSites`, `LegacyPrincipalSignIns`, `RiskyUsers`, `OAuthGrantsThirdParty`, `RecentConsentEvents`, `EnterpriseApps`, ...
* `LegacyPrincipalAlerts_<ts>.kql` - alert / hunting queries

The command also returns an object with these paths and the `Findings`.

### Microsoft Learn grounding

Every actionable finding (non-compliant, manual, skipped, failed) carries up to three `learn.microsoft.com` articles in its `Reference` column. They are shown in the log/console (once per article per task), next to each recommendation in the HTML report, and listed together in a **Microsoft Learn references** section at the end of the report. The mapping lives in `internal/functions/Get-LearnReference.ps1`; add or change an entry there (and verify the URL resolves) to update a recommendation's sources.

## Permissions

Graph (delegated, **read-only**, requested only for the selected tasks, and only when the existing session lacks them): `Organization.Read.All`, `Application.Read.All`, `Directory.Read.All`, `AuditLog.Read.All`, `DelegatedPermissionGrant.Read.All`, `Policy.Read.All`, `IdentityRiskyUser.Read.All`, `IdentityRiskEvent.Read.All`, `SecurityAlert.Read.All`.

SharePoint: the signed-in account needs the SharePoint Administrator role (tenant admin site access).

### PnP sign-in

PnP.PowerShell requires your own Entra app registration for interactive sign-in. Create one once:

```powershell
Register-PnPEntraIDAppForInteractiveLogin -ApplicationName 'SPLegacyHardening' -Tenant contoso.onmicrosoft.com
```

(Interactive sign-in is the default in PnP.PowerShell 3.x; there is no `-Interactive` switch - only `-DeviceLogin` to opt out.) Then pass `-PnPClientId <id>` or set `$env:ENTRAID_APP_ID`. If neither is given, the module searches the tenant (via Graph, `Application.Read.All`) for a public-client app registration (an app named `SPLegacyHardening` is preferred; otherwise a single candidate is used). An app created without a `http://localhost` redirect URI or "Allow public client flows" is not detected - pass `-PnPClientId` explicitly. Without a usable app, tasks that need SharePoint admin (1, 2, 4, 7-SharePoint-side) are logged as `Skipped` and the Graph-only tasks still run. This is called out in three places: a red **ACTION REQUIRED** notice in the console when connecting (with the reason, affected tasks and fix), a **NOT FULLY ASSESSED** notice after the run summary, and an **Action required: run prerequisites not met** section at the top of the recommendations report (also recorded as a `Prerequisites` row in the Findings CSV and in `Summary_*.json`). When an app is auto-detected the console and report state which app and source were used.

## Corrections to common guidance

Some commands often quoted for this topic **do not exist**; the module uses the real equivalents:

| Quoted | Reality / what this module uses |
|--------|----------------------------------|
| `Get-SPOApplicationPrincipals` | No such cmdlet. `Get-PnPAzureACSPrincipal` (PnP) lists ACS principals. |
| `Remove-SPOApplicationPrincipal` | No such cmdlet, and PnP has no `Remove-PnPAzureACSPrincipal`. Removal is manual through `AppPrincipals.aspx`. |
| `Disable-LegacyServicePrincipal` | No such cmdlet. The documented switch is `Set-SPOTenant` / `Set-PnPTenant -DisableCustomAppAuthentication $true` (recommended to the customer, never run by the module) and, optionally, `Disable-PnPTenantServicePrincipal`. |
| `Set-PnPAzureADAppSitePermission` | Changes an existing grant. Creating one is `Grant-PnPEntraIDAppSitePermission` (alias `Grant-PnPAzureADAppSitePermission` on older PnP). Quoted only as guidance. |

## Limitations (please read)

* **ACS removal is manual.** No supported cmdlet deletes an ACS registration; the report tells the customer to remove it on `AppPrincipals.aspx`. `DisableCustomAppAuthentication` (item 2) is what actually blocks ACS app-only tokens tenant-wide. Microsoft retired ACS for SharePoint Online on 2 April 2026, so anything still active should be treated with suspicion.
* **ACS tokens are not in Entra sign-in logs.** Task 5 covers sign-ins that flow through the Entra-side principals; ACS-issued app-only access shows up only in SharePoint/Purview audit logs (`FileDownloaded`, `FileSyncDownloadedFull`). The KQL file includes a mass-download hunt for that.
* **Alerts are not deployed.** Creating alert rules needs a Log Analytics/Sentinel workspace; the module writes the queries.
* **Defender for Cloud Apps policies and the admin-consent workflow are portal-only** and are reported as `Manual`. Entra ID Protection licensing cannot be enabled by script.
* **Periodic review (item 8)** is a repeatable report. The module signs in interactively, so schedule it by running it on a cadence from an admin workstation and diffing the `EnterpriseApps` CSVs.
* Sign-in log retention is 30 days (P1/P2); service-principal sign-in activity (`lastSignIn`) requires P1/P2.
* PnP.PowerShell and Microsoft.Graph.Authentication ship overlapping MSAL assemblies. If sign-in fails with an assembly conflict, use a fresh PowerShell session and run `Connect-SPLegacyTenant` first.

## If this is an active incident

This module reviews and reports; it does not contain the compromise or change anything. In parallel: revoke the user's sessions and refresh tokens, reset credentials and MFA methods, review the user's inbox rules and registered MFA methods, remove any consented attacker app (task 6 lists recent consents), and search the unified audit log for `FileDownloaded` / `FileSyncDownloadedFull` by that user and IP to scope the data exposure.

## Module layout

```
1.0\
  Start-SPLegacyPrincipalHardening.psd1 / .psm1
  functions\            Connect-SPLegacyTenant, Start-SPLegacyPrincipalHardening, New-SPLegacyRecommendationReport (public)
  internal\functions\   logging, retry/paging (GET-only), module install, session connect/reuse,
                        findings/Learn-reference/HTML-report plumbing, and one function per task
```

