# Windows Server 2022 Compatibility Notes

This document describes non-obvious design decisions in this collection that exist specifically to handle Windows Server 2022 behavioral changes. Every item here was discovered through testing and represents a real regression from older Windows Server versions.

---

## 1. Domain Join (`ludus_child_domain_join`) — NTLM Loopback Protection

### Symptom
`microsoft.ad.membership` fails with:
```
Computer 'castelblack' failed to join domain 'north.sevenkingdoms.local'...
The specified network name is no longer available.
```

### Root Cause
Windows Server 2022 DCs enforce NTLM loopback protection. When `NetJoinDomain` contacts the DC using an **IP address** (which triggers NTLM), the DC rejects its own NTLM auth response. This affects domain joins from workgroup machines after `ludus_ad_misconfigs` applies `TrustedToAuthForDelegation` on any user — that flag triggers a KDC policy reload which changes how NTLM sessions are negotiated.

### Fix
Pass `domain_server: winterfell` (short NetBIOS hostname, NOT FQDN) to `microsoft.ad.membership`. The short hostname uses NetBIOS name resolution which routes through Kerberos, bypassing the NTLM loopback restriction. The FQDN would resolve to an IP via DNS and trigger NTLM.

```yaml
- name: Join machine to child domain
  microsoft.ad.membership:
    dns_domain_name: "{{ ludus_child_domain_fqdn }}"
    domain_admin_user: "administrator@{{ ludus_child_domain_fqdn }}"
    domain_admin_password: "password"
    domain_server: "{{ ludus_child_dc_hostname }}"   # SHORT hostname only
    state: domain
    reboot: true
```

**Always set `ludus_child_dc_hostname` to the short (NetBIOS) DC hostname in role_vars.**

---

## 2. Domain Join Credential Requirement

### Symptom
Domain join fails with auth errors even with valid domain admin credentials (`eddard.stark`, etc.).

### Root Cause
On Windows Server 2022, `NetJoinDomain` internally uses the **calling machine's own credential context** to negotiate the initial SMB session. Named domain admin accounts (e.g. `eddard.stark`) can fail this internal negotiation due to NTLM restrictions on the DC. The built-in `Administrator` account has different trust handling.

### Fix
Always use `administrator@<child_domain_fqdn>` with Ludus's standard `password` for the join credential, not named domain admin accounts.

---

## 3. KDC Stabilization After Delegation Changes (`ludus_ad_misconfigs`)

### Symptom
Domain join of member servers fails with "network name not available" when `depends_on` fires immediately after `ludus_ad_misconfigs` completes on the DC.

### Root Cause
Setting `TrustedToAuthForDelegation = $true` (constrained delegation) on any AD user triggers a **KDC policy reload** on the domain controller. If a dependent role (like `ludus_child_domain_join`) fires immediately after `misconfigs` returns, `NetJoinDomain` hits the DC during this reload window and fails.

### Fix
A stabilization wait was added to `ludus_ad_misconfigs` after any constrained delegation changes:
```yaml
- name: Wait for KDC to stabilize after delegation changes
  ansible.windows.win_powershell:
    script: |
      repadmin /syncall /AdeP 2>&1 | Out-Null
      Start-Sleep -Seconds 15
  when: >
    (ludus_constrained_delegation_any | length > 0) or
    (ludus_constrained_delegation_kerb_only | length > 0)
```

---

## 4. SMB Signing on Domain Controllers (`ludus_ad_misconfigs`)

### Symptom
`Get-SmbServerConfiguration` shows `RequireSecuritySignature: True` even after setting registry keys to 0.

### Root Cause
On Domain Controllers, the **Default Domain Controllers Policy GPO** enforces SMB signing via a security template (`GptTmpl.inf` in SYSVOL). Registry changes are overwritten by GPO every `gpupdate` cycle (~90 minutes). `secedit /configure` also gets overridden because the GPO security template takes precedence over the baseline.

### Fix
Edit `GptTmpl.inf` in SYSVOL directly for the Default Domain Controllers Policy (GUID `{6AC1786C-016F-11D2-945F-00C04fB984F9}`), then force `gpupdate`. This is the only reliable method:

```powershell
$gptFile = "C:\Windows\SYSVOL\sysvol\$domain\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
$content = (Get-Content $gptFile -Raw).Replace(
    "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature=4,1",
    "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature=4,0"
)
Set-Content $gptFile -Value $content -Encoding Unicode
gpupdate /force
```

The GUID `{6AC1786C-016F-11D2-945F-00C04fB984F9}` is Microsoft's permanent well-known GUID for the Default Domain Controllers Policy and does not change between deployments.

---

## 5. Cross-Domain Group Membership (`ludus_ad_forest_trust`)

### Symptom
`Add-ADGroupMember -Members "essos.local\daenerys.targaryen"` fails with "A referral was returned from the server" or "Cannot find an object with identity."

### Root Cause
When adding cross-forest members to domain-local groups, PowerShell's AD module cannot resolve a string like `"essos.local\daenerys.targaryen"` because it tries to find the object in the **local domain** rather than the foreign domain. The ForeignSecurityPrincipal must be explicitly fetched from the foreign domain DC first.

### Fix
Fetch the `ADObject` from the foreign DC using `-Server`, then pass the object (not a string) to `Add-ADGroupMember`:

```powershell
$member = Get-ADUser -Identity "daenerys.targaryen" -Server "10.X.X.13"
Add-ADGroupMember -Identity "AcrossTheNarrowSea" -Members $member
```

---

## 6. Credential Manager from WinRM (`ludus_ad_misconfigs`)

### Symptom
`cmdkey.exe` calls from Ansible tasks silently succeed but credentials are not stored in the user's vault. `cmdkey /list` shows nothing.

### Root Cause
Windows Credential Manager is **per-user and DPAPI-encrypted**. `cmdkey.exe` and `CredWrite` API calls made from a WinRM/SYSTEM session store credentials in the SYSTEM account's vault, not in the interactive user's vault. The autologon user (`robb.stark`) therefore never sees the stored credential.

### Fix
Use a one-shot scheduled task that runs as the target user in an interactive logon context. The task creates itself, runs once, then self-deletes:

```powershell
$action = New-ScheduledTaskAction -Execute "cmdkey.exe" -Argument "/generic:$target /user:$user /pass:$pass"
Register-ScheduledTask -TaskName "TempCredStore" -Action $action -RunLevel Highest ...
Start-ScheduledTask -TaskName "TempCredStore"
```

---

## 7. Constrained Delegation for Computer Accounts (`ludus_ad_misconfigs`)

### Note
`Set-ADComputer` with `msDS-AllowedToDelegateTo` requires the caller to have `SeEnableDelegationPrivilege` which is only held by Domain Admins. Ensure the `become` user in the role has Domain Admin rights in the target domain.
