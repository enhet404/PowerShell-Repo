### Overview

| Script | Purpose |
|---|---|
| **Import-IntuneUserPfxCertificate.ps1** | Bulk upload user PFX certs (skips duplicates by thumbprint). |
| **Remove-IntuneUserPfxByThumbprint.ps1** | Bulk removal of user PFX certs by thumbprint (module first, Graph fallback). |
| **Get-PfxThumbprint.ps1** | Local inspection of a `.pfx` (prints subject/issuer/dates + SHA-1/SHA-256). |
| **Export-PfxCAs.ps1** | Export Root + Intermediate CA certs from a `.pfx/.p12` to `.cer` (no private keys). |

---

### Import-IntuneUserPfxCertificate.ps1 (Bulk upload)

<details>
<summary><strong>What it does</strong></summary>

- Enumerates **transitive members** (handles nested groups) of an Entra security group.
- Calculates the **PFX thumbprint locally**.
- For each user, checks existing **Intune `userPfxCertificates`**; skips if the same thumbprint is already present.
- Otherwise, uploads the PFX for that user via the **Intune PFX import module**.

</details>

---

### Remove-IntuneUserPfxByThumbprint.ps1 (Bulk removal)

<details>
<summary><strong>What it does</strong></summary>

- Enumerates **transitive members** of a group.
- For each user, finds a `userPfxCertificate` with the given thumbprint.
- **Phase 1:** Tries the module `Remove-IntuneUserPfxCertificate`.
- **Phase 2 (fallback):** If still present, deletes directly via Graph  
  `DELETE /beta/deviceManagement/userPfxCertificates/{id}`
- Verifies after deletion and prints the final summary.

</details>

---

### Get-PfxThumbprint.ps1 (Local PFX info)

<details>
<summary><strong>What it does</strong></summary>

Imports a local `.pfx` using resilient strategies and prints:

- Subject
- Issuer
- NotBefore / NotAfter
- SHA-1 Thumbprint
- SHA-256

If .NET can’t open the PFX (modern PBES), it falls back to `certutil -dump` to validate the password and parse SHA-1.

</details>

---

### Export-PfxCAs.ps1 (Export Root + Intermediate Certificates)

<details>
<summary><strong>What it does</strong></summary>

Exports the **Root** and any **Intermediate CA** certificates embedded in a `.pfx/.p12` to DER `.cer` files, ready for upload to Intune as **Trusted certificate** profiles.

- Reads your PFX using **OpenSSL** (handles legacy RC2/etc. with the legacy provider).
- **Never exports private keys.**
- Writes:
  - `root.cer`, `root_2.cer` (if multiple roots, rare)
  - `intermediate_1.cer`, `intermediate_2.cer`, …

</details>