# Scoped vaults for K3s

The master KeePass database holds everything. A pod never gets it. Each service gets its own
small database, built by `auto-pass` from the master and containing only that service's
entries, protected by its own random password. A compromised pod can read its own vault and
nothing else, because nothing else is in the file.

```
master.kdbx  ──(auto-pass scope sync)──►  <scope>.kdbx  ──(kubectl apply, stdin)──►  Secret  ──►  pod
     ▲                                          ▲                                                  │
     └──── write-back: Password of `writable` entries only, master wins on conflict ◄─────────────┘
```

Everything that touches the master (building, write-back, conflict handling, delivery) runs in
`auto-pass` on the host. Nothing in the cluster holds the master password or can write the master.

## 1. Define scopes

Copy `config/scopes.example.toml` to `config/scopes.local.toml` (gitignored).

```toml
[scopes.intake]
entries  = ["infra/intake-*", "shared/object-store"]   # copied into the scoped vault
writable = ["infra/intake-api-token"]                  # password may be changed by the service
writeback_path = "~/.local/share/auto-pass/writeback/intake.kdbx"
```

```bash
auto-pass scope list            # exactly what each scope would contain, [ro]/[rw] per entry
auto-pass scope sync            # build/refresh the scoped databases on the host
```

Rules enforced by the code:

- Only entries matching `entries` are copied, all attributes included (custom attributes and
  TOTP seeds survive; entry history is dropped so superseded passwords are not shipped).
- Nothing under `auto-pass/` is ever copied. The scope's own password is stored there, in the
  master, as `auto-pass/scopes/<name>`.
- A scope that matches no entries is an error, not an empty vault.
- A scope is rebuilt only when its content changed (keyed digests in
  `~/.cache/auto-pass/scope-state.json`, mode 0600), so the Secret is not rewritten needlessly.

## 2. RBAC

```bash
auto-pass scope manifest --with-namespace | kubectl apply -f -
```

This emits no secret data and is safe to commit. Per scope it creates:

| Object | Purpose |
|---|---|
| `Namespace/<ns>` | One namespace per service; `pod-security.kubernetes.io/enforce` set (default `restricted`) |
| `ServiceAccount/<name>` | The pod's identity. `automountServiceAccountToken: false` and **no Role at all**: the kubelet mounts the Secret, so the pod needs no API access |
| `Role/auto-pass-sync` | `create` on secrets (cannot be name-limited), and `get/update/patch` on **only** `<secret_name>` |
| `RoleBinding/auto-pass-sync` | Binds that Role to the sync identity (`ServiceAccount/auto-pass-sync` in `auto-pass-system` by default) |

Because RBAC is additive, isolation holds only while nothing else grants Secret access in these
namespaces (no `ClusterRoleBinding` to `cluster-admin`, `edit` or `admin` for pod identities,
no wildcard Roles). Check it against the live API server:

```bash
auto-pass scope verify          # impersonates every scope's ServiceAccount against every Secret
```

It exits non-zero if any pod ServiceAccount can `get` or `update` any scope Secret, or if the
sync identity cannot update its own. It needs a kubeconfig that may impersonate (the admin one).

For the sync identity, either run `auto-pass` with the K3s admin kubeconfig (`kubectl = "k3s kubectl"`
in the config), or mint a token for `auto-pass-sync` and point `kubeconfig` at a file that uses
it, which limits what a leaked kubeconfig can do to those Secrets.

## 3. etcd (datastore) encryption

Secrets are base64, not encrypted, in the K3s datastore (SQLite/etcd) unless encryption at rest
is on. The scoped vault is itself an encrypted kdbx, but the password sits beside it in the same
Secret, so encrypt the datastore too. K3s manages the key and the `EncryptionConfiguration`:

```bash
# root required — run these yourself (agents here cannot sudo). Absolute paths, so they paste
# from any directory; <repo> is this repository's checkout.
/usr/bin/sudo /usr/bin/install -m 0644 <repo>/deploy/k3s/config.yaml.example /etc/rancher/k3s/config.yaml   # or merge the keys into your existing file
/usr/bin/sudo /usr/bin/systemctl restart k3s
/usr/bin/sudo /usr/local/bin/k3s secrets-encrypt status          # expect: Encryption Status: Enabled
```

Secrets that already existed are only encrypted when rewritten. Re-encrypt them, then rotate
the key on a schedule:

```bash
/usr/local/bin/kubectl get secrets -A -o json | /usr/local/bin/kubectl replace -f -
/usr/bin/sudo /usr/local/bin/k3s secrets-encrypt rotate-keys
/usr/bin/sudo /usr/local/bin/k3s secrets-encrypt status
```

The `write-kubeconfig-*` keys let your login run `kubectl` without sudo; without them `auto-pass scope sync --apply` fails with "permission denied" on `/etc/rancher/k3s/k3s.yaml`.

(Commands are from `k3s secrets-encrypt --help` on v1.36.6; confirm against your version. On a
multi-server cluster, restart all servers.) Also keep the K3s token and
`/var/lib/rancher/k3s/server/cred/encryption-config.json` out of backups that leave the host.

## 4. Deliver

```bash
auto-pass scope sync --apply            # rebuild changed scopes and apply their Secrets
auto-pass scope sync intake --apply --force
```

The Secret (`vault.kdbx`, `password`) is sent to `kubectl apply -f -` on stdin; it is never
written to disk or into a manifest. Mount it read-only and use the normal library:

```yaml
spec:
  serviceAccountName: intake
  automountServiceAccountToken: false
  containers:
    - name: intake
      env:
        - {name: AUTO_PASS_KEEPASSXC_DB_PATH, value: /var/run/auto-pass/vault.kdbx}
        - name: AUTO_PASS_KEEPASSXC_DB_PASSWORD
          valueFrom: {secretKeyRef: {name: intake-vault, key: password}}
      volumeMounts:
        - {name: vault, mountPath: /var/run/auto-pass, readOnly: true}
  volumes:
    - name: vault
      secret: {secretName: intake-vault, defaultMode: 0400}
```

Do not mount it with `subPath`: those mounts never see Secret updates. Run `scope sync --apply`
from a timer (see `clockwork`) so rotations in the master reach the pods.

## 5. Two-way sync (latest change wins)

`auto-pass scope sync` reconciles both directions on every run. For each `writable` entry:

| Master changed since last sync | Pod copy changed | Result |
|---|---|---|
| no | no | nothing |
| yes | no | master value is pushed into the rebuilt scoped vault |
| no | yes | pod's password is written into the master |
| yes | yes | the later modification time wins; ties keep the master; reported under `resolved` |

The pod's file is untrusted input, so also:

- only `writable` entries that already exist in the master and are inside `entries` are
  considered, and only their `Password`; added entries and other edits are `ignored`;
- a pod timestamp more than 5 minutes in the future (or unreadable) is not believed: the master
  is kept and it is listed as a `conflict`, so a compromised pod cannot win by faking its clock;
- each version of the pod's file is consumed once, and a copy older than the last build is
  skipped, so a stale copy cannot undo a newer master value.

### Transport: how the pod's vault reaches the host

Set `writeback = "secret"` on the scope (recommended). The cluster then holds one extra object
per scope, the **return Secret** `<secret_name>-return`:

```
host:  sync --apply ──► Secret/<name>-vault          (read-only mount in the pod)
pod :  init container copies it to an emptyDir; app edits the copy via auto-pass
pod :  auto-pass scope return --vault /work/vault.kdbx --secret <name>-vault-return
                         └─► PATCH /api/v1/namespaces/<ns>/secrets/<name>-vault-return
host:  sync ──► kubectl get secret <name>-vault-return ──► ~/.local/share/auto-pass/scopes/<name>.return.kdbx
                         └─► the policy above, then master updated, scope rebuilt, Secret re-applied
```

`scope manifest` then also emits `Role/<name>-return` bound to the pod's ServiceAccount:
`get/update/patch` on exactly `<name>-vault-return`. That is the pod's only API permission, and
it needs `automountServiceAccountToken: true` **on the pod** (the ServiceAccount stays false so
no other pod using it is affected). The returned file is still encrypted with the scope's
password, and the master is only touched after the checks above.

Pod spec additions for a writable scope:

```yaml
spec:
  serviceAccountName: intake
  automountServiceAccountToken: true
  initContainers:
    - name: vault-copy
      image: busybox
      command: ["sh","-c","cp /seed/vault.kdbx /work/vault.kdbx && chmod 600 /work/vault.kdbx"]
      volumeMounts: [{name: vault, mountPath: /seed, readOnly: true}, {name: work, mountPath: /work}]
  containers:
    - name: intake
      env:
        - {name: AUTO_PASS_KEEPASSXC_DB_PATH, value: /work/vault.kdbx}
        # AUTO_PASS_KEEPASSXC_DB_PASSWORD from secretKeyRef as in section 4
      volumeMounts: [{name: work, mountPath: /work}]
  volumes:
    - name: vault
      secret: {secretName: intake-vault}
    - name: work
      emptyDir: {}
```

Call `auto-pass scope return --vault /work/vault.kdbx --secret intake-vault-return` after the
app changes a password (or on a timer in a sidecar). The command uses only the standard
library, the mounted token and CA, so any image with Python and `auto-pass` works.

Alternatives, if you prefer no API token in the pod: `writeback = "path"` with `writeback_path`
set to a host path the pod's PVC writes to (K3s local-path volumes live under
`/var/lib/rancher/k3s/storage/`, which is root-only, so you would need an ACL), or fetch with
`kubectl cp`/`exec` from a timer (needs `tar`/`cat` in the image and `pods/exec` RBAC, which is
broader than one named Secret). The return Secret is the narrowest of the three.

Limit: a Secret holds 1 MiB, so the vault must stay under about 700 KB.

## 6. Splitting out common and merging everything into the master

```bash
auto-pass consolidate --common            # plan only
auto-pass consolidate --common --apply    # backups, then do it
```

1. The master's current contents (except `auto-pass/` bookkeeping and anything already merged)
   are copied into a new `common.kdbx` next to the master, with a random password stored in the
   master as `vaults/common.kdbx`, and `common` is added to `config/keepass-dbs.local.json`.
2. Every sub-vault (`common`, `infra`, `finance`, `totp`, ...) is merged into the master under
   a top-level group named after its alias, so the master holds `common/`, `infra/`,
   `finance/` and `totp/`.

It is additive and idempotent: nothing is removed from the master, so existing consumers and the
sub-vault passwords under `vaults/` keep working. Remove the original top-level entries only
after every consumer and allowlist has moved to the prefixed paths. `common/` includes the
copies of the sub-vault passwords (`common/vaults/*`), so never give a scope a glob that matches
them. Backups are written as `*.bak-<timestamp>` (gitignored).

## Limits

- Attachments are copied but not size-checked; large ones inflate the Secret (1 MiB limit).
- A scoped vault is a snapshot. Revoking an entry from a scope takes effect at the next
  `sync --apply`; a pod that already read the old file keeps what it read.
- `scope verify` needs a live cluster; unit tests cover the manifests, not API-server admission.
