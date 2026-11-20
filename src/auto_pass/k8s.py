"""Kubernetes (K3s) side of scoped vaults: RBAC manifests, Secret delivery, isolation checks.

Two rules shape everything here:

* A pod gets its vault through a Secret volume, which the kubelet mounts. The pod's own
  ServiceAccount therefore needs *no* API permissions, and is created with token automount off.
* Only the ``auto-pass`` sync identity may write the Secrets, and only the named ones. Secret
  data is piped to ``kubectl`` on stdin and never written to disk or into a manifest.
"""

from __future__ import annotations

import base64
import json
import os
import ssl
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from .scopes import Scope, ScopeConfig

_SA_DIR = Path("/var/run/secrets/kubernetes.io/serviceaccount")
MAX_RETURN_BYTES = 700_000  # a Secret holds 1 MiB; base64 adds a third

MANAGED_BY = {"app.kubernetes.io/managed-by": "auto-pass"}
KDBX_KEY = "vault.kdbx"
PASSWORD_KEY = "password"


class K8sError(RuntimeError):
    """Raised when kubectl is missing or refuses a request."""


# ----------------------------------------------------------------------
# Manifests (no secret material)
# ----------------------------------------------------------------------


def _yaml(value: object, indent: int = 0) -> str:
    pad = "  " * indent
    if isinstance(value, dict):
        if not value:
            return "{}"
        lines = []
        for key, val in value.items():
            if isinstance(val, (dict, list)) and val:
                lines.append(f"{pad}{key}:\n{_yaml(val, indent + 1)}")
            else:
                lines.append(f"{pad}{key}: {_yaml(val)}")
        return "\n".join(lines)
    if isinstance(value, list):
        if not value:
            return "[]"
        lines = []
        for item in value:
            if isinstance(item, dict) and item:
                body = _yaml(item, indent + 1).split("\n")
                lines.append(f"{pad}- {body[0].lstrip()}")
                lines.extend(body[1:])
            else:
                lines.append(f"{pad}- {_yaml(item)}")
        return "\n".join(lines)
    if isinstance(value, bool):
        return "true" if value else "false"
    return json.dumps(value)  # JSON scalars are valid YAML (and quote every string safely)


def _subject(cfg: ScopeConfig) -> dict:
    subject = {"kind": cfg.sync_kind, "name": cfg.sync_name}
    if cfg.sync_kind == "ServiceAccount":
        subject["namespace"] = cfg.sync_namespace
    else:
        subject["apiGroup"] = "rbac.authorization.k8s.io"
    return subject


def _meta(name: str, namespace: str = "") -> dict:
    meta: dict = {"name": name}
    if namespace:
        meta["namespace"] = namespace
    meta["labels"] = dict(MANAGED_BY)
    return meta


def scope_documents(scope: Scope, cfg: ScopeConfig, *, with_namespace: bool = False) -> list[dict]:
    """Namespace (optional), pod ServiceAccount and the sync identity's Role and binding."""
    ns = scope.namespace
    docs: list[dict] = []
    if with_namespace:
        meta = _meta(ns)
        meta["labels"] = {
            **meta["labels"],
            "pod-security.kubernetes.io/enforce": cfg.pod_security,
        }
        docs.append({"apiVersion": "v1", "kind": "Namespace", "metadata": meta})
    docs.append(
        {
            "apiVersion": "v1",
            "kind": "ServiceAccount",
            "metadata": _meta(scope.name, ns),
            # The pod reads its vault from a mounted Secret; it never needs the API.
            "automountServiceAccountToken": False,
        }
    )
    sync_names = [scope.secret_name]
    if scope.writeback == "secret":
        sync_names.append(scope.return_secret)
    docs.append(
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "Role",
            "metadata": _meta("auto-pass-sync", ns),
            "rules": [
                # `create` cannot be limited by resourceNames; the rest can.
                {"apiGroups": [""], "resources": ["secrets"], "verbs": ["create"]},
                {
                    "apiGroups": [""],
                    "resources": ["secrets"],
                    "resourceNames": sync_names,
                    "verbs": ["get", "update", "patch"],
                },
            ],
        }
    )
    docs.append(
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "RoleBinding",
            "metadata": _meta("auto-pass-sync", ns),
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "Role",
                "name": "auto-pass-sync",
            },
            "subjects": [_subject(cfg)],
        }
    )
    if scope.writeback == "secret":
        # The one API permission a pod gets: replace its own return Secret, nothing else.
        docs.append(
            {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "Role",
                "metadata": _meta(f"{scope.name}-return", ns),
                "rules": [
                    {
                        "apiGroups": [""],
                        "resources": ["secrets"],
                        "resourceNames": [scope.return_secret],
                        "verbs": ["get", "update", "patch"],
                    }
                ],
            }
        )
        docs.append(
            {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "RoleBinding",
                "metadata": _meta(f"{scope.name}-return", ns),
                "roleRef": {
                    "apiGroup": "rbac.authorization.k8s.io",
                    "kind": "Role",
                    "name": f"{scope.name}-return",
                },
                "subjects": [{"kind": "ServiceAccount", "name": scope.name, "namespace": ns}],
            }
        )
    return docs


def system_documents(cfg: ScopeConfig) -> list[dict]:
    """The sync identity itself, when it is a ServiceAccount."""
    if cfg.sync_kind != "ServiceAccount":
        return []
    return [
        {"apiVersion": "v1", "kind": "Namespace", "metadata": _meta(cfg.sync_namespace)},
        {
            "apiVersion": "v1",
            "kind": "ServiceAccount",
            "metadata": _meta(cfg.sync_name, cfg.sync_namespace),
        },
    ]


def render_manifests(scopes: list[Scope], cfg: ScopeConfig, *, with_namespace: bool = False) -> str:
    docs = system_documents(cfg)
    for scope in scopes:
        docs.extend(scope_documents(scope, cfg, with_namespace=with_namespace))
    return "---\n" + "\n---\n".join(_yaml(d) for d in docs) + "\n"


# ----------------------------------------------------------------------
# kubectl
# ----------------------------------------------------------------------


def _kubectl(
    cfg: ScopeConfig, args: list[str], stdin: str = ""
) -> subprocess.CompletedProcess[str]:
    cmd = list(cfg.kubectl)
    if cfg.kubeconfig:
        cmd.append(f"--kubeconfig={cfg.kubeconfig}")
    cmd.extend(args)
    try:
        return subprocess.run(  # noqa: S603
            cmd, input=stdin, capture_output=True, text=True, timeout=60, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise K8sError(f"kubectl failed: {exc}") from exc


def secret_object(scope: Scope, kdbx_bytes: bytes, password: str, digest: str) -> dict:
    return {
        "apiVersion": "v1",
        "kind": "Secret",
        "type": "Opaque",
        "metadata": {
            "name": scope.secret_name,
            "namespace": scope.namespace,
            "labels": dict(MANAGED_BY),
            "annotations": {"auto-pass/digest": digest[:16]},
        },
        "data": {
            KDBX_KEY: base64.b64encode(kdbx_bytes).decode(),
            PASSWORD_KEY: base64.b64encode(password.encode()).decode(),
        },
    }


def apply_secret(
    scope: Scope, cfg: ScopeConfig, kdbx_bytes: bytes, password: str, digest: str
) -> None:
    """Create or update the scope's Secret, with the data passed on stdin only."""
    body = json.dumps(secret_object(scope, kdbx_bytes, password, digest))
    result = _kubectl(cfg, ["apply", "-f", "-"], stdin=body)
    if result.returncode != 0:
        detail = (result.stderr or "").strip().splitlines()
        raise K8sError(f"apply of {scope.namespace}/{scope.secret_name} failed: {detail[-1:]}")


@dataclass(frozen=True)
class Check:
    ok: bool
    subject: str
    action: str
    expected: str
    got: str

    def as_dict(self) -> dict:
        return {
            "ok": self.ok,
            "subject": self.subject,
            "action": self.action,
            "expected": self.expected,
            "got": self.got,
        }


def _can_i(cfg: ScopeConfig, verb: str, secret: str, namespace: str, as_who: str) -> str:
    result = _kubectl(
        cfg,
        ["auth", "can-i", verb, f"secret/{secret}", "-n", namespace, f"--as={as_who}"],
    )
    answer = (result.stdout or "").strip().lower()
    if answer in {"yes", "no"}:
        return answer
    raise K8sError(f"auth can-i failed: {(result.stderr or '').strip()[-200:]}")


def verify_isolation(scopes: list[Scope], cfg: ScopeConfig) -> list[Check]:
    """Ask the API server (by impersonation) who can read and write each scope's Secret.

    Needs an identity allowed to impersonate; the host admin kubeconfig has it.
    Every pod ServiceAccount must be denied every scope's Secret, and the sync identity must
    be allowed to update exactly those Secrets.
    """
    checks: list[Check] = []
    sync_who = (
        f"system:serviceaccount:{cfg.sync_namespace}:{cfg.sync_name}"
        if cfg.sync_kind == "ServiceAccount"
        else cfg.sync_name
    )
    for target in scopes:
        for actor in scopes:
            who = f"system:serviceaccount:{actor.namespace}:{actor.name}"
            for verb in ("get", "update"):
                got = _can_i(cfg, verb, target.secret_name, target.namespace, who)
                checks.append(
                    Check(
                        got == "no",
                        f"{actor.namespace}/{actor.name}",
                        f"{verb} secret {target.namespace}/{target.secret_name}",
                        "no",
                        got,
                    )
                )
        got = _can_i(cfg, "update", target.secret_name, target.namespace, sync_who)
        checks.append(
            Check(
                got == "yes",
                sync_who,
                f"update secret {target.namespace}/{target.secret_name}",
                "yes",
                got,
            )
        )
    return checks


# ----------------------------------------------------------------------
# Return transport (pod -> host), via a per-scope "return" Secret
# ----------------------------------------------------------------------


def ensure_return_secret(scope: Scope, cfg: ScopeConfig) -> bool:
    """Create the empty return Secret if it does not exist. True if it was created."""
    probe = _kubectl(cfg, ["get", "secret", scope.return_secret, "-n", scope.namespace])
    if probe.returncode == 0:
        return False
    body = {
        "apiVersion": "v1",
        "kind": "Secret",
        "type": "Opaque",
        "metadata": {
            "name": scope.return_secret,
            "namespace": scope.namespace,
            "labels": dict(MANAGED_BY),
        },
        "data": {},
    }
    result = _kubectl(cfg, ["create", "-f", "-"], stdin=json.dumps(body))
    if result.returncode != 0:
        raise K8sError(f"could not create {scope.namespace}/{scope.return_secret}")
    return True


def pull_return(scope: Scope, cfg: ScopeConfig, dest: Path) -> bool:
    """Fetch the pod's returned vault to ``dest`` (0600). True if there is new content."""
    result = _kubectl(
        cfg,
        ["get", "secret", scope.return_secret, "-n", scope.namespace, "-o", "json"],
    )
    if result.returncode != 0:
        raise K8sError(f"cannot read {scope.namespace}/{scope.return_secret}")
    blob = (json.loads(result.stdout).get("data") or {}).get(KDBX_KEY, "")
    if not blob:
        return False
    data = base64.b64decode(blob)
    if dest.is_file() and dest.read_bytes() == data:
        return False
    dest.parent.mkdir(parents=True, exist_ok=True)
    part = dest.with_name(dest.name + ".part")
    fd = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    os.replace(part, dest)
    return True


def push_return(vault: Path, secret_name: str, namespace: str = "") -> None:
    """Run inside the pod: store the modified vault in the return Secret via the API.

    Uses only the pod's mounted ServiceAccount token and the standard library, so it works in
    any image that has Python. The token is allowed to patch that one Secret and nothing else.
    """
    data = vault.read_bytes()
    if len(data) > MAX_RETURN_BYTES:
        raise K8sError(f"vault is {len(data)} bytes; the return Secret holds {MAX_RETURN_BYTES}")
    try:
        token = (_SA_DIR / "token").read_text().strip()
        ns = namespace or (_SA_DIR / "namespace").read_text().strip()
    except OSError as exc:
        raise K8sError(
            "no ServiceAccount token: set automountServiceAccountToken: true on this pod"
        ) from exc
    host = os.environ.get("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc")
    port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
    url = f"https://{host}:{port}/api/v1/namespaces/{ns}/secrets/{secret_name}"
    request = urllib.request.Request(  # noqa: S310
        url,
        data=json.dumps({"data": {KDBX_KEY: base64.b64encode(data).decode()}}).encode(),
        method="PATCH",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/merge-patch+json",
        },
    )
    context = ssl.create_default_context(cafile=str(_SA_DIR / "ca.crt"))
    try:
        urllib.request.urlopen(request, context=context, timeout=30).close()  # noqa: S310
    except urllib.error.HTTPError as exc:
        raise K8sError(f"API server refused the update: HTTP {exc.code}") from exc
    except OSError as exc:
        raise K8sError(f"could not reach the API server: {exc}") from exc
