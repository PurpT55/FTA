"""Test helpers: build tiny evidence folders from dicts and run single analysers."""
from __future__ import annotations

import json
import os
import tempfile

from droidtriage.evidence import Evidence
from droidtriage.iocs import IocDb
from droidtriage.model import Context, Options

TRUSTED = {"com.android.vending"}
ECHAP_SNIPPET = """- name: TheTruthSpy
  names:
  - Copy9
  type: stalkerware
  packages:
  - com.systemservice
  certificates:
  - 31A6ECECD97CF39BC4126B8745CD94A7C30BF81C
  websites:
  - copy9.com
  c2:
    ips:
    - 69.64.74.239
    domains:
    - api.thetruth.example
"""


def evidence_dir(files: dict[str, object]) -> str:
    """Write ``{relative path: str|bytes|dict|list}`` into a temp folder; dict/list are JSON-encoded."""
    root = tempfile.mkdtemp(prefix="dt_")
    for rel, content in files.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if isinstance(content, (dict, list)):
            content = json.dumps(content)
        mode = "wb" if isinstance(content, bytes) else "w"
        with open(path, mode) as fh:
            fh.write(content)
    return root


def iocs() -> IocDb:
    db = IocDb()
    db._yaml(ECHAP_SNIPPET, "test")
    return db


def ctx_for(files: dict[str, object], db: IocDb | None = None, **opt) -> Context:
    o = Options(trusted_installers=set(TRUSTED), **opt)
    return Context(Evidence(evidence_dir(files)), db if db is not None else iocs(), o)


def app(pkg, label=None, installer="com.android.vending", system=False, launcher=True, granted=(), cert="aa", first="2020-01-01T00:00:00Z", **kw):
    """Minimal packages.json record (DroidCollector format)."""
    rec = {"package": pkg, "label": label or pkg, "installer": installer, "system": system, "hasLauncher": launcher,
           "grantedPermissions": list(granted), "requestedPermissions": list(granted), "certSha256": [cert * 32],
           "certSha1": [], "certSubjects": ["CN=Test"], "firstInstallTime": first, "lastUpdateTime": first,
           "versionName": "1.0", "targetSdk": 33, "components": []}
    rec.update(kw)
    return rec


def ids(ctx: Context, pkg: str | None = "*") -> set[str]:
    """Finding ids, optionally restricted to one package (None = device-level)."""
    return {f.id for f in ctx.findings if pkg == "*" or f.package == pkg}
