---
name: odg-create-scanner
description: Scaffold a new CycloneDX-based vulnerability scanner extension
---
You are scaffolding a new vulnerability scanner extension for ODG (Open Delivery Gear).

Start by briefly introducing what you are about to build together, so the user has context before
answering the setup questions. Explain:

- A scanner extension is a self-contained Python package (`src/SCANNER_extension/`) that wraps a
  CLI-based vulnerability scanner and feeds its results into ODG as `VulnerabilityFinding` records.
- It integrates via the standard backlog/orchestrator pattern: the artefact enumerator creates
  backlog items, the extension processes them by calling the scanner CLI, and `scanner_utils`
  converts the CycloneDX output into findings stored in the delivery-db.
- The end result includes: `scanner.py` (subprocess wrapper), `__main__.py` (entry point), a Helm
  chart, and wiring in `model.py`, `extensions_cfg.py`, and `artefact_enumerator.py`.

Then ask the user for:
1. Scanner name (e.g. "trivy", "grype") — used for package names, class names, and the datasource key
2. Scanner CLI install snippet for the Dockerfile (or "skip" if not needed yet)
3. Which scanning modes to support: binary, sbom, sbom_with_binary_fallback (default: all three)

Then implement the following, replacing SCANNER with the scanner name and SCANNER_NAME with its
camelCase Services enum value:

## 1. src/odg/model.py

Add `SCANNER = 'scanner'` to the `Datasource` StrEnum (keep alphabetical order), and add
`Datasource.SCANNER: (Datatype.VULNERABILITY_FINDING,)` to `Datasource.datatypes()`.

## 2. src/odg/extensions_cfg.py

- Add `SCANNER_NAME = 'scannerName'` to `Services` StrEnum (keep alphabetical order)
- Add `ScannerMapping(Mapping)` dataclass — inherits `prefix: str`; no extra fields unless needed
- Add `ScannerConfig(BacklogItemMixins)`:

  ```python
  @dataclasses.dataclass(kw_only=True)
  class ScannerConfig(BacklogItemMixins):
      service: Services = Services.SCANNER_NAME
      delivery_service_url: str
      mappings: list[ScannerMapping] = dataclasses.field(default_factory=list)
      interval: int = 60 * 60 * 24
      on_unsupported: WarningVerbosities = WarningVerbosities.WARNING
      scan_target: scanner_utils.model.ScanningMode = scanner_utils.model.ScanningMode.SBOM_WITH_BINARY_FALLBACK

      def is_supported(self, artefact_kind=None, access_type=None, artefact_type=None) -> bool:
          # Supported artefact_kind: ArtefactKind.RESOURCE
          # Supported access_types: OCI_REGISTRY, LOCAL_BLOB, OCI_BLOB
          # Supported artefact_types: BLOB, DIRECTORY_TREE, EXECUTABLE, OCI_ARTEFACT, OCI_IMAGE, SBOM
          # Log warning or raise per on_unsupported for artefact_kind/access_type
          # Log debug for unsupported artefact_type (not warning — these are silently skipped)
  ```

- Add `scanner: ScannerConfig | None = None` to `ExtensionsConfiguration`
- Add `('scanner_name', self.scanner)` to the `vuln_scanners` list inside `__post_init__`
- Add a `vulnerability_scanner_datasource` property to `ExtensionsConfiguration`:

  ```python
  @property
  def vulnerability_scanner_datasource(self) -> odg.model.Datasource | None:
      if self.bdba and self.bdba.enabled:
          return odg.model.Datasource.BDBA
      if self.scanner and self.scanner.enabled:
          return odg.model.Datasource.SCANNER
      return None
  ```

## 3. .devcontainer/Dockerfile

Add the CLI install snippet. For scanners distributed as a Docker image use a multi-stage COPY:
```dockerfile
COPY --from=vendor/scanner:latest /usr/local/bin/scanner /usr/local/bin/scanner
```

## 4. src/scanner_extension/__init__.py

Empty file.

## 5. src/scanner_extension/scanner.py

Implements `scanner_utils.orchestrator.Scanner`. Override only the hooks you need — never override
`scan_ocm_resource` (the base class handles all OCM/OCI/S3 dispatch via `ocm_util.iter_blob_descriptors`).

### Hook signatures

```python
def scan_oci_image(self, image_reference: str) -> dict
    # OCI_REGISTRY access — pass ref directly to CLI

def scan_oci_image_archive(self, path: str, blob: ocm_util.BlobDescriptor) -> dict
    # LOCAL_BLOB/OCI_BLOB whose mediaType is an OCI image tar (ASAF)
    # blob.media_type has the mediaType; path is already written to disk

def scan_file(self, path: str, blob: ocm_util.BlobDescriptor, is_tar: bool) -> dict
    # All other LOCAL_BLOB/OCI_BLOB/S3 content
    # is_tar pre-computed by base class via ocm_util.is_tar_archive
    # blob.media_type, blob.name, blob.digest available if needed

def scan_sbom(self, data: dict) -> dict
    # Existing SBOM (CycloneDX or SPDX) as a parsed dict
```

### Stream overrides (optional)

The base class writes blobs to disk before calling `scan_oci_image_archive` / `scan_file`.
Override `scan_oci_image_archive_stream(blob)` or `scan_file_stream(blob, is_tar)` to consume
the stream directly and skip the temp file.

### Temp file hygiene

- Archive extraction: `tempfile.TemporaryDirectory()` as a context manager (auto-cleaned)
- Single temp file a subprocess must read: `NamedTemporaryFile(delete=False)` + `os.unlink` in `finally`
- The base class already handles temp file creation and cleanup for the blob-to-disk step
- Use `filter='data'` with `tarfile.extractall()` (required in Python 3.12+)

### ScannerImpl structure

```python
import dataclasses
import json
import subprocess

import ocm_util
import scanner_utils.orchestrator


@dataclasses.dataclass
class ScannerImpl(scanner_utils.orchestrator.Scanner):
    def scan_oci_image(self, image_reference: str) -> dict:
        return _run_scanner([image_reference])

    def scan_oci_image_archive(self, path: str, blob: ocm_util.BlobDescriptor) -> dict:
        return _run_scanner(['--input', path])

    def scan_file(self, path: str, blob: ocm_util.BlobDescriptor, is_tar: bool) -> dict: ...

    def scan_sbom(self, data: dict) -> dict: ...


def _run_scanner(args: list[str], timeout: int = 600) -> dict:
    result = subprocess.run(
        ['scanner', '--format', 'cyclonedx'] + args,
        capture_output=True,
        check=False,
        timeout=timeout,
    )
    if result.returncode != 0:
        logger.error(f'scanner failed (exit {result.returncode}):\n{result.stderr.decode()}')
        result.check_returncode()
    return json.loads(result.stdout)
```

After implementing the scanner, ask the user whether they want unit tests written for it. If yes,
write `src/test/test_scanner_extension.py` covering the implemented methods, for example:

- **`scan_sbom`** — pass a minimal CycloneDX dict (with at least one component that has a known
  CVE purl) and assert the returned dict contains the expected vulnerability findings.
- **`scan_file`** — call with different `blob.media_type` values, stored at a `tmp_path` fixture:
  - an executable (`application/octet-stream`) with a known CVE
  - a plain text file
- **`scan_oci_image`** — pass a well-known public image reference with a known CVE
- **`scan_oci_image_archive`** — write a minimal OCI image with a well-known CVE as tar to a `tmp_path` fixture

First run these tests without mocking `_run_scanner` until the scanner produces the expected results. Then rewrite them to use `unittest.mock.patch` to mock `_run_scanner` (or `subprocess.run`) so tests do not require
the scanner binary or actual artifact downloads. Keep fixtures minimal — a two-component CycloneDX dict is enough for SBOM
tests.

## 6. src/scanner_extension/__main__.py

```python
import functools

import odg.extensions_cfg
import odg.findings
import odg.model
import odg.util
import paths
import scanner_extension.scanner
import scanner_utils.orchestrator


def main():
    parsed_arguments = odg.util.parse_args()
    vulnerability_cfg = odg.findings.Finding.from_file(
        path=parsed_arguments.findings_cfg_path or paths.findings_cfg_path(),
        finding_type=odg.model.Datatype.VULNERABILITY_FINDING,
    )
    odg.util.process_backlog_items(
        parsed_arguments=parsed_arguments,
        service=odg.extensions_cfg.Services.SCANNER_NAME,
        callback=functools.partial(
            scanner_utils.orchestrator.run_scan,
            scanner=scanner_extension.scanner.ScannerImpl(),
            datasource=odg.model.Datasource.SCANNER,
            vulnerability_cfg=vulnerability_cfg,
        ),
    )
```

## 7. src/artefact_enumerator.py

In `_process_compliance_snapshot_of_artefact()`, add a block after the last scanner block:

```python
if (
    extensions_cfg.scanner
    and extensions_cfg.scanner.enabled
    and extensions_cfg.scanner.is_supported(artefact_kind=artefact.artefact_kind)
):
    compliance_snapshot, uncommitted_backlog_item = _create_backlog_item_for_extension(
        finding_cfgs=finding_cfgs,
        finding_types=(odg.model.Datatype.VULNERABILITY_FINDING,),
        artefact=artefact,
        compliance_snapshot=compliance_snapshot,
        service=odg.extensions_cfg.Services.SCANNER_NAME,
        interval_seconds=extensions_cfg.scanner.interval,
        now=now,
    )
    if uncommitted_backlog_item:
        uncommitted_backlog_items.append(uncommitted_backlog_item)
```

## 8. .vscode/launch.json

Add the new extension to the `options` list of the `extension` input (keep alphabetical order).

## 9. Helm chart

Four touch-points in `charts/extensions/`:

**charts/extensions/charts/SCANNER/Chart.yaml**
```yaml
apiVersion: v2
name: SCANNER
version: 0.1.0
```

**charts/extensions/charts/SCANNER/templates/SCANNER.yaml**
Copy `charts/extensions/charts/bdba/templates/bdba.yaml` verbatim and substitute:
- `$podName` → `"SCANNER"`
- Both `delivery-gear.gardener.cloud/service:` label values → `SCANNER`
- `command` → `python3 -m SCANNER_extension`
- If the scanner needs no external credentials: remove the scanner-specific secret volume (keep aws, github, github-app, kubernetes, oci-registry as optional)
- NetworkPolicy name → `allow-egress-from-SCANNER`
- `terminationGracePeriodSeconds`: `1800` for slow scanners (binary pulls), `300` for SBOM-only

**charts/extensions/Chart.yaml** — add dependency (alphabetical):
```yaml
- name: SCANNER
  repository: file://charts/SCANNER
  condition: SCANNER.enabled
```

**charts/extensions/values.yaml** — add stanza (alphabetical):
```yaml
SCANNER:
  deployment:
    annotations: []
    resources:
      requests:
        memory: 300Mi
        cpu: 250m
      limits:
        memory: 1Gi
  enabled: false
```

## Key rules

- Emit `odg.model.VulnerabilityFinding` — NOT `BDBAVulnerabilityFinding`
- `scanner.py` only runs subprocesses — all finding logic is in `scanner_utils`
- `__main__.py` only wires config and calls `run_scan` — no orchestration logic
- Do NOT emit RESCORING or SCANNER_WRITEBACK records
- Always pass `datasource` explicitly — never use `Datatype.datasource()`
- Only one vulnerability scanner (bdba or the new one) may be enabled at a time
- Never override `scan_ocm_resource` — it is the base class dispatch method
- Blob fetching (OCI, LOCAL_BLOB, S3) is handled by `ocm_util.iter_blob_descriptors` inside `scan_ocm_resource`; hooks only receive an already-fetched path or blob descriptor

After creating all files, run `uv run python -m pytest src/test/ -q` and fix any failures.
