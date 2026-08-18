"""
Generic scan orchestration for CycloneDX-based vulnerability scanners.

New scanner extensions call `run_scan()` from their `__main__.py` instead of
re-implementing the orchestration steps themselves. Only the subprocess invocation
(the Scanner object) is scanner-specific.
"""

import abc
import dataclasses
import datetime
import json
import logging

import ocm.iter

import k8s.util
import odg.extensions_cfg
import odg.findings
import odg.model
import odg_client
import scanner_utils.cyclonedx
import scanner_utils.findings
import scanner_utils.model

logger = logging.getLogger(__name__)


class SbomNotAvailable(Exception):
    """
    Raised when the scanner requires an SBOM (scan_target=SBOM or SBOM_WITH_BINARY_FALLBACK)
    but none has been generated yet for this artefact.

    Callers should requeue the backlog item with a delay to allow the sbom_generator job
    to complete before retrying.
    """


class Scanner(abc.ABC):
    """
    Interface that a scanner extension must implement.

    Each method receives an already-resolved `resource_node` (the OCM resource with its
    component context) so the scanner never has to deal with OCM lookup itself.

    `oci_client` is passed through to access OCI artefacts.
    For binary scans of OCI images the scanner uses `oci_client.credentials_lookup` to obtain
    `username`/`password` and passes them to the CLI.
    For local or OCI blobs the scanner streams the blob bytes through `oci_client.blob()`.
    """

    def scan_binary(
        self,
        resource_node: ocm.iter.ResourceNode,
        oci_client: object,
    ) -> dict:
        """
        Run a direct binary/image scan and return the CycloneDX JSON document as a dict.

        Called when `scan_target` is BINARY or as the fallback in SBOM_WITH_BINARY_FALLBACK
        when no SBOM is available.
        """
        raise NotImplementedError(f'{type(self).__name__} does not support binary scanning')

    def scan_sbom(self, sbom_cyclonedx: dict) -> dict:
        """
        Re-scan an existing CycloneDX SBOM and return a new CycloneDX JSON document.

        Called when `scan_target` is SBOM or SBOM_WITH_BINARY_FALLBACK (primary path).
        """
        raise NotImplementedError(f'{type(self).__name__} does not support SBOM scanning')


def run_scan(
    artefact: odg.model.ComponentArtefactId,
    extension_cfg,
    vulnerability_cfg: odg.findings.Finding | None,
    component_descriptor_lookup,
    delivery_service_client: odg_client.DeliveryServiceClient,
    oci_client,
    scanner: Scanner,
    datasource: odg.model.Datasource,
    **kwargs,
) -> None:
    """
    Generic orchestration loop for a CycloneDX-based vulnerability scanner.

    artefact: The backlog item being processed — identifies the OCM component + resource
    extension_cfg: Scanner-specific configuration (e.g. `TrivyConfig`)
    vulnerability_cfg: Determines which CVSS score ranges produce findings and label-based exclusion rules
    component_descriptor_lookup: Resolve an OCM `ComponentIdentity` → `ComponentDescriptor`
    delivery_service_client: Client for the ODG delivery service API
    oci_client: Authenticated OCI client (`oci.client.Client`)
    scanner: Implementation of the `Scanner` interface
    datasource: `odg.model.Datasource` enum value for this scanner (e.g. `Datasource.TRIVY`).
        Used as the primary key namespace for all DB records written by this scanner
    """
    if not vulnerability_cfg or not vulnerability_cfg.matches(artefact):
        logger.debug(f'vulnerability finding cfg filters out {artefact=}, skipping')
        return

    if not extension_cfg.is_supported(artefact_kind=artefact.artefact_kind):
        if extension_cfg.on_unsupported is odg.extensions_cfg.WarningVerbosities.FAIL:
            raise TypeError(
                f'{artefact.artefact_kind} is not supported by {datasource}, '
                'adjust filter configuration to exclude this artefact kind',
            )
        return

    resource_node = k8s.util.get_ocm_node(
        component_descriptor_lookup=component_descriptor_lookup,
        artefact=artefact,
    )
    access = resource_node.resource.access

    if not extension_cfg.is_supported(access_type=access.type):
        if extension_cfg.on_unsupported is odg.extensions_cfg.WarningVerbosities.FAIL:
            raise TypeError(
                f'{access.type} is not supported by {datasource}, '
                'adjust filter configuration to exclude this access type',
            )
        return

    scan_target = extension_cfg.scan_target
    cyclonedx: dict | None = None

    if scan_target in (
        scanner_utils.model.ScanningMode.SBOM,
        scanner_utils.model.ScanningMode.SBOM_WITH_BINARY_FALLBACK,
    ):
        sbom = _fetch_sbom(delivery_service_client=delivery_service_client, artefact=artefact)
        if sbom is not None:
            cyclonedx = scanner.scan_sbom(sbom)

        if sbom is None:
            if scan_target is scanner_utils.model.ScanningMode.SBOM:
                logger.warning('no SBOM available for %s, raising SbomNotAvailable', artefact)
                raise SbomNotAvailable(artefact)
            logger.debug('no SBOM available for %s, falling back to binary scan', artefact)

    if cyclonedx is None:
        cyclonedx = scanner.scan_binary(resource_node=resource_node, oci_client=oci_client)

    findings = list(
        scanner_utils.cyclonedx.parse_vulnerability_findings(
            cyclonedx=cyclonedx,
            vulnerability_cfg=vulnerability_cfg,
        ),
    )

    finding_artefact_ref = odg.model.component_artefact_id_from_ocm(
        component=resource_node.component,
        artefact=resource_node.resource,
    )
    finding_artefact_ref = dataclasses.replace(finding_artefact_ref, component_version=None)

    existing = {
        ef.data.key: ef
        for ef in scanner_utils.findings.iter_existing_findings(
            delivery_service_client=delivery_service_client,
            resource_node=resource_node,
            finding_type=odg.model.Datatype.VULNERABILITY_FINDING,
            datasource=datasource,
        )
    }

    now = datetime.datetime.now(tz=datetime.timezone.utc)
    ams = [
        odg.model.ArtefactMetadata(
            artefact=finding_artefact_ref,
            meta=odg.model.Metadata(
                datasource=datasource,
                type=odg.model.Datatype.VULNERABILITY_FINDING,
                creation_date=now,
            ),
            data=f,
            discovery_date=now.date(),
        )
        for f in findings
    ]

    scan_info = scanner_utils.findings.make_artefact_scan_info(
        resource_node=resource_node,
        datasource=datasource,
    )

    delivery_service_client.update_metadata(data=[scan_info] + ams)
    scanner_utils.findings.delete_stale_findings(
        existing_findings_by_key=existing,
        current_findings=ams,
        delivery_service_client=delivery_service_client,
    )

    logger.debug(f'finished scan of {artefact}')


def _fetch_sbom(
    delivery_service_client: odg_client.DeliveryServiceClient,
    artefact: odg.model.ComponentArtefactId,
) -> dict | None:
    entries = delivery_service_client.query_metadata(
        artefacts=[artefact],
        type=odg.model.Datatype.ARTEFACT_SCAN_INFO,
        datasource=odg.model.Datasource.SBOM_GENERATOR,
    )
    if not entries:
        return None
    digest = entries[0].get('data', {}).get('digest')
    if not digest:
        return None
    sbom_bytes = delivery_service_client.get_blob(digest=digest)
    return json.loads(sbom_bytes)
