import collections.abc
import dataclasses
import logging

import odg.cvss
import odg.findings
import rescore.utility as ru


logger = logging.getLogger(__name__)


@dataclasses.dataclass
class VulnerabilityCandidate:
    cve: str
    cvss_score: float
    cvss_vector: str | None
    is_skippable: bool
    is_already_triaged: bool


def compute_auto_triage_cves(
    component_name: str,
    component_version: str | None,
    vulnerabilities: collections.abc.Iterable[VulnerabilityCandidate],
    vulnerability_cfg: odg.findings.Finding,
    cve_categorisation: odg.cvss.CveCategorisation,
) -> list[str]:
    """
    Return CVE IDs that should be automatically triaged to zero for a single package component.

    Returns an empty list if none qualify or if component_version is None.

    component_name: Package name (used for logging only)
    component_version: Package version; if None, no auto-triage is performed
    vulnerabilities: Candidates to evaluate — typically one per CVE for this component
    vulnerability_cfg: Finding config supplying rescoring rules and score thresholds
    cve_categorisation: CVSS categorisation data used to match rescoring rules
    """
    if not component_version:
        return []

    vulns_to_triage = []

    for v in vulnerabilities:
        if v.is_skippable or v.is_already_triaged:
            continue

        categorisation = odg.findings.categorise_finding(
            finding_cfg=vulnerability_cfg,
            finding_property=v.cvss_score,
        )

        if not categorisation or not categorisation.automatic_rescoring:
            continue

        matching_rules = ru.matching_rescore_rules(
            rescoring_rules=vulnerability_cfg.rescoring_ruleset.rules,
            categorisation=cve_categorisation,
            cvss=odg.cvss.CVSSV3.parse(v.cvss_vector),
        )

        rescored_categorisation = ru.rescore_finding(
            finding_cfg=vulnerability_cfg,
            current_categorisation=categorisation,
            rescoring_rules=matching_rules,
            operations=vulnerability_cfg.rescoring_ruleset.operations,
        )

        if rescored_categorisation.value == 0:
            vulns_to_triage.append(v.cve)

    if vulns_to_triage:
        logger.debug(
            f'auto-triage candidates for {component_name}:{component_version}: {vulns_to_triage}',
        )

    return vulns_to_triage
