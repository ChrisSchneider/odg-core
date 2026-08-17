import collections.abc
import logging

import odg.cvss
import odg.findings
import odg.model


logger = logging.getLogger(__name__)

# Preferred source order when multiple CVSS ratings are present.
_PREFERRED_SOURCES = ('nvd', 'redhat', 'ghsa')

_SEVERITY_FALLBACK: dict[str, float] = {
    'critical': 9.5,
    'high': 8.0,
    'medium': 5.0,
    'low': 2.0,
}


def _strip_cvss_prefix(vector: str) -> str:
    # "CVSS:3.1/AV:N/..." → "AV:N/..."  (CVSSV3.parse expects no prefix token)
    if vector.startswith('CVSS:') and '/' in vector:
        return vector.split('/', 1)[1]
    return vector


def _pick_rating(ratings: list[dict]) -> dict | None:
    """
    Return the best rating from a CycloneDX vulnerability's ratings array.

    Preference order: nvd → redhat → ghsa → first CVSSv3 → first rating of any method.
    Non-v3 ratings are accepted for their score; their vector will not be parsed.
    """
    if not ratings:
        return None

    cvssv3 = [r for r in ratings if 'v3' in (r.get('method') or '').lower()]

    for source in _PREFERRED_SOURCES:
        for r in cvssv3:
            if (r.get('source') or {}).get('name', '').lower() == source:
                return r

    if cvssv3:
        return cvssv3[0]

    return ratings[0]


def parse_vulnerability_findings(
    cyclonedx: dict,
    vulnerability_cfg: odg.findings.Finding,
) -> collections.abc.Generator[odg.model.VulnerabilityFinding, None, None]:
    """
    Parse a CycloneDX JSON document and yield one VulnerabilityFinding per affected component.

    A vulnerability that affects N components yields N findings (same CVE, different package).
    Skips findings where categorise_finding() returns None (outside configured score ranges).
    Falls back to _SEVERITY_FALLBACK when no numeric score is present.

    cyclonedx: Parsed CycloneDX JSON document (as returned by the scanner CLI)
    vulnerability_cfg: Finding config — determines score thresholds and label-based exclusions
    """
    components_by_ref: dict[str, dict] = {
        c['bom-ref']: c
        for c in cyclonedx.get('components') or []
        if c.get('bom-ref')
    }

    for vuln in cyclonedx.get('vulnerabilities') or []:
        cve = vuln.get('id', '')
        description = vuln.get('description')
        recommendation = vuln.get('recommendation')
        urls = [a['url'] for a in (vuln.get('advisories') or []) if a.get('url')]

        rating = _pick_rating(vuln.get('ratings') or [])
        if rating:
            cvss_score = rating.get('score')
            raw_vector = rating.get('vector')
            rating_source = (rating.get('source') or {}).get('name')
        else:
            cvss_score = None
            raw_vector = None
            rating_source = (vuln.get('source') or {}).get('name')

        # Fall back to severity string when no numeric score is available.
        if cvss_score is None:
            severity_str = (rating or {}).get('severity', '')
            cvss_score = _SEVERITY_FALLBACK.get(severity_str.lower())

        if cvss_score is None:
            logger.debug('skipping %s: no score and unrecognised severity', cve)
            continue

        categorisation = odg.findings.categorise_finding(
            finding_cfg=vulnerability_cfg,
            finding_property=cvss_score,
        )
        if not categorisation:
            continue

        cvss: odg.cvss.CVSSV3 | None = None
        if raw_vector and rating and 'v3' in (rating.get('method') or '').lower():
            try:
                cvss = odg.cvss.CVSSV3.parse(_strip_cvss_prefix(raw_vector))
            except (ValueError, KeyError):
                logger.debug('could not parse CVSS vector %r for %s', raw_vector, cve)

        affects = vuln.get('affects') or []
        if not affects:
            logger.warning('skipping %s: no affected components listed', cve)
            continue

        for affect in affects:
            ref = affect.get('ref', '')
            component = components_by_ref.get(ref, {})
            yield odg.model.VulnerabilityFinding(
                severity=categorisation.id,
                package_name=component.get('name', ref),
                package_version=component.get('version'),
                cve=cve,
                purl=component.get('purl'),
                cvss_score=cvss_score,
                cvss=cvss,
                rating_source=rating_source,
                summary=description,
                recommendation=recommendation,
                urls=list(urls),
            )