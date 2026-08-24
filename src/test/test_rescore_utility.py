import ocm
import ocm.iter
import pytest

import consts
import odg.cvss
import odg.findings
import odg.labels
import odg.model
import rescore.utility

_CVE_CATEGORISATION_VALUE = {
    'network_exposure': 'public',
    'authentication_enforced': True,
    'user_interaction': 'operator',
    'confidentiality_requirement': 'high',
    'integrity_requirement': 'high',
    'availability_requirement': 'low',
    'comment': None,
}


def _make_artefact_node(
    artefact_labels: list[ocm.Label] = (),
    component_labels: list[ocm.Label] = (),
) -> ocm.iter.ResourceNode:
    resource = ocm.Resource(
        name='test-resource',
        version='1.0.0',
        type='ociImage',
        access=None,
        labels=list(artefact_labels),
    )
    component = ocm.Component(
        name='test-component',
        version='1.0.0',
        repositoryContexts=[],
        provider='test',
        sources=[],
        componentReferences=[],
        resources=[],
        labels=list(component_labels),
    )
    return ocm.iter.ResourceNode(
        path=(ocm.iter.NodePathEntry(component=component),),
        resource=resource,
    )


# ---------------------------------------------------------------------------
# find_cve_categorisation — new label name
# ---------------------------------------------------------------------------


def test_find_cve_categorisation_from_artefact():
    label = ocm.Label(
        name='security.ocm.software/risk-profile',
        value=_CVE_CATEGORISATION_VALUE,
    )
    node = _make_artefact_node(artefact_labels=[label])
    result = rescore.utility.find_cve_categorisation(node)
    assert result is not None
    assert result.authentication_enforced is True


def test_find_cve_categorisation_from_component_fallback():
    label = ocm.Label(
        name='security.ocm.software/risk-profile',
        value=_CVE_CATEGORISATION_VALUE,
    )
    node = _make_artefact_node(component_labels=[label])
    result = rescore.utility.find_cve_categorisation(node)
    assert result is not None
    assert result.authentication_enforced is True


def test_find_cve_categorisation_artefact_label_takes_precedence():
    artefact_label = ocm.Label(
        name='security.ocm.software/risk-profile',
        value={**_CVE_CATEGORISATION_VALUE, 'authentication_enforced': False},
    )
    component_label = ocm.Label(
        name='security.ocm.software/risk-profile',
        value={**_CVE_CATEGORISATION_VALUE, 'authentication_enforced': True},
    )
    node = _make_artefact_node(artefact_labels=[artefact_label], component_labels=[component_label])
    result = rescore.utility.find_cve_categorisation(node)
    assert result.authentication_enforced is False


def test_find_cve_categorisation_not_found():
    node = _make_artefact_node()
    result = rescore.utility.find_cve_categorisation(node)
    assert result is None


# ---------------------------------------------------------------------------
# find_cve_categorisation — legacy label name (backwards compat)
# ---------------------------------------------------------------------------


def test_find_cve_categorisation_from_artefact_legacy():
    label = ocm.Label(
        name='gardener.cloud/cve-categorisation',
        value=_CVE_CATEGORISATION_VALUE,
    )
    node = _make_artefact_node(artefact_labels=[label])
    result = rescore.utility.find_cve_categorisation(node)
    assert result is not None
    assert result.authentication_enforced is True


def test_find_cve_categorisation_from_component_fallback_legacy():
    label = ocm.Label(
        name='gardener.cloud/cve-categorisation',
        value=_CVE_CATEGORISATION_VALUE,
    )
    node = _make_artefact_node(component_labels=[label])
    result = rescore.utility.find_cve_categorisation(node)
    assert result is not None
    assert result.authentication_enforced is True


def test_find_cve_categorisation_legacy_artefact_beats_new_component():
    artefact_label = ocm.Label(
        name='gardener.cloud/cve-categorisation',
        value={**_CVE_CATEGORISATION_VALUE, 'authentication_enforced': False},
    )
    component_label = ocm.Label(
        name='security.ocm.software/risk-profile',
        value={**_CVE_CATEGORISATION_VALUE, 'authentication_enforced': True},
    )
    node = _make_artefact_node(artefact_labels=[artefact_label], component_labels=[component_label])
    result = rescore.utility.find_cve_categorisation(node)
    assert result.authentication_enforced is False


# ---------------------------------------------------------------------------
# matching_rescore_rules + rescore_finding
# ---------------------------------------------------------------------------

_VULNERABILITY_CFG_RAW = [
    {
        'type': odg.model.Datatype.VULNERABILITY_FINDING,
        'categorisations': [
            {'id': 'NONE', 'display_name': 'NONE', 'value': 0},
            {
                'id': 'MEDIUM',
                'display_name': 'MEDIUM',
                'value': 2,
                'allowed_processing_time': 90,
                'rescoring': 'automatic',
                'selector': {'cve_score_range': {'min': 4.0, 'max': 6.9}},
            },
            {
                'id': 'CRITICAL',
                'display_name': 'CRITICAL',
                'value': 8,
                'allowed_processing_time': 30,
                'rescoring': 'automatic',
                'selector': {'cve_score_range': {'min': 9.0, 'max': 10.0}},
            },
        ],
        'rescoring_ruleset': {
            'name': 'test-ruleset',
            'operations': {
                'not-exploitable': f'{consts.RESCORING_OPERATOR_SET_TO_PREFIX}NONE',
                'reduce': {'order': ['CRITICAL', 'MEDIUM', 'NONE']},
            },
            'rules': [
                {
                    'category_value': 'network_exposure:public',
                    'name': 'local-only',
                    'rules': [{'cve_values': ['AV:L'], 'operation': 'not-exploitable'}],
                },
                {
                    'category_value': 'network_exposure:public',
                    'name': 'adjacent-reduces',
                    'rules': [{'cve_values': ['AV:A'], 'operation': 'reduce'}],
                },
            ],
        },
    },
]


@pytest.fixture
def vulnerability_cfg() -> odg.findings.Finding:
    return odg.findings.Finding.from_dict(
        findings_raw=_VULNERABILITY_CFG_RAW,
        finding_type=odg.model.Datatype.VULNERABILITY_FINDING,
    )


@pytest.fixture
def cve_categorisation() -> odg.cvss.CveCategorisation:
    label = ocm.Label(
        name='security.ocm.software/risk-profile',
        value={
            'network_exposure': 'public',
            'authentication_enforced': True,
            'user_interaction': 'operator',
            'confidentiality_requirement': 'high',
            'integrity_requirement': 'high',
            'availability_requirement': 'low',
            'comment': None,
        },
    )
    return odg.labels.deserialise_label(label).value


@pytest.mark.parametrize(
    'cvss_vector,cvss_score,expected_value',
    [
        ('CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 5.0, 0),  # AV:L → not-exploitable → NONE
        ('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 5.0, 2),  # AV:N → no rule match → MEDIUM
        ('CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.5, 2),  # AV:A → reduce CRITICAL → MEDIUM
    ],
)
def test_rescore_finding(
    cvss_vector,
    cvss_score,
    expected_value,
    vulnerability_cfg,
    cve_categorisation,
):
    cvss = odg.cvss.CVSSV3.parse(cvss_vector)
    categorisation = odg.findings.categorise_finding(
        finding_cfg=vulnerability_cfg,
        finding_property=cvss_score,
    )
    rules = list(
        rescore.utility.matching_rescore_rules(
            rescoring_rules=vulnerability_cfg.rescoring_ruleset.rules,
            categorisation=cve_categorisation,
            cvss=cvss,
        ),
    )
    result = rescore.utility.rescore_finding(
        finding_cfg=vulnerability_cfg,
        current_categorisation=categorisation,
        rescoring_rules=rules,
        operations=vulnerability_cfg.rescoring_ruleset.operations,
    )
    assert result.value == expected_value


def test_score_outside_all_ranges_has_no_categorisation(vulnerability_cfg):
    # score=1.0 falls below the lowest range (MEDIUM: 4.0–6.9) → None
    assert (
        odg.findings.categorise_finding(
            finding_cfg=vulnerability_cfg,
            finding_property=1.0,
        )
        is None
    )


def test_find_cve_categorisation_new_artefact_beats_legacy_component():
    artefact_label = ocm.Label(
        name='security.ocm.software/risk-profile',
        value={**_CVE_CATEGORISATION_VALUE, 'authentication_enforced': False},
    )
    component_label = ocm.Label(
        name='gardener.cloud/cve-categorisation',
        value={**_CVE_CATEGORISATION_VALUE, 'authentication_enforced': True},
    )
    node = _make_artefact_node(artefact_labels=[artefact_label], component_labels=[component_label])
    result = rescore.utility.find_cve_categorisation(node)
    assert result.authentication_enforced is False
