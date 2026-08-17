import unittest.mock

import ocm
import ocm.iter

import odg.model
import scanner_utils.findings


def _make_resource_node(
    component_name: str = 'example.org/test',
    version: str = '1.0.0',
) -> ocm.iter.ResourceNode:
    component = ocm.Component(
        name=component_name,
        version=version,
        repositoryContexts=[],
        provider='test',
        sources=[],
        componentReferences=[],
        resources=[],
    )
    resource = ocm.Resource(
        name='test-image',
        version=version,
        type=ocm.ArtefactType.OCI_IMAGE,
        access=None,
    )
    return ocm.iter.ResourceNode(
        path=(ocm.iter.NodePathEntry(component=component),),
        resource=resource,
    )


def _make_vulnerability_finding_metadata(
    cve: str = 'CVE-2024-0001',
    package_name: str = 'pkg',
    component_version: str | None = None,
) -> odg.model.ArtefactMetadata:
    finding = odg.model.VulnerabilityFinding(
        severity='MEDIUM',
        package_name=package_name,
        package_version='1.0',
        cve=cve,
        cvss_score=5.0,
    )
    return odg.model.ArtefactMetadata(
        artefact=odg.model.ComponentArtefactId(
            component_name='example.org/test',
            component_version=component_version,
        ),
        meta=odg.model.Metadata(
            datasource=odg.model.Datasource.BDBA,
            type=odg.model.Datatype.VULNERABILITY_FINDING,
        ),
        data=finding,
    )


def _raw_artefact_metadata_dict(datasource: str = 'bdba') -> dict:
    """Minimal raw dict that round-trips through ArtefactMetadata.from_dict."""
    return {
        'artefact': {
            'component_name': 'example.org/test',
            'component_version': None,
            'artefact': {
                'artefact_name': 'test-image',
                'artefact_type': 'ociImage',
                'artefact_version': '1.0.0',
            },
            'artefact_kind': 'resource',
        },
        'meta': {
            'datasource': datasource,
            'type': 'finding/vulnerability',
            'creation_date': '2025-01-01T00:00:00+00:00',
        },
        'data': {
            'severity': 'MEDIUM',
            'package_name': 'pkg',
            'package_version': '1.0',
            'cve': 'CVE-2024-0001',
            'cvss_score': 5.0,
        },
        'discovery_date': '2025-01-01',
        'allowed_processing_time': '30d',
    }


class TestDeleteStaleFindings:
    def test_deletes_finding_absent_from_current_scan(self):
        stale = _make_vulnerability_finding_metadata(cve='CVE-2024-0001')
        live = _make_vulnerability_finding_metadata(cve='CVE-2024-0002')
        existing = {stale.key: stale, live.key: live}
        client = unittest.mock.Mock()

        scanner_utils.findings.delete_stale_findings(existing, [live], client)

        client.delete_metadata.assert_called_once_with(data=[stale])

    def test_no_deletion_when_all_findings_still_present(self):
        am = _make_vulnerability_finding_metadata()
        existing = {am.key: am}
        client = unittest.mock.Mock()

        scanner_utils.findings.delete_stale_findings(existing, [am], client)

        client.delete_metadata.assert_not_called()

    def test_no_deletion_when_both_sets_empty(self):
        client = unittest.mock.Mock()

        scanner_utils.findings.delete_stale_findings({}, [], client)

        client.delete_metadata.assert_not_called()

    def test_deletes_all_when_current_scan_empty(self):
        am1 = _make_vulnerability_finding_metadata(cve='CVE-2024-0001')
        am2 = _make_vulnerability_finding_metadata(cve='CVE-2024-0002')
        existing = {am1.key: am1, am2.key: am2}
        client = unittest.mock.Mock()

        scanner_utils.findings.delete_stale_findings(existing, [], client)

        client.delete_metadata.assert_called_once()
        deleted = client.delete_metadata.call_args.kwargs['data']
        assert set(am.key for am in deleted) == {am1.key, am2.key}

    def test_component_version_difference_does_not_cause_false_stale(self):
        # Existing findings are stored without component_version (None); current findings
        # may be built with a component_version set. The comparison must ignore this difference
        # and match on (type, data.key) only — otherwise all findings are incorrectly deleted.
        existing_am = _make_vulnerability_finding_metadata(
            cve='CVE-2024-0001',
            component_version=None,
        )
        current_am = _make_vulnerability_finding_metadata(
            cve='CVE-2024-0001',
            component_version='1.0.0',  # different artefact key, same finding content
        )
        existing = {existing_am.key: existing_am}
        client = unittest.mock.Mock()

        scanner_utils.findings.delete_stale_findings(existing, [current_am], client)

        client.delete_metadata.assert_not_called()


class TestIterExistingFindings:
    def test_queries_delivery_client_with_correct_args(self):
        node = _make_resource_node()
        client = unittest.mock.Mock()
        client.query_metadata.return_value = []

        list(
            scanner_utils.findings.iter_existing_findings(
                delivery_service_client=client,
                resource_node=node,
                finding_type=odg.model.Datatype.VULNERABILITY_FINDING,
                datasource=odg.model.Datasource.BDBA,
            ),
        )

        client.query_metadata.assert_called_once()
        kwargs = client.query_metadata.call_args.kwargs
        assert kwargs['datasource'] == odg.model.Datasource.BDBA
        assert kwargs['type'] == odg.model.Datatype.VULNERABILITY_FINDING

    def test_deserialises_returned_findings(self):
        node = _make_resource_node()
        client = unittest.mock.Mock()
        client.query_metadata.return_value = [_raw_artefact_metadata_dict()]

        results = list(
            scanner_utils.findings.iter_existing_findings(
                delivery_service_client=client,
                resource_node=node,
                finding_type=odg.model.Datatype.VULNERABILITY_FINDING,
                datasource=odg.model.Datasource.BDBA,
            ),
        )

        assert len(results) == 1
        assert isinstance(results[0], odg.model.ArtefactMetadata)
        assert isinstance(results[0].data, odg.model.VulnerabilityFinding)
        assert results[0].data.cve == 'CVE-2024-0001'

    def test_accepts_tuple_of_finding_types(self):
        node = _make_resource_node()
        client = unittest.mock.Mock()
        client.query_metadata.return_value = []

        list(
            scanner_utils.findings.iter_existing_findings(
                delivery_service_client=client,
                resource_node=node,
                finding_type=(
                    odg.model.Datatype.VULNERABILITY_FINDING,
                    odg.model.Datatype.LICENSE_FINDING,
                ),
                datasource=odg.model.Datasource.BDBA,
            ),
        )

        kwargs = client.query_metadata.call_args.kwargs
        assert kwargs['type'] == (
            odg.model.Datatype.VULNERABILITY_FINDING,
            odg.model.Datatype.LICENSE_FINDING,
        )

    def test_empty_results_from_delivery_client(self):
        node = _make_resource_node()
        client = unittest.mock.Mock()
        client.query_metadata.return_value = []

        results = list(
            scanner_utils.findings.iter_existing_findings(
                delivery_service_client=client,
                resource_node=node,
                finding_type=odg.model.Datatype.VULNERABILITY_FINDING,
                datasource=odg.model.Datasource.BDBA,
            ),
        )

        assert results == []


class TestMakeArtefactScanInfo:
    def test_returns_artefact_scan_info_with_correct_meta(self):
        node = _make_resource_node()

        am = scanner_utils.findings.make_artefact_scan_info(
            resource_node=node,
            datasource=odg.model.Datasource.BDBA,
        )

        assert am.meta.type == odg.model.Datatype.ARTEFACT_SCAN_INFO
        assert am.meta.datasource == odg.model.Datasource.BDBA

    def test_artefact_fields_match_resource_node(self):
        node = _make_resource_node(component_name='my.org/comp', version='2.3.4')

        am = scanner_utils.findings.make_artefact_scan_info(
            resource_node=node,
            datasource=odg.model.Datasource.CLAMAV,
        )

        assert am.artefact.component_name == 'my.org/comp'
        assert am.artefact.component_version == '2.3.4'
        assert am.meta.datasource == odg.model.Datasource.CLAMAV

    def test_different_datasources_produce_different_keys(self):
        node = _make_resource_node()

        bdba = scanner_utils.findings.make_artefact_scan_info(node, odg.model.Datasource.BDBA)
        clamav = scanner_utils.findings.make_artefact_scan_info(node, odg.model.Datasource.CLAMAV)

        assert bdba.meta.datasource != clamav.meta.datasource
        assert bdba.key != clamav.key


class TestBDBAVulnerabilityFindingUrls:
    def test_report_url_added_to_urls_on_construction(self):
        finding = odg.model.BDBAVulnerabilityFinding(
            severity='MEDIUM',
            package_name='pkg',
            package_version='1.0',
            cve='CVE-2024-0001',
            cvss_score=5.0,
            base_url='https://bdba.example',
            report_url='https://bdba.example/report/42',
            product_id=42,
            group_id=7,
        )

        assert any('bdba.example/report/42' in u for u in finding.urls)
        assert any('nvd.nist.gov' in u for u in finding.urls)

    def test_report_url_not_duplicated_when_already_present(self):
        bdba_link = '[BDBA 42](https://bdba.example/report/42)'
        finding = odg.model.BDBAVulnerabilityFinding(
            severity='MEDIUM',
            package_name='pkg',
            package_version='1.0',
            cve='CVE-2024-0001',
            cvss_score=5.0,
            base_url='https://bdba.example',
            report_url='https://bdba.example/report/42',
            product_id=42,
            group_id=7,
            urls=[bdba_link],
        )

        assert finding.urls.count(bdba_link) == 1

    def test_urls_not_part_of_finding_key(self):
        # Ensures that adding the BDBA link to urls on deserialization does not change the key,
        # preventing accidental key drift between old and new DB records.
        base_kwargs = dict(
            severity='MEDIUM',
            package_name='pkg',
            package_version='1.0',
            cve='CVE-2024-0001',
            cvss_score=5.0,
            base_url='https://bdba.example',
            report_url='https://bdba.example/report/42',
            product_id=42,
            group_id=7,
        )
        without_extra_url = odg.model.BDBAVulnerabilityFinding(**base_kwargs)
        with_extra_url = odg.model.BDBAVulnerabilityFinding(
            **base_kwargs,
            urls=['https://extra.example'],
        )

        assert without_extra_url.key == with_extra_url.key
