import enum


class ScanningMode(enum.StrEnum):
    """
    ADR 005: configurable scanning modes for vulnerability scanners.

    - BINARY: fetch and scan the artifact directly
    - SBOM: use a pre-existing SBOM only
    - SBOM_WITH_BINARY_FALLBACK: use SBOM when available, fall back to binary scanning
    """

    BINARY = 'binary'
    SBOM = 'sbom'
    SBOM_WITH_BINARY_FALLBACK = 'sbom_with_binary_fallback'
