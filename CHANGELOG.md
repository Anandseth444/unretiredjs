## [1.4.16] - 2026-11-03

### Changed
- Bumped version to 1.4.16.
- Verified RetireJS database sync and persistent Next.js CVE-2026-96889 support.

## [1.4.15] - 2026-11-03

### Added
- Synced RetireJS vulnerability database from upstream (+395 vulnerabilities, 76 total components).
- Added persistent custom CVE enrichment for Next.js Image Optimization RCE (CVE-2026-96889 / GHSA-2464-fhr4-w9xw).
- Added comprehensive unit tests for Next.js CVE-2026-96889 detection and edge cases.

### Changed
- Refactored `retirejs.py` to follow modern Python best practices, PEP 8 standards, and type annotations.
- Refactored `update_vulnerabilities.py` with custom enrichments architecture to ensure persistent CVEs across syncs.
- Upgraded GitHub Actions workflows (`checkout@v4`, `setup-python@v5`, added `permissions: contents: write`).

### Fixed
- Fixed `KeyError` in `check()` when an unknown component was scanned.
- Fixed `TypeError` in `_is_at_or_above()` when comparing against `None`.
- Fixed `_replacement_match()` regex flag handling (`/i`, `/m`, `/s`).
- Fixed `unique()` unhashable dict handling.
- Preserved bootstrap URI extractor regex.

## [1.4.14] - 2026-05-04

### Fixed
- Bootstrap regex fix in URI extractor.

## [1.4.13] - 2026-05-04

### Fixed
- Fix bootstrap URI regex.

## [1.4.12] - 2026-04-15

### Changed
- Added version ranges for CVE-2026-40175 axios entries.

## [1.4.11] - 2026-04-15

### Added
- Added CVE-2026-40175 (GHSA-fvcv-3m26-pcqx) for axios header injection gadget.

## [1.4.10] - 2026-04-01

### Added
- Axios supply chain vulnerability data.

## [1.4.8] - 2025-10-01

### Added
- Updated RetireJS vulnerability database

## [1.4.7] - 2025-08-01

### Added
- Updated RetireJS vulnerability database

## [1.4.6] - 2025-07-01

### Added
- Updated RetireJS vulnerability database

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
