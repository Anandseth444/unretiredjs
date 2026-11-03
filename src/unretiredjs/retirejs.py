import hashlib
import json
import logging
import re
from typing import Any, Dict, List, Optional, Union
import urllib3
from urllib3.exceptions import InsecureRequestWarning
import requests

try:
    from .vulnerabilities import definitions
except (ImportError, ModuleNotFoundError):
    from vulnerabilities import definitions

logger = logging.getLogger(__name__)


def is_defined(obj: Any) -> bool:
    """Helper to check if an object is not None (preserved for backwards compatibility)."""
    return obj is not None


def scan(data: str, extractor: str, matcher=None, definitions: Dict[str, Any] = definitions) -> List[Dict[str, Any]]:
    """Scan data using extractors of a given type across component definitions."""
    matcher = matcher or _simple_match
    detected: List[Dict[str, Any]] = []

    for component, comp_data in definitions.items():
        comp_extractors = (comp_data.get("extractors") or {}).get(extractor)
        if not comp_extractors:
            continue
        for pattern in comp_extractors:
            match = matcher(pattern, data)
            if match:
                detected.append({
                    "version": match,
                    "component": component,
                    "detection": extractor,
                })
    return detected


def _simple_match(regex: str, data: str) -> Optional[str]:
    """Execute a regex search and return the captured group or full match."""
    try:
        match = re.search(regex, data)
    except re.error as e:
        logger.debug(f"Regex error in _simple_match for pattern {regex!r}: {e}")
        return None

    if not match:
        return None
    return match.group(1) if match.lastindex else match.group(0)


def _replacement_match(regex: str, data: str) -> Optional[str]:
    """Execute regex pattern replacement matching /pattern/replacement/flags format."""
    if not regex or len(regex) < 3:
        return None

    delimiter = regex[0]
    parts = regex[1:].split(delimiter)
    if len(parts) < 2:
        return None

    pattern_str = parts[0]
    replacement_str = parts[1]
    flags_str = parts[2] if len(parts) > 2 else ""

    flags = 0
    if "i" in flags_str:
        flags |= re.IGNORECASE
    if "m" in flags_str:
        flags |= re.MULTILINE
    if "s" in flags_str:
        flags |= re.DOTALL

    try:
        match = re.search(pattern_str, data, flags=flags)
    except re.error as e:
        logger.debug(f"Regex error in _replacement_match pattern {pattern_str!r}: {e}")
        return None

    if not match:
        return None

    # Convert JS style $1, $2 backreferences to Python \1, \2
    replacement_str = re.sub(r'\$(\d+)', r'\\\1', replacement_str)
    try:
        return re.sub(pattern_str, replacement_str, match.group(0), flags=flags)
    except re.error as e:
        logger.debug(f"Regex error in _replacement_match substitution: {e}")
        return None


def _scanhash(hash_value: str, definitions: Dict[str, Any] = definitions) -> List[Dict[str, Any]]:
    """Scan for components by file hash."""
    detected: List[Dict[str, Any]] = []
    for component, comp_data in definitions.items():
        hashes = (comp_data.get("extractors") or {}).get("hashes")
        if not isinstance(hashes, dict):
            continue
        if hash_value in hashes:
            detected.append({
                "version": hashes[hash_value],
                "component": component,
                "detection": "hash",
            })
    return detected


def check(results: List[Dict[str, Any]], definitions: Dict[str, Any] = definitions) -> List[Dict[str, Any]]:
    """Check detected component versions against vulnerability definitions."""
    for result in results:
        component_name = result.get("component")
        if not component_name or component_name not in definitions:
            continue

        version = result.get("version")
        if not version:
            continue

        comp_def = definitions[component_name]
        vulns = comp_def.get("vulnerabilities") or []

        for vuln in vulns:
            below = vuln.get("below")
            at_or_above = vuln.get("atOrAbove")

            # Check if version is below the fixed version
            if below and _is_at_or_above(version, below):
                continue
            # Check if version is at or above the vulnerable starting version
            if at_or_above and not _is_at_or_above(version, at_or_above):
                continue

            vulnerability: Dict[str, Any] = {"info": vuln.get("info")}
            if vuln.get("severity"):
                vulnerability["severity"] = vuln.get("severity")
            if vuln.get("identifiers"):
                vulnerability["identifiers"] = vuln.get("identifiers")

            if "vulnerabilities" not in result:
                result["vulnerabilities"] = []
            result["vulnerabilities"].append(vulnerability)

    return results


def unique(ar: list) -> list:
    """Return deduplicated list while preserving order."""
    seen = set()
    result = []
    for item in ar:
        key = json.dumps(item, sort_keys=True) if isinstance(item, (dict, list)) else item
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def _is_at_or_above(version1: Optional[str], version2: Optional[str]) -> bool:
    """Compare two version strings, returning True if version1 >= version2."""
    if not version1 or not version2:
        return False

    v1 = re.split(r'[.-]', str(version1).lstrip('v').strip())
    v2 = re.split(r'[.-]', str(version2).lstrip('v').strip())

    max_len = max(len(v1), len(v2))
    for i in range(max_len):
        v1_c = _to_comparable(v1[i] if i < len(v1) else None)
        v2_c = _to_comparable(v2[i] if i < len(v2) else None)

        if not isinstance(v1_c, type(v2_c)):
            # If one is int and one is str (e.g. 0 vs 'beta'), int release is higher than prerelease
            return isinstance(v1_c, int)
        if v1_c > v2_c:
            return True
        if v1_c < v2_c:
            return False

    return True


def _to_comparable(n: Any) -> Union[int, str]:
    """Convert version token into comparable int or string."""
    if n is None:
        return 0
    n_str = str(n).strip()
    if n_str.isdigit():
        return int(n_str, 10)
    return n_str


def _replace_version(js_repo_json_as_text: str) -> str:
    """Replace version placeholders in raw repo JSON."""
    return re.sub(r'[.0-9]*', r'[0-9][0-9.a-z_\-]+', js_repo_json_as_text)


def is_vulnerable(results: List[Dict[str, Any]]) -> bool:
    """Check if any detection in results has associated vulnerabilities."""
    return any(bool(r.get("vulnerabilities")) for r in results)


def scan_uri(uri: str, definitions: Dict[str, Any] = definitions) -> List[Dict[str, Any]]:
    """Scan a URI string for known vulnerable components."""
    result = scan(uri, 'uri', definitions=definitions)
    return check(result, definitions=definitions)


def scan_filename(file_name: str, definitions: Dict[str, Any] = definitions) -> List[Dict[str, Any]]:
    """Scan a filename for known vulnerable components."""
    result = scan(file_name, 'filename', definitions=definitions)
    return check(result, definitions=definitions)


def scan_file_content(content: str, definitions: Dict[str, Any] = definitions) -> List[Dict[str, Any]]:
    """Scan file content using content regexes, replacement regexes, and SHA-1 hashes."""
    result = scan(content, 'filecontent', definitions=definitions)
    if not result:
        result = scan(content, 'filecontentreplace', _replacement_match, definitions=definitions)

    if not result:
        file_hash = hashlib.sha1(content.encode('utf-8')).hexdigest()
        result = _scanhash(file_hash, definitions=definitions)

    return check(result, definitions=definitions)


def scan_endpoint(
    uri: str,
    definitions: Dict[str, Any] = definitions,
    timeout: int = 10,
    verify: bool = False,
    headers: Optional[Dict[str, str]] = None,
) -> List[Dict[str, Any]]:
    """
    Given a URI, scans for vulnerabilities in the URI string and the content
    hosted at that URI.
    """
    uri_scan_result = scan_uri(uri, definitions=definitions)

    try:
        with urllib3.warnings.catch_warnings():
            urllib3.disable_warnings(InsecureRequestWarning)
            response = requests.get(uri, verify=verify, timeout=timeout, headers=headers)
        if response.status_code == 200:
            content_scan_result = scan_file_content(response.text, definitions=definitions)
            uri_scan_result.extend(content_scan_result)
    except requests.RequestException as e:
        logger.debug(f"Network error in scan_endpoint for URI {uri!r}: {e}")

    return uri_scan_result
