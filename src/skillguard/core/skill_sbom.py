"""CycloneDX SBOM generator for AI Agent Skills.

Generates a comprehensive Software Bill of Materials (SBOM) from a skill
directory, inventorying all files, dependencies, metadata, licenses,
external references, and declared capabilities. Produces CycloneDX 1.5
format output independent of scan results.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from skillguard.core.hasher import hash_content, hash_file, hash_skill
from skillguard.core.models import FileType, SkillFile
from skillguard.core.skill_parser import (
    classify_file,
    parse_frontmatter,
    parse_skill_directory,
)


# ── Dependency parsers ───────────────────────────────────────────────

def _parse_requirements_txt(content: str) -> list[dict[str, Any]]:
    """Parse a pip requirements.txt file into dependency entries."""
    deps: list[dict[str, Any]] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Handle: package==1.0, package>=1.0, package~=1.0, package
        match = re.match(
            r"^([A-Za-z0-9_][A-Za-z0-9._-]*)\s*([><=!~]+\s*[\d.]+(?:\s*,\s*[><=!~]+\s*[\d.]+)*)?",
            line,
        )
        if match:
            name = match.group(1)
            version_spec = match.group(2) or ""
            version = _extract_pinned_version(version_spec)
            deps.append({
                "type": "library",
                "name": name,
                "version": version,
                "purl": f"pkg:pypi/{name.lower()}@{version}" if version != "unspecified" else f"pkg:pypi/{name.lower()}",
                "scope": "required",
                "properties": [{"name": "skillguard:source", "value": "requirements.txt"}],
            })
    return deps


def _parse_package_json(content: str) -> list[dict[str, Any]]:
    """Parse a package.json file into dependency entries."""
    deps: list[dict[str, Any]] = []
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return deps

    for section, scope in [("dependencies", "required"), ("devDependencies", "optional")]:
        for name, version_str in data.get(section, {}).items():
            # Strip semver range chars: ^, ~, >=, etc.
            version = re.sub(r"^[\^~>=<]*", "", version_str).strip() or "unspecified"
            deps.append({
                "type": "library",
                "name": name,
                "version": version,
                "purl": f"pkg:npm/{name}@{version}" if version != "unspecified" else f"pkg:npm/{name}",
                "scope": scope,
                "properties": [{"name": "skillguard:source", "value": "package.json"}],
            })
    return deps


def _parse_pyproject_toml(content: str) -> list[dict[str, Any]]:
    """Parse dependency declarations from pyproject.toml."""
    deps: list[dict[str, Any]] = []
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ImportError:
            # Fall back to regex extraction
            return _parse_pyproject_toml_regex(content)

    try:
        data = tomllib.loads(content)
    except Exception:
        return _parse_pyproject_toml_regex(content)

    dep_list = data.get("project", {}).get("dependencies", [])
    for dep_str in dep_list:
        match = re.match(r"^([A-Za-z0-9_][A-Za-z0-9._-]*)\s*([><=!~]+.*)?", dep_str)
        if match:
            name = match.group(1)
            version_spec = match.group(2) or ""
            version = _extract_pinned_version(version_spec)
            deps.append({
                "type": "library",
                "name": name,
                "version": version,
                "purl": f"pkg:pypi/{name.lower()}@{version}" if version != "unspecified" else f"pkg:pypi/{name.lower()}",
                "scope": "required",
                "properties": [{"name": "skillguard:source", "value": "pyproject.toml"}],
            })
    return deps


def _parse_pyproject_toml_regex(content: str) -> list[dict[str, Any]]:
    """Regex fallback for pyproject.toml dependency extraction."""
    deps: list[dict[str, Any]] = []
    in_deps = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped == "dependencies = [":
            in_deps = True
            continue
        if in_deps:
            if stripped == "]":
                break
            match = re.match(r'["\']([A-Za-z0-9_][A-Za-z0-9._-]*)([><=!~]+[^"\']*)?["\']', stripped)
            if match:
                name = match.group(1)
                version_spec = match.group(2) or ""
                version = _extract_pinned_version(version_spec)
                deps.append({
                    "type": "library",
                    "name": name,
                    "version": version,
                    "purl": f"pkg:pypi/{name.lower()}@{version}" if version != "unspecified" else f"pkg:pypi/{name.lower()}",
                    "scope": "required",
                    "properties": [{"name": "skillguard:source", "value": "pyproject.toml"}],
                })
    return deps


def _extract_pinned_version(spec: str) -> str:
    """Extract exact version from a version spec like '==1.2.3' or '>=1.0,<2'."""
    match = re.search(r"==\s*([\d][A-Za-z0-9._-]*)", spec)
    if match:
        return match.group(1)
    # For ranges, return the lower bound
    match = re.search(r">=\s*([\d][A-Za-z0-9._-]*)", spec)
    if match:
        return match.group(1)
    match = re.search(r"~=\s*([\d][A-Za-z0-9._-]*)", spec)
    if match:
        return match.group(1)
    return "unspecified"


# ── External reference extraction ────────────────────────────────────

_URL_PATTERN = re.compile(r"https?://[^\s\"'`<>\)\]]+")
_LICENSE_FILES = {"license", "license.md", "license.txt", "licence", "licence.md", "copying"}


def _extract_external_refs(files: list[SkillFile]) -> list[dict[str, str]]:
    """Extract unique external URL references from skill files."""
    urls: set[str] = set()
    for sf in files:
        if sf.content is None:
            continue
        for match in _URL_PATTERN.finditer(sf.content):
            url = match.group().rstrip(".,;:")
            # Skip example/placeholder URLs
            if "example.com" in url or "localhost" in url or "127.0.0.1" in url:
                continue
            urls.add(url)

    refs: list[dict[str, str]] = []
    for url in sorted(urls):
        ref_type = "website"
        if "github.com" in url or "gitlab.com" in url:
            ref_type = "vcs"
        elif "pypi.org" in url or "npmjs.com" in url:
            ref_type = "distribution"
        elif "/docs" in url or "readthedocs" in url:
            ref_type = "documentation"
        refs.append({"type": ref_type, "url": url})
    return refs


def _detect_license(files: list[SkillFile]) -> str | None:
    """Detect license from LICENSE files or frontmatter."""
    for sf in files:
        if sf.path.lower().split("/")[-1].split(".")[0] in _LICENSE_FILES:
            if sf.content:
                content_lower = sf.content.lower()
                if "mit license" in content_lower:
                    return "MIT"
                if "apache license" in content_lower:
                    return "Apache-2.0"
                if "gnu general public license" in content_lower:
                    if "version 3" in content_lower:
                        return "GPL-3.0-only"
                    return "GPL-2.0-only"
                if "bsd" in content_lower:
                    return "BSD-3-Clause"
                if "isc" in content_lower:
                    return "ISC"
                return "unknown"
    return None


# ── Main SBOM generator ─────────────────────────────────────────────

def generate_skill_sbom(
    skill_path: str | Path,
    include_scan_result: Any | None = None,
) -> dict[str, Any]:
    """Generate a CycloneDX SBOM for a skill directory.

    This analyzes the skill package directly (without running a scan)
    to produce a comprehensive bill of materials including:
    - Complete file inventory with integrity hashes
    - Dependency extraction (requirements.txt, package.json, pyproject.toml)
    - Metadata from SKILL.md frontmatter (author, version, tools)
    - License detection
    - External URL references
    - Capability/tool declarations

    Args:
        skill_path: Path to the skill directory.
        include_scan_result: Optional ScanResult to embed security findings.

    Returns:
        CycloneDX 1.5 SBOM as a dict.
    """
    skill_path = Path(skill_path)
    if not skill_path.exists():
        raise FileNotFoundError(f"Skill path does not exist: {skill_path}")

    # Parse all files
    skill_files = parse_skill_directory(skill_path)

    # Compute composite hash
    file_pairs = [(sf.path, sf.sha256) for sf in skill_files]
    composite_hash = hash_skill(file_pairs)

    # Extract frontmatter metadata from the primary SKILL.md
    metadata = _extract_skill_metadata(skill_files)
    skill_name = metadata.get("name", skill_path.name)
    skill_version = metadata.get("version", "unknown")
    author = metadata.get("author", "unknown")
    description = metadata.get("description", "")
    declared_tools = metadata.get("tools", [])

    # Detect license
    detected_license = _detect_license(skill_files)

    # Extract dependencies
    dependencies = _extract_all_dependencies(skill_files)

    # Extract external references
    ext_refs = _extract_external_refs(skill_files)

    # Build file inventory components
    file_components = _build_file_inventory(skill_files)

    # Build the main skill component
    skill_component: dict[str, Any] = {
        "type": "application",
        "bom-ref": f"skill:{composite_hash[:16]}",
        "name": skill_name,
        "version": skill_version,
        "description": description,
        "author": author,
        "hashes": [
            {"alg": "SHA-256", "content": composite_hash},
        ],
        "properties": [
            {"name": "skillguard:type", "value": "ai-agent-skill"},
            {"name": "skillguard:files_count", "value": str(len(skill_files))},
            {"name": "skillguard:total_size_bytes", "value": str(sum(sf.size_bytes for sf in skill_files))},
        ],
    }

    # Add declared tools/capabilities
    for tool in declared_tools:
        skill_component["properties"].append({
            "name": "skillguard:declared_tool",
            "value": str(tool),
        })

    if detected_license:
        skill_component["licenses"] = [
            {"license": {"id": detected_license}}
        ]

    if ext_refs:
        skill_component["externalReferences"] = ext_refs

    # All components: skill + dependencies + files
    all_components = [skill_component] + dependencies + file_components

    # Build dependency tree
    dep_graph: list[dict[str, Any]] = []
    if dependencies:
        dep_graph.append({
            "ref": skill_component["bom-ref"],
            "dependsOn": [d["bom-ref"] for d in dependencies],
        })

    # Build the CycloneDX BOM
    bom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "serialNumber": f"urn:uuid:skillguard:{composite_hash[:32]}",
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "SkillGuard",
                        "version": "0.3.0",
                        "description": "Multi-engine security scanner for AI Agent Skills",
                    }
                ],
            },
            "component": skill_component,
            "properties": [
                {"name": "skillguard:sbom_type", "value": "skill-inventory"},
                {"name": "skillguard:skill_path", "value": str(skill_path)},
            ],
        },
        "components": all_components,
        "dependencies": dep_graph,
    }

    # Embed scan vulnerabilities if a scan result is provided
    if include_scan_result is not None:
        bom["vulnerabilities"] = _build_vulnerabilities(include_scan_result, skill_component["bom-ref"])

    return bom


def generate_skill_sbom_json(
    skill_path: str | Path,
    include_scan_result: Any | None = None,
) -> str:
    """Generate a CycloneDX SBOM as a JSON string."""
    return json.dumps(
        generate_skill_sbom(skill_path, include_scan_result),
        indent=2,
    )


# ── Internal helpers ─────────────────────────────────────────────────

def _extract_skill_metadata(files: list[SkillFile]) -> dict[str, Any]:
    """Extract metadata from the primary SKILL.md frontmatter."""
    for sf in files:
        if sf.file_type == FileType.SKILL_MD and sf.content:
            fm, _ = parse_frontmatter(sf.content)
            if fm:
                return fm
    return {}


def _extract_all_dependencies(files: list[SkillFile]) -> list[dict[str, Any]]:
    """Extract dependencies from all recognized manifest files."""
    deps: list[dict[str, Any]] = []
    seen_purls: set[str] = set()

    for sf in files:
        if sf.content is None:
            continue

        filename = sf.path.split("/")[-1].lower()

        if filename == "requirements.txt":
            parsed = _parse_requirements_txt(sf.content)
        elif filename == "package.json":
            parsed = _parse_package_json(sf.content)
        elif filename == "pyproject.toml":
            parsed = _parse_pyproject_toml(sf.content)
        else:
            continue

        for dep in parsed:
            purl = dep.get("purl", "")
            if purl in seen_purls:
                continue
            seen_purls.add(purl)
            # Add a bom-ref for dependency graph
            dep["bom-ref"] = f"dep:{dep['name'].lower()}"
            deps.append(dep)

    return deps


def _build_file_inventory(files: list[SkillFile]) -> list[dict[str, Any]]:
    """Build CycloneDX components for each file in the skill package."""
    components: list[dict[str, Any]] = []
    for sf in files:
        file_type = sf.file_type if isinstance(sf.file_type, str) else sf.file_type.value
        comp: dict[str, Any] = {
            "type": "file",
            "bom-ref": f"file:{sf.sha256[:16]}",
            "name": sf.path,
            "version": "",
            "hashes": [
                {"alg": "SHA-256", "content": sf.sha256},
            ],
            "properties": [
                {"name": "skillguard:file_type", "value": file_type},
                {"name": "skillguard:size_bytes", "value": str(sf.size_bytes)},
            ],
        }
        components.append(comp)
    return components


def _build_vulnerabilities(
    scan_result: Any,
    skill_ref: str,
) -> list[dict[str, Any]]:
    """Build vulnerability entries from a ScanResult (optional merge)."""
    vulnerabilities: list[dict[str, Any]] = []
    seen_rules: set[str] = set()

    for er in scan_result.engine_results:
        for finding in er.findings:
            if finding.rule_id in seen_rules:
                continue
            seen_rules.add(finding.rule_id)

            vuln: dict[str, Any] = {
                "id": finding.rule_id,
                "source": {"name": "SkillGuard"},
                "description": finding.description,
                "ratings": [
                    {
                        "source": {"name": "SkillGuard"},
                        "severity": finding.severity if isinstance(finding.severity, str) else finding.severity.value,
                        "score": finding.confidence,
                        "method": "other",
                    }
                ],
                "affects": [{"ref": skill_ref}],
                "properties": [],
            }

            for owasp in finding.owasp_llm:
                vuln["properties"].append({"name": "owasp:llm", "value": owasp})
            for mitre in finding.mitre_attack:
                vuln["properties"].append({"name": "mitre:attack", "value": mitre})

            if finding.remediation:
                vuln["recommendation"] = finding.remediation

            vulnerabilities.append(vuln)

    return vulnerabilities
