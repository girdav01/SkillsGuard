"""Tests for Skill SBOM (Software Bill of Materials) generator."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest
from click.testing import CliRunner

from skillguard.core.skill_sbom import (
    generate_skill_sbom,
    generate_skill_sbom_json,
    _parse_requirements_txt,
    _parse_package_json,
    _extract_external_refs,
    _detect_license,
    _extract_pinned_version,
)
from skillguard.core.models import (
    EngineResult,
    EngineVerdict,
    Finding,
    FileType,
    ScanResult,
    Severity,
    SkillFile,
    SkillPlatform,
    Verdict,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"
CLEAN_SKILL = FIXTURES_DIR / "clean_skill"
DEPS_SKILL = FIXTURES_DIR / "skill_with_deps"


# ── CycloneDX structure tests ───────────────────────────────────────

class TestSBOMStructure:
    def test_cyclonedx_format(self):
        bom = generate_skill_sbom(CLEAN_SKILL)
        assert bom["bomFormat"] == "CycloneDX"
        assert bom["specVersion"] == "1.5"
        assert bom["version"] == 1

    def test_has_serial_number(self):
        bom = generate_skill_sbom(CLEAN_SKILL)
        assert bom["serialNumber"].startswith("urn:uuid:skillguard:")

    def test_has_metadata(self):
        bom = generate_skill_sbom(CLEAN_SKILL)
        meta = bom["metadata"]
        assert "timestamp" in meta
        assert meta["tools"]["components"][0]["name"] == "SkillGuard"
        assert meta["properties"][0]["name"] == "skillguard:sbom_type"
        assert meta["properties"][0]["value"] == "skill-inventory"

    def test_has_components(self):
        bom = generate_skill_sbom(CLEAN_SKILL)
        assert len(bom["components"]) > 0

    def test_has_dependencies_key(self):
        bom = generate_skill_sbom(CLEAN_SKILL)
        assert "dependencies" in bom

    def test_nonexistent_path(self):
        with pytest.raises(FileNotFoundError):
            generate_skill_sbom("/nonexistent/skill/path")


# ── Skill metadata extraction ───────────────────────────────────────

class TestSkillMetadata:
    def test_extracts_name_from_frontmatter(self):
        bom = generate_skill_sbom(CLEAN_SKILL)
        main_comp = bom["metadata"]["component"]
        assert main_comp["name"] == "code-formatter"

    def test_extracts_version_from_frontmatter(self):
        bom = generate_skill_sbom(CLEAN_SKILL)
        main_comp = bom["metadata"]["component"]
        assert main_comp["version"] == "1.0.0"

    def test_extracts_author(self):
        bom = generate_skill_sbom(CLEAN_SKILL)
        main_comp = bom["metadata"]["component"]
        assert main_comp["author"] == "example-dev"

    def test_extracts_description(self):
        bom = generate_skill_sbom(CLEAN_SKILL)
        main_comp = bom["metadata"]["component"]
        assert "code formatting" in main_comp["description"].lower()

    def test_extracts_declared_tools(self):
        bom = generate_skill_sbom(CLEAN_SKILL)
        main_comp = bom["metadata"]["component"]
        tool_props = [
            p["value"]
            for p in main_comp["properties"]
            if p["name"] == "skillguard:declared_tool"
        ]
        assert "Read" in tool_props
        assert "Edit" in tool_props

    def test_skill_with_deps_metadata(self):
        bom = generate_skill_sbom(DEPS_SKILL)
        main_comp = bom["metadata"]["component"]
        assert main_comp["name"] == "data-analyzer"
        assert main_comp["version"] == "2.1.0"
        assert main_comp["author"] == "data-team"


# ── File inventory ───────────────────────────────────────────────────

class TestFileInventory:
    def test_files_listed_as_components(self):
        bom = generate_skill_sbom(CLEAN_SKILL)
        file_comps = [
            c for c in bom["components"] if c["type"] == "file"
        ]
        assert len(file_comps) == 2  # SKILL.md + format.py

    def test_file_hashes_present(self):
        bom = generate_skill_sbom(CLEAN_SKILL)
        file_comps = [c for c in bom["components"] if c["type"] == "file"]
        for fc in file_comps:
            assert len(fc["hashes"]) == 1
            assert fc["hashes"][0]["alg"] == "SHA-256"
            assert len(fc["hashes"][0]["content"]) == 64

    def test_file_type_property(self):
        bom = generate_skill_sbom(CLEAN_SKILL)
        file_comps = [c for c in bom["components"] if c["type"] == "file"]
        file_types = {
            fc["name"]: [
                p["value"]
                for p in fc["properties"]
                if p["name"] == "skillguard:file_type"
            ][0]
            for fc in file_comps
        }
        assert file_types["SKILL.md"] == "skill_md"
        assert file_types["format.py"] == "script_python"

    def test_size_bytes_property(self):
        bom = generate_skill_sbom(CLEAN_SKILL)
        file_comps = [c for c in bom["components"] if c["type"] == "file"]
        for fc in file_comps:
            size_props = [
                p["value"]
                for p in fc["properties"]
                if p["name"] == "skillguard:size_bytes"
            ]
            assert len(size_props) == 1
            assert int(size_props[0]) > 0

    def test_deps_skill_has_more_files(self):
        bom = generate_skill_sbom(DEPS_SKILL)
        file_comps = [c for c in bom["components"] if c["type"] == "file"]
        assert len(file_comps) == 5  # SKILL.md, requirements.txt, package.json, analyze.py, LICENSE

    def test_composite_hash(self):
        bom = generate_skill_sbom(CLEAN_SKILL)
        main_comp = bom["metadata"]["component"]
        assert main_comp["hashes"][0]["alg"] == "SHA-256"
        assert len(main_comp["hashes"][0]["content"]) == 64

    def test_total_size_property(self):
        bom = generate_skill_sbom(CLEAN_SKILL)
        main_comp = bom["metadata"]["component"]
        total_size = [
            p["value"]
            for p in main_comp["properties"]
            if p["name"] == "skillguard:total_size_bytes"
        ]
        assert len(total_size) == 1
        assert int(total_size[0]) > 0


# ── Dependency parsing ───────────────────────────────────────────────

class TestRequirementsTxt:
    def test_parse_pinned(self):
        deps = _parse_requirements_txt("pandas==2.1.4\nnumpy==1.24.0\n")
        assert len(deps) == 2
        assert deps[0]["name"] == "pandas"
        assert deps[0]["version"] == "2.1.4"
        assert "pkg:pypi/pandas@2.1.4" == deps[0]["purl"]

    def test_parse_range(self):
        deps = _parse_requirements_txt("requests>=2.31,<3.0\n")
        assert deps[0]["name"] == "requests"
        assert deps[0]["version"] == "2.31"

    def test_parse_compatible(self):
        deps = _parse_requirements_txt("matplotlib~=3.8.0\n")
        assert deps[0]["name"] == "matplotlib"
        assert deps[0]["version"] == "3.8.0"

    def test_parse_no_version(self):
        deps = _parse_requirements_txt("pyyaml\n")
        assert deps[0]["name"] == "pyyaml"
        assert deps[0]["version"] == "unspecified"

    def test_skip_comments(self):
        deps = _parse_requirements_txt("# this is a comment\npandas==1.0\n")
        assert len(deps) == 1

    def test_skip_flags(self):
        deps = _parse_requirements_txt("-r base.txt\npandas==1.0\n")
        assert len(deps) == 1

    def test_skip_empty_lines(self):
        deps = _parse_requirements_txt("\n\npandas==1.0\n\n")
        assert len(deps) == 1


class TestPackageJson:
    def test_parse_dependencies(self):
        content = json.dumps({
            "dependencies": {"chart.js": "^4.4.0", "d3": "~7.8.5"},
        })
        deps = _parse_package_json(content)
        assert len(deps) == 2
        names = {d["name"] for d in deps}
        assert "chart.js" in names
        assert "d3" in names

    def test_parse_dev_dependencies(self):
        content = json.dumps({
            "dependencies": {"chart.js": "^4.4.0"},
            "devDependencies": {"prettier": "^3.0.0"},
        })
        deps = _parse_package_json(content)
        scopes = {d["name"]: d["scope"] for d in deps}
        assert scopes["chart.js"] == "required"
        assert scopes["prettier"] == "optional"

    def test_strip_semver_prefix(self):
        content = json.dumps({"dependencies": {"foo": "^1.2.3"}})
        deps = _parse_package_json(content)
        assert deps[0]["version"] == "1.2.3"

    def test_npm_purl(self):
        content = json.dumps({"dependencies": {"express": "4.18.0"}})
        deps = _parse_package_json(content)
        assert deps[0]["purl"] == "pkg:npm/express@4.18.0"

    def test_invalid_json(self):
        deps = _parse_package_json("not valid json {{{")
        assert deps == []


# ── Dependency extraction in SBOM ────────────────────────────────────

class TestSBOMDependencies:
    def test_requirements_extracted(self):
        bom = generate_skill_sbom(DEPS_SKILL)
        lib_comps = [c for c in bom["components"] if c["type"] == "library"]
        names = {c["name"] for c in lib_comps}
        assert "pandas" in names
        assert "numpy" in names
        assert "matplotlib" in names

    def test_npm_deps_extracted(self):
        bom = generate_skill_sbom(DEPS_SKILL)
        lib_comps = [c for c in bom["components"] if c["type"] == "library"]
        names = {c["name"] for c in lib_comps}
        assert "chart.js" in names
        assert "d3" in names
        assert "prettier" in names

    def test_dependency_graph(self):
        bom = generate_skill_sbom(DEPS_SKILL)
        dep_graph = bom["dependencies"]
        assert len(dep_graph) > 0
        main_dep = dep_graph[0]
        assert main_dep["ref"].startswith("skill:")
        assert len(main_dep["dependsOn"]) > 0

    def test_no_duplicate_deps(self):
        bom = generate_skill_sbom(DEPS_SKILL)
        lib_comps = [c for c in bom["components"] if c["type"] == "library"]
        names = [c["name"] for c in lib_comps]
        assert len(names) == len(set(names))

    def test_purl_format(self):
        bom = generate_skill_sbom(DEPS_SKILL)
        lib_comps = [c for c in bom["components"] if c["type"] == "library"]
        for lc in lib_comps:
            assert "purl" in lc
            assert lc["purl"].startswith("pkg:")

    def test_no_deps_for_clean_skill(self):
        bom = generate_skill_sbom(CLEAN_SKILL)
        lib_comps = [c for c in bom["components"] if c["type"] == "library"]
        assert len(lib_comps) == 0
        assert bom["dependencies"] == []


# ── License detection ────────────────────────────────────────────────

class TestLicenseDetection:
    def test_mit_license_from_file(self):
        sf = SkillFile(
            path="LICENSE",
            file_type=FileType.OTHER,
            sha256="abc",
            size_bytes=100,
            content="MIT License\n\nCopyright 2025...",
        )
        assert _detect_license([sf]) == "MIT"

    def test_apache_license(self):
        sf = SkillFile(
            path="LICENSE.txt",
            file_type=FileType.OTHER,
            sha256="abc",
            size_bytes=100,
            content="Apache License\nVersion 2.0...",
        )
        assert _detect_license([sf]) == "Apache-2.0"

    def test_no_license_file(self):
        sf = SkillFile(
            path="SKILL.md",
            file_type=FileType.SKILL_MD,
            sha256="abc",
            size_bytes=100,
            content="# Skill",
        )
        assert _detect_license([sf]) is None

    def test_license_in_sbom(self):
        bom = generate_skill_sbom(DEPS_SKILL)
        main_comp = bom["metadata"]["component"]
        assert "licenses" in main_comp
        assert main_comp["licenses"][0]["license"]["id"] == "MIT"

    def test_no_license_in_clean_skill(self):
        bom = generate_skill_sbom(CLEAN_SKILL)
        main_comp = bom["metadata"]["component"]
        assert "licenses" not in main_comp


# ── External references ──────────────────────────────────────────────

class TestExternalReferences:
    def test_extract_urls(self):
        sf = SkillFile(
            path="SKILL.md",
            file_type=FileType.SKILL_MD,
            sha256="abc",
            size_bytes=100,
            content="See https://github.com/org/repo for details.",
        )
        refs = _extract_external_refs([sf])
        assert len(refs) == 1
        assert refs[0]["type"] == "vcs"
        assert refs[0]["url"] == "https://github.com/org/repo"

    def test_skip_example_urls(self):
        sf = SkillFile(
            path="SKILL.md",
            file_type=FileType.SKILL_MD,
            sha256="abc",
            size_bytes=100,
            content="See https://example.com and https://localhost:8080 for details.",
        )
        refs = _extract_external_refs([sf])
        assert len(refs) == 0

    def test_classify_pypi_url(self):
        sf = SkillFile(
            path="SKILL.md",
            file_type=FileType.SKILL_MD,
            sha256="abc",
            size_bytes=100,
            content="Install from https://pypi.org/project/pandas/",
        )
        refs = _extract_external_refs([sf])
        assert refs[0]["type"] == "distribution"


# ── Version extraction ───────────────────────────────────────────────

class TestVersionExtraction:
    def test_exact_pin(self):
        assert _extract_pinned_version("==1.2.3") == "1.2.3"

    def test_minimum(self):
        assert _extract_pinned_version(">=1.0.0") == "1.0.0"

    def test_compatible(self):
        assert _extract_pinned_version("~=3.8.0") == "3.8.0"

    def test_no_version(self):
        assert _extract_pinned_version("") == "unspecified"

    def test_complex_range(self):
        assert _extract_pinned_version(">=2.31,<3.0") == "2.31"


# ── JSON output ──────────────────────────────────────────────────────

class TestSBOMJSON:
    def test_valid_json(self):
        output = generate_skill_sbom_json(CLEAN_SKILL)
        data = json.loads(output)
        assert data["bomFormat"] == "CycloneDX"

    def test_json_pretty_printed(self):
        output = generate_skill_sbom_json(CLEAN_SKILL)
        # Pretty printed JSON has newlines
        assert "\n" in output


# ── Scan result embedding ────────────────────────────────────────────

class TestScanResultEmbedding:
    def _make_scan_result(self) -> ScanResult:
        finding = Finding(
            rule_id="SG-TEST-001",
            rule_name="Test",
            severity=Severity.HIGH,
            category="test",
            description="Test finding",
            file_path="test.py",
            confidence=0.9,
            owasp_llm=["LLM01"],
            mitre_attack=["T1059"],
            remediation="Fix it.",
        )
        return ScanResult(
            scan_id="embed-test",
            skill_name="test",
            skill_sha256="abc",
            platform=SkillPlatform.GENERIC,
            scan_started=datetime(2025, 1, 1),
            scan_completed=datetime(2025, 1, 1),
            composite_score=50,
            verdict=Verdict.SUSPICIOUS,
            engine_results=[
                EngineResult(
                    engine_name="test",
                    engine_version="1.0",
                    verdict=EngineVerdict.SUSPICIOUS,
                    confidence=0.9,
                    findings=[finding],
                    duration_ms=50,
                )
            ],
            total_findings=1,
            findings_by_severity={"high": 1},
            files_scanned=1,
            owasp_coverage=["LLM01"],
        )

    def test_vulnerabilities_embedded(self):
        result = self._make_scan_result()
        bom = generate_skill_sbom(CLEAN_SKILL, include_scan_result=result)
        assert "vulnerabilities" in bom
        assert len(bom["vulnerabilities"]) == 1
        assert bom["vulnerabilities"][0]["id"] == "SG-TEST-001"

    def test_no_vulnerabilities_without_scan(self):
        bom = generate_skill_sbom(CLEAN_SKILL)
        assert "vulnerabilities" not in bom


# ── CLI bom command ──────────────────────────────────────────────────

class TestCLIBomCommand:
    def test_bom_stdout(self):
        from skillguard.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["bom", str(CLEAN_SKILL)])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["bomFormat"] == "CycloneDX"

    def test_bom_to_file(self, tmp_path: Path):
        from skillguard.cli.main import cli

        output_file = tmp_path / "test-sbom.json"
        runner = CliRunner()
        result = runner.invoke(cli, ["bom", str(CLEAN_SKILL), "-o", str(output_file)])
        assert result.exit_code == 0
        data = json.loads(output_file.read_text())
        assert data["bomFormat"] == "CycloneDX"

    def test_bom_with_deps(self):
        from skillguard.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["bom", str(DEPS_SKILL)])
        assert result.exit_code == 0
        data = json.loads(result.output)
        lib_comps = [c for c in data["components"] if c["type"] == "library"]
        assert len(lib_comps) > 0


# ── API SBOM endpoint ───────────────────────────────────────────────

class TestSBOMAPI:
    @pytest.fixture
    def client(self):
        from fastapi.testclient import TestClient
        from skillguard.api.app import create_app

        return TestClient(create_app())

    def test_generate_sbom(self, client):
        resp = client.post(
            "/api/v1/sbom",
            json={"skill_path": str(CLEAN_SKILL)},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["bomFormat"] == "CycloneDX"
        assert data["specVersion"] == "1.5"

    def test_sbom_with_deps(self, client):
        resp = client.post(
            "/api/v1/sbom",
            json={"skill_path": str(DEPS_SKILL)},
        )
        assert resp.status_code == 200
        data = resp.json()
        lib_comps = [c for c in data["components"] if c["type"] == "library"]
        assert len(lib_comps) > 0

    def test_sbom_nonexistent_path(self, client):
        resp = client.post(
            "/api/v1/sbom",
            json={"skill_path": "/nonexistent/path"},
        )
        # Path outside allowed directory is rejected as 400 (path traversal protection)
        assert resp.status_code == 400

    def test_sbom_with_scan_result(self, client):
        # Submit a scan first
        scan_resp = client.post(
            "/api/v1/scan",
            json={"skill_path": str(CLEAN_SKILL)},
        )
        scan_id = scan_resp.json()["scan_id"]

        # Generate SBOM with embedded scan results
        resp = client.post(
            "/api/v1/sbom",
            json={"skill_path": str(CLEAN_SKILL), "include_scan_id": scan_id},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["bomFormat"] == "CycloneDX"
