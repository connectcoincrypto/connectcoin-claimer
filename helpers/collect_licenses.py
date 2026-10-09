"""Copy original runtime/dependency notices into the generated helper artifact.

No license text is synthesized. Third-party Rust crate archives are verified
against cryptography's installed wheel SBOM or its hash-pinned source lockfile.
"""

from __future__ import annotations

import hashlib
import importlib.metadata as metadata
import io
import json
import re
import shutil
import ssl
import sys
import tarfile
import tomllib
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
OUTPUT = PROJECT / "tmp" / "claims-licenses"
CACHE = (PROJECT / "tmp" / "claims-license-cache").resolve()
MANIFEST: list[dict] = []
# PyPI's exact 50.0.1 sdist and SHA-256, reviewed together with requirements.txt.
# A provider update must explicitly update this inventory pin; never use latest.
CRYPTOGRAPHY_SDISTS = {
    "50.0.1": (
        "https://files.pythonhosted.org/packages/bb/ad/5d6702db60b1e40b41ef513b6967ff5848f307d50f8449baf1634f5908f1/cryptography-50.0.1.tar.gz",
        "5dd9bda1c12b4162f6ff568eeb5e0ff956c28d14406e875cfe8a63a2d414ff20",
    ),
}


def crate_identity(component: dict) -> tuple[str, str, str]:
    name, version = component["name"], component["version"]
    if not re.fullmatch(r"[A-Za-z0-9_-]+", name) or not re.fullmatch(r"[A-Za-z0-9.+-]+", version):
        raise ValueError("Invalid Rust crate identity")
    hashes = [item["content"] for item in component["hashes"] if item["alg"] == "SHA-256"]
    if len(hashes) != 1 or not re.fullmatch(r"[0-9a-f]{64}", hashes[0]):
        raise ValueError("Invalid Rust crate checksum")
    return name, version, hashes[0]


def lockfile_components(data: bytes) -> list[dict]:
    packages = tomllib.loads(data.decode("utf-8")).get("package", [])
    if not isinstance(packages, list) or not 1 <= len(packages) <= 512:
        raise ValueError("Missing or oversized Rust dependency lockfile")
    components, seen = [], set()
    for package in packages:
        if "source" not in package:
            if not package.get("name", "").startswith("cryptography-"):
                raise ValueError("Unexpected local Rust dependency")
            continue  # Cryptography workspace crates use its installed notices.
        if package["source"] != "registry+https://github.com/rust-lang/crates.io-index":
            raise ValueError("Unsupported Rust dependency source")
        component = {"name": package["name"], "version": package["version"],
                     "hashes": [{"alg": "SHA-256", "content": package.get("checksum", "")}]}
        name, version, _ = crate_identity(component)
        if (name, version) in seen:
            raise ValueError("Duplicate Rust dependency")
        seen.add((name, version))
        components.append(component)
    if not components:
        raise ValueError("Missing Rust registry dependencies")
    return components


def source_components(version: str) -> list[dict]:
    if version not in CRYPTOGRAPHY_SDISTS:
        raise ValueError("No reviewed cryptography source inventory for this version")
    url, expected = CRYPTOGRAPHY_SDISTS[version]
    data = fetch(url)
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError("Cryptography source checksum differs from the reviewed pin")
    wanted = {f"cryptography-{version}/{name}": None for name in ("Cargo.lock", "pyproject.toml")}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for count, member in enumerate(archive):
            if count >= 10000:
                raise ValueError("Oversized cryptography source archive")
            if member.name not in wanted:
                continue
            if wanted[member.name] is not None or not member.isfile() or not 0 < member.size <= 1024 * 1024:
                raise ValueError("Invalid cryptography source inventory member")
            wanted[member.name] = archive.extractfile(member).read()
    if any(value is None for value in wanted.values()):
        raise ValueError("Cryptography source inventory is incomplete")
    project_data = wanted[f"cryptography-{version}/pyproject.toml"]
    project = tomllib.loads(project_data.decode("utf-8"))
    if (project.get("project", {}).get("name") != "cryptography"
            or project.get("project", {}).get("version") != version
            or project.get("tool", {}).get("maturin", {}).get("locked") is not True):
        raise ValueError("Cryptography source version or locked build policy differs")
    lock = wanted[f"cryptography-{version}/Cargo.lock"]
    components = lockfile_components(lock)
    for name in ("Cargo.lock", "pyproject.toml"):
        member = f"cryptography-{version}/{name}"
        MANIFEST.append(save(member, wanted[member], f"{url}#{member}"))
    provenance = {"version": version, "sdistUrl": url, "sdistSha256": expected,
                  "inventory": "All crates.io packages in the source Cargo.lock, including build and target-specific dependencies; not binary build attestation."}
    MANIFEST.append(save(f"cryptography-{version}/source-provenance.json",
                         (json.dumps(provenance, indent=2) + "\n").encode(), url))
    return components


def rust_components(distribution) -> list[dict]:
    sbom = distribution.read_text("sboms/cryptography-rust.cyclonedx.json")
    if sbom is None:
        return source_components(distribution.version)
    components = [item for item in json.loads(sbom).get("components", [])
                  if item.get("bom-ref", "").startswith("registry+")]
    if not components:
        raise ValueError("Missing Rust dependencies in installed wheel SBOM")
    for component in components:
        crate_identity(component)
    return components


def openssl_versions(native_sbom: str | None, *runtime_versions: str) -> set[str]:
    versions = {item["version"] for item in json.loads(native_sbom).get("components", [])
                if item["name"] == "openssl"} if native_sbom is not None else set()
    for runtime in runtime_versions:
        match = re.match(r"OpenSSL ([0-9]+\.[0-9]+\.[0-9]+)(?: |$)", runtime)
        if not match:
            raise ValueError("Unexpected OpenSSL version in the build environment")
        versions.add(match[1])
    if not versions or any(not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value) for value in versions):
        raise ValueError("Unexpected OpenSSL version in the build environment")
    return versions


def fetch(url: str, limit: int = 20 * 1024 * 1024) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "ConnectWallet-License-Bundler/1"})
    with urllib.request.urlopen(request, timeout=45) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError("License source exceeds the download limit")
    return data


def save(relative: str, data: bytes, source: str) -> dict:
    path = (OUTPUT / relative).resolve()
    if not path.is_relative_to(OUTPUT) or len(data) > 8 * 1024 * 1024:
        raise ValueError("Invalid license artifact path or size")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return {"file": relative, "source": source, "sha256": hashlib.sha256(data).hexdigest()}


def local_or_upstream(name: str, candidates: list[Path], url: str) -> None:
    for candidate in candidates:
        if candidate.is_file():
            MANIFEST.append(save(name, candidate.read_bytes(), f"installed CPython {sys.version.split()[0]}: {candidate.name}"))
            return
    MANIFEST.append(save(name, fetch(url, 1024 * 1024), url))


def crate_notices(component: dict) -> list[dict]:
    name, version, expected = crate_identity(component)
    url = f"https://static.crates.io/crates/{name}/{name}-{version}.crate"
    cached = CACHE / f"{expected}.crate"
    data = cached.read_bytes() if cached.is_file() else b""
    if hashlib.sha256(data).hexdigest() != expected:
        data = fetch(url)
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError(f"License source checksum differs from the dependency inventory: {name}")
        cached.write_bytes(data)
    result = []
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for member in archive.getmembers():
            if not member.isfile() or not re.match(r"(?i)^(license|licence|copying|notice|copyright)", Path(member.name).name):
                continue
            if member.size > 1024 * 1024 or len(result) >= 128:
                raise ValueError("Oversized third-party license archive")
            # Never extract an archive pathname into the filesystem.
            text = archive.extractfile(member).read()
            filename = f"{len(result):02d}-{Path(member.name).name}"
            result.append(save(f"rust/{name}-{version}/{filename}", text, f"{url}#{member.name}"))
    if not result:
        raise ValueError(f"No original license notice was found for {name} {version}")
    return result


def main() -> None:
    MANIFEST.clear()
    # Rebuild only this generated staging directory. Otherwise notices/SBOMs
    # from an older provider are silently shipped beside the new manifest.
    # Never follow a substituted link/junction to a different directory.
    if OUTPUT.resolve() != PROJECT / "tmp" / "claims-licenses" or OUTPUT.is_symlink():
        raise ValueError("Unexpected license staging directory")
    if OUTPUT.exists():
        shutil.rmtree(OUTPUT)
    OUTPUT.mkdir(parents=True, exist_ok=True)
    CACHE.mkdir(parents=True, exist_ok=True)
    version = ".".join(map(str, sys.version_info[:3]))
    base = Path(sys.base_prefix)
    local_or_upstream(f"python-{version}/LICENSE.txt", [base / "LICENSE.txt", base / "LICENSE"],
                      f"https://raw.githubusercontent.com/python/cpython/v{version}/LICENSE")
    local_or_upstream(f"python-{version}/third-party-license.rst", [base / "Doc/html/_sources/license.rst.txt"],
                      f"https://raw.githubusercontent.com/python/cpython/v{version}/Doc/license.rst")
    dependencies = ["cryptography", "cffi", "pycparser", "pyinstaller", "pyinstaller-hooks-contrib",
                    "altgraph", "packaging", "setuptools"]
    if sys.platform == "darwin":
        dependencies.append("macholib")
    for name in dependencies:
        distribution = metadata.distribution(name)
        copied = 0
        for file in distribution.files or []:
            path = Path(str(file))
            if re.match(r"(?i)^(license|licence|copying|notice|copyright)", path.name) or "sboms" in path.parts:
                source = Path(distribution.locate_file(file))
                destination = f"{name}-{distribution.version}/{copied:02d}-{path.name}"
                MANIFEST.append(save(destination, source.read_bytes(), f"installed {name}@{distribution.version}: {file}"))
                copied += 1
        if not copied:
            raise ValueError(f"No original license notice was found for {name}")
    crypto = metadata.distribution("cryptography")
    import cryptography
    from cryptography.hazmat.backends.openssl.backend import backend
    pins = re.findall(r"(?m)^cryptography==([0-9]+\.[0-9]+\.[0-9]+)$",
                      (PROJECT / "helpers/requirements.txt").read_text())
    if pins != [crypto.version] or cryptography.__version__ != crypto.version:
        raise ValueError("Installed cryptography does not match the exact provider pin")
    components = rust_components(crypto)
    for openssl_version in sorted(openssl_versions(crypto.read_text("sboms/sbom.json"),
                                                   backend.openssl_version_text(), ssl.OPENSSL_VERSION)):
        url = f"https://raw.githubusercontent.com/openssl/openssl/openssl-{openssl_version}/LICENSE.txt"
        MANIFEST.append(save(f"openssl-{openssl_version}/LICENSE.txt", fetch(url, 1024 * 1024), url))
    with ThreadPoolExecutor(max_workers=6) as executor:
        for notices in executor.map(crate_notices, components):
            MANIFEST.extend(notices)
    (OUTPUT / "manifest.json").write_text(json.dumps(sorted(MANIFEST, key=lambda value: value["file"]), indent=2) + "\n", encoding="utf-8")
    print(f"Collected {len(MANIFEST)} original runtime and dependency license/SBOM files.")


if __name__ == "__main__":
    main()
