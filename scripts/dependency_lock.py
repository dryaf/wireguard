"""Generate and verify dependency locks. Runs exclusively in the tool containers."""

import hashlib
import json
from pathlib import Path, PurePosixPath
import posixpath
import re
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
LOCKS = ROOT / "locks"
INPUTS = ("requirements.in", "requirements-dev.in", "requirements.txt", "requirements-dev.txt", "requirements.yml")
LOCK_FILES = ("requirements.lock", "requirements-dev.lock", "collections.lock.json")
SUMMED_FILES = (*INPUTS, *(f"locks/{name}" for name in LOCK_FILES))
GALAXY = "https://galaxy.ansible.com"


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def check_entrypoints():
    for filename, lock in (("requirements.txt", "requirements.lock"),
                           ("requirements-dev.txt", "requirements-dev.lock")):
        lines = [line.strip() for line in (ROOT / filename).read_text().splitlines()
                 if line.strip() and not line.lstrip().startswith("#")]
        if lines != ["--require-hashes", "--only-binary=:all:", f"-r locks/{lock}"]:
            raise ValueError(f"{filename} must reference its complete hashed lock; edit the .in file instead")


def check_locks():
    check_entrypoints()
    entries = {}
    for line in (LOCKS / "manifest.sha256").read_text().splitlines():
        digest, name = line.split("  ", 1)
        if name not in SUMMED_FILES or name in entries:
            raise ValueError("Unexpected dependency file in manifest.sha256")
        entries[name] = digest
    if set(entries) != set(SUMMED_FILES):
        raise ValueError("Incomplete dependency checksums; run make deps-lock")
    for name, digest in entries.items():
        if sha256(ROOT / name) != digest:
            raise ValueError(f"Dependency checksum mismatch for {name}; run make deps-lock")


class HTTPSRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme != "https":
            raise ValueError("Refusing a non-HTTPS dependency redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(url, destination, expected_hash=None, limit=128 * 1024 * 1024):
    if urllib.parse.urlsplit(url).scheme != "https":
        raise ValueError("Dependency downloads must use HTTPS")
    opener = urllib.request.build_opener(HTTPSRedirects())
    digest = hashlib.sha256()
    total = 0
    try:
        with opener.open(url, timeout=60) as response, Path(destination).open("wb") as output:
            while data := response.read(1024 * 1024):
                total += len(data)
                if total > limit:
                    raise ValueError("Dependency download exceeded its size limit")
                digest.update(data)
                output.write(data)
        if expected_hash is not None and digest.hexdigest() != expected_hash:
            raise ValueError(f"SHA-256 mismatch for {Path(destination).name}")
    except BaseException:
        Path(destination).unlink(missing_ok=True)
        raise


def collection_manifest(archive):
    with tarfile.open(archive, "r:gz") as collection:
        # Validate every path before handing anything to Galaxy. Hash checks
        # alone do not make a newly approved upstream archive safe to extract.
        entries, total = {}, 0
        for entry in collection:
            path = PurePosixPath(entry.name)
            name = str(path)
            if path.is_absolute() or ".." in path.parts or "\\" in entry.name:
                raise ValueError("Unsafe collection archive path")
            if not (entry.isfile() or entry.isdir() or entry.issym()):
                raise ValueError("Collection hard links and special files are not supported")
            if name in entries:
                raise ValueError("Duplicate collection archive path")
            entries[name] = entry
            total += entry.size
            if total > 512 * 1024 * 1024 or len(entries) > 100000:
                raise ValueError("Collection archive exceeds extraction limits")
        for name, entry in entries.items():
            for parent in PurePosixPath(name).parents:
                if str(parent) in entries and not entries[str(parent)].isdir():
                    raise ValueError("Collection member has a non-directory archive ancestor")
            if entry.issym():
                # Existing collections contain file aliases. Permit only direct
                # links to regular files in this archive, never directory/link
                # chains that could redirect a subsequent extraction.
                target = posixpath.normpath(posixpath.join(str(PurePosixPath(name).parent), entry.linkname))
                if entry.linkname.startswith("/") or "\\" in entry.linkname or target not in entries or not entries[target].isfile():
                    raise ValueError("Unsafe collection symbolic link")
        member = collection.getmember("MANIFEST.json")
        if not member.isfile() or member.size > 2 * 1024 * 1024:
            raise ValueError("Invalid collection manifest")
        with collection.extractfile(member) as stream:
            return json.load(stream)["collection_info"]


def check_collection_lock(data):
    if data.get("format") != 1 or not data.get("collections"):
        raise ValueError("Missing or unsupported collection lock")
    entries = {}
    for entry in data["collections"]:
        name = entry["name"]
        version = entry["version"]
        if not re.fullmatch(r"[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*", name):
            raise ValueError("Invalid collection name")
        if not re.fullmatch(r"\d+\.\d+\.\d+", version):
            raise ValueError("Only stable collection releases may be locked")
        if name in entries or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]):
            raise ValueError("Duplicate collection or invalid SHA-256")
        namespace, collection = name.split(".")
        expected_url = f"{GALAXY}/api/v3/plugin/ansible/content/published/collections/artifacts/{namespace}-{collection}-{version}.tar.gz"
        if entry["url"] != expected_url:
            raise ValueError("Unexpected collection artifact URL")
        entries[name] = entry
    for entry in entries.values():
        for dependency in entry["dependencies"]:
            if dependency not in entries:
                raise ValueError(f"Unpinned transitive collection: {dependency}")
    return entries


def check_collection_constraints(data):
    # Called with the hashed controller environment, where these are installed.
    from packaging.specifiers import SpecifierSet
    from packaging.version import Version
    import yaml

    entries = check_collection_lock(data)
    roots = yaml.safe_load((ROOT / "requirements.yml").read_text())["collections"]
    constraints = [(entry["name"], str(entry["version"])) for entry in roots]
    for entry in entries.values():
        constraints.extend(entry["dependencies"].items())
    for name, constraint in constraints:
        if name not in entries:
            raise ValueError(f"Required collection missing from lock: {name}")
        if constraint == "*":
            continue
        if re.fullmatch(r"\d+\.\d+\.\d+", constraint):
            constraint = "==" + constraint
        if Version(entries[name]["version"]) not in SpecifierSet(constraint):
            raise ValueError(f"Locked collection {name} does not satisfy {constraint}")
    reachable = set()

    def visit(name):
        if name not in reachable:
            reachable.add(name)
            for dependency in entries[name]["dependencies"]:
                visit(dependency)

    for entry in roots:
        visit(entry["name"])
    if reachable != set(entries):
        raise ValueError("Collection lock contains dependencies unrelated to requirements.yml")
    return entries


def update():
    check_entrypoints()
    LOCKS.mkdir(exist_ok=True)
    # Stage all outputs first. Failed resolution leaves the committed locks intact.
    with tempfile.TemporaryDirectory() as temporary:
        temporary = Path(temporary)
        for source, output, constraints in (
            ("requirements.in", "requirements.lock", []),
            ("requirements-dev.in", "requirements-dev.lock", ["--constraint", str(temporary / "requirements.lock")]),
        ):
            subprocess.run([
                "uv", "pip", "compile", str(ROOT / source), "--upgrade", "--generate-hashes",
                "--no-build", "--python", sys.executable,
                "--custom-compile-command", "make deps-lock", "--output-file", str(temporary / output),
                *constraints,
            ], check=True, stdout=subprocess.DEVNULL)
            # uv annotates constraint filenames; don't commit random temp paths.
            path = temporary / output
            path.write_text("".join(
                line.replace(str(temporary / "requirements.lock"), "locks/requirements.lock")
                if line.lstrip().startswith("#") else line
                for line in path.read_text().splitlines(keepends=True)
            ))
        environment = temporary / "venv"
        subprocess.run(["uv", "venv", "--python", sys.executable, str(environment)], check=True)
        subprocess.run([
            "uv", "pip", "install", "--python", str(environment / "bin/python"),
            "--require-hashes", "--no-build", "-r", str(temporary / "requirements.lock"),
        ], check=True)
        archives = temporary / "collections"
        subprocess.run([
            str(environment / "bin/ansible-galaxy"), "collection", "download",
            "--requirements-file", str(ROOT / "requirements.yml"), "--download-path", str(archives),
        ], check=True)
        entries = []
        for archive in sorted(archives.glob("*.tar.gz")):
            info = collection_manifest(archive)
            namespace, name, version = info["namespace"], info["name"], info["version"]
            metadata_file = temporary / "metadata.json"
            download(
                f"{GALAXY}/api/v3/plugin/ansible/content/published/collections/index/{namespace}/{name}/versions/{version}/",
                metadata_file, limit=8 * 1024 * 1024,
            )
            metadata = json.loads(metadata_file.read_text())
            digest = sha256(archive)
            if metadata["artifact"]["sha256"] != digest:
                raise ValueError(f"Galaxy checksum mismatch for {archive.name}")
            entries.append({
                "name": f"{namespace}.{name}", "version": version, "sha256": digest,
                "url": f"{GALAXY}/api/v3/plugin/ansible/content/published/collections/artifacts/{namespace}-{name}-{version}.tar.gz",
                "dependencies": info.get("dependencies", {}),
            })
        data = {"format": 1, "collections": sorted(entries, key=lambda entry: entry["name"])}
        check_collection_lock(data)
        (temporary / "collections.lock.json").write_text(json.dumps(data, indent=2) + "\n")
        subprocess.run([
            str(environment / "bin/python"), str(Path(__file__).resolve()),
            "check-collections", str(temporary / "collections.lock.json"),
        ], check=True)
        (temporary / "manifest.sha256").write_text(
            "".join(f"{sha256(ROOT / name)}  {name}\n" for name in INPUTS)
            + "".join(f"{sha256(temporary / name)}  locks/{name}\n" for name in LOCK_FILES)
        )
        # Commit the full lock-set fingerprint last: interrupted writes fail the next build.
        for name in (*LOCK_FILES, "manifest.sha256"):
            staged = LOCKS / (name + ".tmp")
            staged.write_bytes((temporary / name).read_bytes())
            staged.replace(LOCKS / name)
    print("Updated Python and Ansible collection locks. Review the diff, then run make test syntax-check audit.")


def install_collections():
    check_locks()
    entries = check_collection_constraints(json.loads((LOCKS / "collections.lock.json").read_text()))
    with tempfile.TemporaryDirectory() as temporary:
        archives = []
        for name, entry in entries.items():
            archive = Path(temporary) / f"{name}-{entry['version']}.tar.gz"
            download(entry["url"], archive, entry["sha256"])
            info = collection_manifest(archive)
            if (f"{info['namespace']}.{info['name']}", info["version"], info.get("dependencies", {})) != (name, entry["version"], entry["dependencies"]):
                raise ValueError(f"Collection manifest disagrees with lock: {name}")
            archives.append(str(archive))
        # Nothing is unpacked or installed until every archive has passed verification.
        subprocess.run([
            "ansible-galaxy", "collection", "install", "--offline", "--no-deps",
            "--collections-path", "/opt/collections", *archives,
        ], check=True)


if __name__ == "__main__":
    try:
        Path("/tmp/wireguard").mkdir(mode=0o700, exist_ok=True)
        if sys.argv[1] == "check-collections":
            check_collection_constraints(json.loads(Path(sys.argv[2]).read_text()))
        else:
            {"deps-lock": update, "check": check_locks, "install-collections": install_collections}[sys.argv[1]]()
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        sys.exit(str(error))
