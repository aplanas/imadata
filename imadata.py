"""Expand repomd metadata with IMA hashes."""

import argparse
import gzip
import hashlib
import multiprocessing
import os
import pathlib
import shutil
import xml.etree.ElementTree as ET

import rpm


def analyze(pkg):
    """Analyze a single RPM package."""
    ts = rpm.TransactionSet()
    ts.setVSFlags(rpm._RPMVSF_NOSIGNATURES | rpm._RPMVSF_NODIGESTS)

    info = {}
    fd = os.open(pkg, os.O_RDONLY)
    hdr = ts.hdrFromFdno(fd)
    os.close(fd)
    info.update(
        (n, hdr[k])
        for n, k in (
            ("name", rpm.RPMTAG_NAME),
            ("arch", rpm.RPMTAG_ARCH),
            ("src", rpm.RPMTAG_SOURCEPACKAGE),
            ("epoch", rpm.RPMTAG_EPOCH),
            ("ver", rpm.RPMTAG_VERSION),
            ("rel", rpm.RPMTAG_RELEASE),
        )
    )
    # TODO - How are symbolic links managed with IMA
    # TODO - How to detect a link in RPM
    info["files"] = [(f.name, f.digest) for f in rpm.files(hdr) if f.digest != "0" * 64]

    return info


def analyze_all(repository, jobs):
    """Analyze all the RPMs in parallel."""
    with multiprocessing.Pool(jobs) as pool:
        packages = pool.map(analyze, repository.glob("**/*.rpm"))

    return packages


def imadata_xml(packages):
    """Create the imadata.xml file."""
    imadata = args.repository / "repodata" / "imadata.xml"

    with open(imadata, "w") as f:
        f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
        f.write(f'<imadata packages="{len(packages)}">\n')
        for pkg in sorted(packages, key=lambda x: x["name"]):
            f.write(
                f'<package name="{pkg["name"]}" arch="{"src" if pkg["src"] else pkg["arch"]}">\n'
            )
            f.write(
                f'  <version epoch="{pkg["epoch"] or 0}" ver="{pkg["ver"]}" rel="{pkg["rel"]}"/>\n'
            )
            for name, hash_ in pkg["files"]:
                f.write(f'  <file hash="{hash_}">{name}</file>\n')
            f.write("</package>\n")
        f.write("</imadata>")

    return imadata


def file_hash(path):
    """Calculate the hash for a filename."""
    m = hashlib.sha256()
    with path.open("rb") as f:
        m.update(f.read())
    return m.hexdigest()


def gzip_file(path):
    """Gzip a file and remove the original."""
    path_gz = path.with_suffix(imadata.suffix + ".gz")
    with path.open("rb") as f_in:
        # The gzip header contains a timestamp, this will make two
        # compressions with the same content but at different time,
        # different in terms of SHA256
        with gzip.open(path_gz, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)
    path.unlink()

    return path_gz


def indent(elem, level=0):
    """Indent a subelement.  Present in Python 3.9"""
    if len(elem):
        elem.text = "\n" + (level + 1) * "  "
        elem.tail = "\n" + (level - 1) * "  "
        for subelem in elem:
            indent(subelem, level + 1)
        elem[-1].tail = "\n" + level * "  "
    else:
        elem.tail = "\n" + level * "  "
    return elem


def add_repomd(repository, data, open_checksum, open_size, checksum, size, timestamp):
    """Add new data entry into the repomd.xml file."""
    tree = ET.parse(repository / "repodata" / "repomd.xml")
    root = tree.getroot()

    ET.register_namespace("", "http://linux.duke.edu/metadata/repo")
    ET.register_namespace("rpm", "http://linux.duke.edu/metadata/rpm")
    for e in root.findall("{http://linux.duke.edu/metadata/repo}data"):
        if e.attrib["type"] == "imadata":
            print("ERROR: data type imadata already present")
            exit(-1)

    # Only for indentation pourposes
    root[-1].tail = "\n  "

    data_element = ET.SubElement(root, "data", {"type": "imadata"})
    ET.SubElement(data_element, "checksum", {"type": "sha256"}).text = checksum
    ET.SubElement(
        data_element, "open-checksum", {"type": "sha256"}
    ).text = open_checksum
    ET.SubElement(
        data_element, "location", {"href": f"repodata/{checksum}_{data.name}"}
    )
    ET.SubElement(data_element, "timestamp").text = str(int(timestamp))
    ET.SubElement(data_element, "size").text = str(size)
    ET.SubElement(data_element, "open-size").text = str(open_size)

    indent(data_element, level=1)
    tree.write(
        repository / "repodata" / "repomd.xml", encoding="UTF-8", xml_declaration=True
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Expand repomd metadata with IMA hashes"
    )
    parser.add_argument(
        "repository", metavar="REPO", type=pathlib.Path, help="path of the repository"
    )
    parser.add_argument(
        "-j",
        "--jobs",
        metavar="N",
        type=int,
        default=multiprocessing.cpu_count(),
        help="allow N jobs at one. #CPUs with no arg",
    )
    parser.add_argument(
        "-m", "--modify", action="store_true", help="modify the repo data, using Python"
    )

    args = parser.parse_args()

    imadata = imadata_xml(analyze_all(args.repository, args.jobs))

    if args.modify:
        open_checksum = file_hash(imadata)
        open_size = imadata.stat().st_size

        imadata_gz = gzip_file(imadata)

        checksum = file_hash(imadata_gz)
        size = imadata_gz.stat().st_size
        timestamp = imadata_gz.stat().st_ctime

        imadata_gz.rename(imadata_gz.with_name(f"{checksum}-{imadata_gz.name}"))

        add_repomd(
            args.repository,
            imadata_gz,
            open_checksum,
            open_size,
            checksum,
            size,
            timestamp,
        )
