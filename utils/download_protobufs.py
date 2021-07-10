import re
import os
import zipfile

import requests
import structlog

from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence, Optional

from grpc_tools import protoc

utf8 = "utf-8"

structlog.configure()
logger = structlog.get_logger()


@dataclass(frozen=True)
class Source:
    """
    Class representing a source archive to be downloaded and extracted.

    By default, files are extracted to a directory named `name`. An alternate
    directory can be specified with `output`.

    The root folder of a source archive is always discarded, such that `root` is
    equivalent to the repository root.

    If an alternate `root` is specified, `pattern` is evaluated against
    filenames relative to root. Extracted filenames are relative to `root`. i.e.
    the `root` portion of filename is discarded during extraction.

    Attributes
    ----------
    name (str): name of the source, used as `output` by default
    url (str): URL for the archive
    pattern (Pattern): regex pattern used to filter archive contents
    root (Path): directory in the archive to treat as root
    output (Path): directory to which files are extracted (defaults to `name`)
    """

    name: str
    url: str
    pattern: re.Pattern = re.compile(r"^.*\.proto$")
    root: Path = Path("")
    output: Optional[Path] = None


sources: Sequence[Source] = (
    Source(
        "envoy",
        "https://github.com/envoyproxy/data-plane-api/archive/master.zip",
        root=Path("envoy"),
    ),
    Source(
        "google",
        "https://github.com/googleapis/googleapis/archive/master.zip",
        pattern=re.compile(r"^(api|rpc)/.*\.proto$"),
        root=Path("google"),
    ),
    Source(
        "udpa", "https://github.com/cncf/udpa/archive/master.zip", root=Path("udpa")
    ),
    Source(
        "validate",
        "https://github.com/envoyproxy/protoc-gen-validate/archive/master.zip",
        root=Path("validate"),
    ),
    Source(
        "protobuf",
        "https://github.com/protocolbuffers/protobuf/archive/master.zip",
        root=Path("src/google/protobuf"),
        output=Path("google/protobuf"),
    ),
    Source(
        "opencensus",
        "https://github.com/census-instrumentation/opencensus-proto/archive/master.zip",
        root=Path("src/opencensus"),
    ),
    Source(
        "prometheus", "https://github.com/prometheus/client_model/archive/master.zip", output=Path(".")
    ),
)

# TODO build dir context mgr
build_directory = Path("BUILD")
if not build_directory.exists():
    logger.msg("Creating BUILD directory")
    build_directory.mkdir()
os.chdir(build_directory)

for source in sources:
    namespace = Path(source.name)
    archive = Path(f"{source.name}.zip")

    # TODO: def get_archive(url, out_file)
    if not archive.exists():
        logger.msg(f"Downloading {source.name} protocol buffers from Github")
        with open(archive, "wb+") as zf:
            zf.write(requests.get(source.url).content)

    source_root_len = len(source.root.parts)
    # TODO: def extract_archive(in_file, out_dir)
    if True or not namespace.exists():
        output = source.output or Path(source.name)
        logger.msg(f"Extracting {namespace} archive")
        with zipfile.ZipFile(archive, "r") as zipref:
            for info in zipref.infolist():
                # TODO: def filter_archive(zipref, pattern, root)
                info_path = Path(info.filename)
                info_parts = info_path.parts
                # strip the repo archive name e.g. {repo}-master
                local_parts = info_parts[1:]
                if local_parts[0:source_root_len] != source.root.parts:
                    # skip files outside root
                    continue
                # TODO: def rewrite_archive_filename(info, root, out_dir)
                norm_local_path = Path().joinpath(*local_parts[source_root_len:])
                if not source.pattern.fullmatch(str(norm_local_path)):
                    # skip files not matching pattern
                    continue
                info.filename = str(output / norm_local_path)
                zipref.extract(info)
    else:
        logger.msg(f"{namespace.absolute()} exists")

output = Path("../src/envoy_data_plane")
# TODO: betterproto doesn't work well with Any; no Pack() method
proto_args = ["grpc_tools.protoc", f"--python_betterproto_out={output}"]


def everything():
    args = deepcopy(proto_args)
    logger.msg("Running GRPC tools to generate python code from protocol buffers")
    # TODO: itertools chunk see: https://www.in-ulm.de/~mascheck/various/argmax/
    protoc.main((*args,  *map(str, Path("envoy").glob("**/*.proto"))))


def xds():
    v2_protos = Path("envoy/api/v2").glob("*ds.proto")
    v3_protos = Path("envoy/service").glob("**/v3/*ds.proto")
    protoc.main([*proto_args, *map(str, (*v2_protos, *v3_protos))])


everything()
# xds()
