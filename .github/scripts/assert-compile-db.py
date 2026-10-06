#!/usr/bin/env python3
"""Require usable compiler invocations for every requested translation unit.

Bear only records compilations it observes. A restored or incremental build can
leave a valid but incomplete database; scanner exit status alone is not proof
that every owned source was analysed.
"""

import json
import os
import shlex
import sys


def compile_arguments(entry, name):
    """Read the preferred argv representation and reject malformed commands."""
    # arguments is the preferred representation. Do not accept a valid command
    # string in its place when an invalid arguments field is also present.
    if "arguments" in entry:
        arguments = entry["arguments"]
    else:
        command = entry.get("command")
        if not isinstance(command, str):
            raise ValueError(f"entry for {name} has no command/arguments")
        arguments = shlex.split(command)
    if (not isinstance(arguments, list) or len(arguments) < 2
            or not all(isinstance(arg, str) and "\0" not in arg for arg in arguments)
            or not arguments[0].strip()):
        raise ValueError(f"entry for {name} has no usable command/arguments")

    return arguments


def source_path(entry):
    """Validate one compilation database entry and return its canonical source."""
    if not isinstance(entry, dict):
        raise TypeError("entry is not an object")
    name = entry.get("file")
    directory = entry.get("directory")
    if not isinstance(name, str) or not name.strip() or "\0" in name:
        raise ValueError("entry has no valid file")
    if (not isinstance(directory, str) or "\0" in directory
            or not os.path.isabs(directory) or not os.path.isdir(directory)):
        raise ValueError(f"entry for {name} has no usable working directory")

    arguments = compile_arguments(entry, name)

    source = os.path.realpath(os.path.join(directory, name))
    if not os.path.isfile(source):
        raise ValueError(f"entry source does not exist: {source}")
    if not any(os.path.realpath(os.path.join(directory, arg)) == source
               for arg in arguments[1:] if arg):
        raise ValueError(f"command does not name its source: {source}")
    return source


def main(argv):
    if len(argv) < 3:
        print("usage: assert-compile-db.py <compile_commands.json> <file.c>...",
              file=sys.stderr)
        return 2

    db_path, sources = argv[1], argv[2:]
    try:
        with open(db_path, encoding="utf-8") as handle:
            entries = json.load(handle)
        if not isinstance(entries, list):
            raise TypeError("compile DB is not a JSON array")
        covered = {source_path(entry) for entry in entries}
    except (OSError, TypeError, ValueError) as exc:
        print(f"FATAL: unusable compile DB {db_path}: {exc}", file=sys.stderr)
        return 1

    print(f"compile DB entries: {len(entries)}")
    missing = [name for name in sources if os.path.realpath(name) not in covered]
    for name in missing:
        print(f"FATAL: no compile_commands.json entry for {name}", file=sys.stderr)
    if missing:
        print(f"FATAL: compile DB covers {len(sources) - len(missing)} of "
              f"{len(sources)} translation units; refusing incomplete analysis",
              file=sys.stderr)
        return 1

    print(f"compile DB covers all {len(sources)} translation unit(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
