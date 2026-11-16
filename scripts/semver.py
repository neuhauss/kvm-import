"""Small SemVer helpers shared by the release and deployment scripts."""

import re


_SEMVER = re.compile(
    r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?"
)


def version_key(value: str) -> tuple:
    """Return a sortable SemVer key, with stable releases above prereleases."""
    match = _SEMVER.fullmatch(value)
    if not match:
        raise ValueError(f"Invalid semantic version: {value!r}")
    major, minor, patch, prerelease = match.groups()
    identifiers = () if prerelease is None else tuple(
        (0, int(item)) if item.isdigit() else (1, item)
        for item in prerelease.split(".")
    )
    return (int(major), int(minor), int(patch), 1 if prerelease is None else 0, identifiers)


def version_after(value: str) -> str:
    """Return the next patch for stable versions, or next prerelease iteration."""
    match = _SEMVER.fullmatch(value)
    if not match:
        raise ValueError(f"Invalid semantic version: {value!r}")
    major, minor, patch, prerelease = match.groups()
    if prerelease is None:
        return f"{major}.{minor}.{int(patch) + 1}"
    identifiers = prerelease.split(".")
    if identifiers[-1].isdigit():
        identifiers[-1] = str(int(identifiers[-1]) + 1)
    else:
        identifiers.append("1")
    return f"{major}.{minor}.{patch}-" + ".".join(identifiers)
