#!/bin/bash
set -euo pipefail

# Build and publish MillWorks.Cryptography packages to the local NuGet feed.
# For local development; CI is the primary publish path.

LOCAL_REPO_PATH="${HOME}/LocalNuGetPackages"
VERSION=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -p|--path) LOCAL_REPO_PATH="$2"; shift 2 ;;
        -v|--version) VERSION="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [-p|--path PATH] [-v|--version VERSION]"
            exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Default the version from Directory.Build.props.
if [ -z "$VERSION" ]; then
    VERSION=$(sed -n 's/.*<Version>\([^<]*\)<\/Version>.*/\1/p' Directory.Build.props | head -1)
    if [ -z "$VERSION" ]; then
        echo "ERROR: could not read <Version> from Directory.Build.props; pass -v"
        exit 1
    fi
fi

mkdir -p "$LOCAL_REPO_PATH"

# Packable projects, in dependency order (Abstractions before the implementations).
projects=(
    "src/MillWorks.Cryptography.Abstractions"
    "src/MillWorks.Cryptography"
    "src/MillWorks.Cryptography.FileSystem"
    "src/MillWorks.Cryptography.KeyVault"
)

echo "MillWorks.Cryptography v${VERSION} -> ${LOCAL_REPO_PATH}"

for project in "${projects[@]}"; do
    name=$(basename "$project")
    csproj="$PWD/$project/$name.csproj"
    echo "Packing $name..."
    dotnet pack "$csproj" --configuration Release --output "$LOCAL_REPO_PATH" /p:Version="$VERSION"
done

echo "Done. Packages written to $LOCAL_REPO_PATH:"
ls -1 "$LOCAL_REPO_PATH" | grep "MillWorks.Cryptography" | grep "$VERSION" || true
