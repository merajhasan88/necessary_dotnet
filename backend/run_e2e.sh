#!/usr/bin/env bash
# Runs the package's end-to-end test (tests/NecessarySdk.Tests/BackendE2ETests.cs)
# against one of the sample backends:
#
#     backend/run_e2e.sh python|typescript|csharp [port]
#
# It starts the backend with its test controls on, waits until it answers,
# runs the test against it, and stops it. PYTHON, NODE and DOTNET name the
# interpreters when they are not on the PATH -- DOTNET the one that runs the C#
# sample, on .NET 10; TEST_DOTNET the one that runs the test. Build the
# TypeScript and C# samples first (npm ci && npm run build; dotnet build -c Release).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
package=$(dirname "$here")
schema=${NECESSARY_SCHEMA:-$package/contract/report-1/android-8-ios-5/report.schema.json}
port=${2:-8787}
case "${1:-}" in
  python) command=("${PYTHON:-python3}" "$here/python/server.py") ;;
  typescript) command=("${NODE:-node}" "$here/typescript/dist/server.js") ;;
  csharp) command=("${DOTNET:-dotnet}" "$here/csharp/bin/Release/net10.0/SampleBackend.dll") ;;
  *) echo "usage: $0 python|typescript|csharp [port]" >&2; exit 2 ;;
esac
# The test controls answer only this run's token.
token=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
SAMPLE_TEST_TOKEN=$token "${command[@]}" --port "$port" --schema "$schema" --test-controls &
server=$!
trap 'kill "$server" 2>/dev/null || true; wait "$server" 2>/dev/null || true' EXIT
curl -fs --retry 30 --retry-connrefused --retry-delay 1 "http://127.0.0.1:$port/health" >/dev/null
NECESSARY_BACKEND_URL="http://127.0.0.1:$port" NECESSARY_TEST_TOKEN=$token \
  "${TEST_DOTNET:-dotnet}" test "$package/tests/NecessarySdk.Tests" \
  --filter "FullyQualifiedName~BackendE2ETests" --logger "console;verbosity=normal"
