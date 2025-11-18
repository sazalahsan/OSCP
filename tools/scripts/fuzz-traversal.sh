#!/usr/bin/env bash
# fuzz-traversal.sh — small wrapper to fuzz path-traversal vectors using ffuf or wfuzz
# Usage examples:
#  bash scripts/fuzz-traversal.sh -u "https://target/loadImage?filename=FUZZ" 
#  bash scripts/fuzz-traversal.sh -u "https://target/loadImage?filename=FUZZ" -w resources/path_traversal_payloads.txt -t ffuf
#  bash scripts/fuzz-traversal.sh -u "https://target/file/FUZZ" -t wfuzz

set -euo pipefail

URL=""
WORDLIST="resources/path_traversal_payloads.txt"
TOOL="ffuf"    # ffuf or wfuzz
OUTDIR="fuzz-results"
THREADS=40

print_usage(){
  cat <<EOF
Usage: $0 -u <url-with-FUZZ> [-w <wordlist>] [-t ffuf|wfuzz] [-o <outdir>] [-T <threads>]
Example:
  $0 -u "https://target/loadImage?filename=FUZZ" -w resources/path_traversal_payloads.txt -t ffuf

Notes:
- URL must contain the literal string FUZZ where the payload should be placed.
- Default wordlist: resources/path_traversal_payloads.txt
- This script does not alter payloads; tune ffuf/wfuzz flags for your environment.
EOF
}

while getopts ":u:w:t:o:T:h" opt; do
  case ${opt} in
    u ) URL=$OPTARG ;;
    w ) WORDLIST=$OPTARG ;;
    t ) TOOL=$OPTARG ;;
    o ) OUTDIR=$OPTARG ;;
    T ) THREADS=$OPTARG ;;
    h ) print_usage; exit 0 ;;
    \? ) echo "Invalid option: -$OPTARG" 1>&2; print_usage; exit 1 ;;
    : ) echo "Invalid option: -$OPTARG requires an argument" 1>&2; print_usage; exit 1 ;;
  esac
done

if [[ -z "$URL" ]]; then
  echo "Error: URL (-u) is required." >&2
  print_usage
  exit 1
fi

mkdir -p "$OUTDIR"
TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
BASEOUT="$OUTDIR/$(echo "$URL" | sed 's/[^a-zA-Z0-9]/_/g')_$TIMESTAMP"

if [[ "$TOOL" == "ffuf" ]]; then
  if ! command -v ffuf >/dev/null 2>&1; then
    echo "ffuf not found in PATH. Install ffuf or choose -t wfuzz." >&2
    exit 2
  fi
  # Run ffuf with common filtering: show 200/302/403 and content-length spikes
  echo "Running ffuf against: $URL"
  ffuf -u "$URL" -w "$WORDLIST" -mc 200,302,403 -fs 0 -t "$THREADS" -o "${BASEOUT}.ffuf" -of json
  echo "ffuf results saved to ${BASEOUT}.ffuf"
elif [[ "$TOOL" == "wfuzz" ]]; then
  if ! command -v wfuzz >/dev/null 2>&1; then
    echo "wfuzz not found in PATH. Install wfuzz or choose -t ffuf." >&2
    exit 2
  fi
  echo "Running wfuzz against: $URL"
  # Basic wfuzz invocation: -c color, -w wordlist, -t threads; adjust -b cookie or -H headers as needed
  wfuzz -c -w "$WORDLIST" -t "$THREADS" "$URL" -o "%d" > "${BASEOUT}.wfuzz"
  echo "wfuzz results saved to ${BASEOUT}.wfuzz"
else
  echo "Unknown tool: $TOOL" >&2
  print_usage
  exit 1
fi

# Quick summary: extract interesting lines from ffuf JSON if present
if [[ -f "${BASEOUT}.ffuf" ]]; then
  echo "Summary of ffuf hits (status, length, url):"
  jq -r '.results[] | [.status, .length, .url] | @tsv' "${BASEOUT}.ffuf" 2>/dev/null || true
fi

echo "Done. Inspect '${OUTDIR}' for raw output and save any promising request/response pairs for reporting."