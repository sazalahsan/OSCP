#!/bin/bash
# Automated enumeration wrapper for HackTheBox machines
# Usage: ./enum.sh <target-ip> <output-dir>

TARGET=$1
OUTPUT_DIR=${2:-.}

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target-ip> [output-dir]"
    exit 1
fi

echo "[*] Starting enumeration for $TARGET..."
echo "[*] Output directory: $OUTPUT_DIR"

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Phase 1: Quick port scan
echo "[*] Phase 1: Quick port scan..."
nmap -p- --open -T4 "$TARGET" -oN "$OUTPUT_DIR/quick-scan.txt"

# Extract open ports
PORTS=$(grep "^[0-9]" "$OUTPUT_DIR/quick-scan.txt" | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')

if [ -z "$PORTS" ]; then
    echo "[-] No open ports found. Exiting."
    exit 1
fi

echo "[+] Open ports: $PORTS"

# Phase 2: Detailed service scan
echo "[*] Phase 2: Service version detection..."
nmap -sV -sC -p "$PORTS" "$TARGET" -oN "$OUTPUT_DIR/service-scan.txt"

# Phase 3: HTTP enumeration (if port 80/443 open)
if echo "$PORTS" | grep -qE "80|443"; then
    echo "[*] Phase 3: HTTP enumeration..."
    
    # Attempt HTTP connection
    if echo "$PORTS" | grep -q "80"; then
        curl -i "http://$TARGET" > "$OUTPUT_DIR/http-response.txt" 2>&1
    fi
    
    if echo "$PORTS" | grep -q "443"; then
        curl -i "https://$TARGET" > "$OUTPUT_DIR/https-response.txt" 2>&1
    fi
    
    # Directory enumeration (requires ffuf or dirsearch)
    if command -v ffuf &> /dev/null; then
        echo "[*] Running ffuf for directory enumeration..."
        ffuf -u "http://$TARGET/FUZZ" -w /usr/share/wordlists/common.txt -o "$OUTPUT_DIR/ffuf-results.json" 2>/dev/null || echo "[-] ffuf directory list not found"
    fi
fi

# Phase 4: SMB enumeration (if port 445 open)
if echo "$PORTS" | grep -q "445"; then
    echo "[*] Phase 4: SMB enumeration..."
    
    if command -v enum4linux &> /dev/null; then
        enum4linux "$TARGET" > "$OUTPUT_DIR/enum4linux-results.txt" 2>&1
    fi
    
    smbclient -L "//$TARGET" -N > "$OUTPUT_DIR/smb-shares.txt" 2>&1 || echo "[-] SMB enumeration failed (may require credentials)"
fi

# Phase 5: Summary
echo ""
echo "[+] Enumeration complete!"
echo "[+] Results saved to: $OUTPUT_DIR"
echo ""
echo "=== Summary ==="
echo "Quick scan: $OUTPUT_DIR/quick-scan.txt"
echo "Service scan: $OUTPUT_DIR/service-scan.txt"

if [ -f "$OUTPUT_DIR/http-response.txt" ]; then
    echo "HTTP response: $OUTPUT_DIR/http-response.txt"
fi

if [ -f "$OUTPUT_DIR/enum4linux-results.txt" ]; then
    echo "SMB enum: $OUTPUT_DIR/enum4linux-results.txt"
fi
