#!/bin/bash
# Script to check DNS records for a domain
# Usage: ./dns_check.sh domain.com

if [ $# -eq 0 ]; then
    echo "Usage: $0 domain.com"
    exit 1
fi

DOMAIN=$1
OUTPUT_DIR="/tmp/dns_checks"
mkdir -p $OUTPUT_DIR

# Cleanup previous output
rm -f $OUTPUT_DIR/${DOMAIN}_*.txt

echo "Checking DNS records for $DOMAIN..."
echo "Output directory: $OUTPUT_DIR"

# Function to run dig and capture full output
run_dig() {
    local record_type=$1
    local domain=$2
    local output_file=$3
    
    echo "Running: dig $record_type $domain"
    
    # Run the dig command with full output (not just +short) to see errors too
    dig $record_type $domain > "$output_file"
    
    # Also save the short version to a separate file for easier parsing
    dig $record_type $domain +short > "${output_file}.short"
    
    # Check if the command succeeded and files were created
    if [ -f "$output_file" ]; then
        echo "Successfully wrote full output to $output_file"
        echo "File size: $(du -h $output_file | cut -f1)"
        echo "Content preview: $(head -n 1 $output_file)"
    else
        echo "ERROR: Failed to write to $output_file"
    fi
    
    if [ -f "${output_file}.short" ]; then
        echo "Successfully wrote short output to ${output_file}.short"
        echo "File size: $(du -h ${output_file}.short | cut -f1)"
        echo "Content: $(cat ${output_file}.short)"
    else
        echo "ERROR: Failed to write to ${output_file}.short"
    fi
}

# Check SPF Records
echo "Checking SPF Records..."
run_dig "TXT" "$DOMAIN" "$OUTPUT_DIR/${DOMAIN}_spf.txt"

# Check DMARC Records
echo "Checking DMARC Records..."
run_dig "TXT" "_dmarc.$DOMAIN" "$OUTPUT_DIR/${DOMAIN}_dmarc.txt"

# Check DKIM Records with common selectors
echo "Checking DKIM Records..."
SELECTORS=("default" "google" "dkim" "k1" "selector1" "selector2" "mail")
for selector in "${SELECTORS[@]}"; do
    echo "Checking selector $selector..."
    run_dig "TXT" "${selector}._domainkey.$DOMAIN" "$OUTPUT_DIR/${DOMAIN}_dkim_${selector}.txt"
done

# Check MX Records
echo "Checking MX Records..."
run_dig "MX" "$DOMAIN" "$OUTPUT_DIR/${DOMAIN}_mx.txt"

# List all files created
echo "Listing all created files:"
ls -la $OUTPUT_DIR/${DOMAIN}_*

echo "All DNS checks completed."
echo "Results stored in $OUTPUT_DIR/"