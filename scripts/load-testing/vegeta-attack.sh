#!/bin/bash
# Vegeta load testing script for Prism
# Install: go install github.com/tsenart/vegeta@latest
# Run: ./scripts/load-testing/vegeta-attack.sh

set -euo pipefail

# Configuration
PRISM_URL="${PRISM_URL:-http://localhost:8080}"
DURATION="${DURATION:-30s}"
RATE="${RATE:-100}"  # requests per second
OUTPUT_DIR="${OUTPUT_DIR:-./load-test-results}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}      PRISM VEGETA LOAD TEST${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Target:   $PRISM_URL"
echo "Rate:     $RATE req/s"
echo "Duration: $DURATION"
echo ""

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Create targets file
TARGETS_FILE=$(mktemp)
cat > "$TARGETS_FILE" << EOF
GET ${PRISM_URL}/
GET ${PRISM_URL}/api/health
GET ${PRISM_URL}/api/users
GET ${PRISM_URL}/api/status

POST ${PRISM_URL}/api/data
Content-Type: application/json
@scripts/load-testing/post-body.json
EOF

# Create POST body if doesn't exist
mkdir -p scripts/load-testing
echo '{"timestamp":"2024-01-01T00:00:00Z","data":"test"}' > scripts/load-testing/post-body.json

# Run constant rate attack
echo -e "${YELLOW}Running constant rate attack...${NC}"
vegeta attack \
    -targets="$TARGETS_FILE" \
    -rate="$RATE" \
    -duration="$DURATION" \
    -header="X-Request-ID: vegeta-$(date +%s)" \
    -timeout=30s \
    | tee "$OUTPUT_DIR/results.bin" \
    | vegeta report

# Generate reports
echo ""
echo -e "${YELLOW}Generating reports...${NC}"

# Text report
vegeta report "$OUTPUT_DIR/results.bin" > "$OUTPUT_DIR/report.txt"
echo "  - Text report: $OUTPUT_DIR/report.txt"

# JSON report
vegeta report -type=json "$OUTPUT_DIR/results.bin" > "$OUTPUT_DIR/report.json"
echo "  - JSON report: $OUTPUT_DIR/report.json"

# Histogram
vegeta report -type=hist "$OUTPUT_DIR/results.bin" > "$OUTPUT_DIR/histogram.txt"
echo "  - Histogram:   $OUTPUT_DIR/histogram.txt"

# HDR histogram (if vegeta supports it)
if vegeta report -type=hdrplot "$OUTPUT_DIR/results.bin" > "$OUTPUT_DIR/hdrplot.txt" 2>/dev/null; then
    echo "  - HDR plot:    $OUTPUT_DIR/hdrplot.txt"
fi

# Plot (requires gnuplot)
if command -v gnuplot &> /dev/null; then
    vegeta plot "$OUTPUT_DIR/results.bin" > "$OUTPUT_DIR/plot.html"
    echo "  - HTML plot:   $OUTPUT_DIR/plot.html"
fi

# Cleanup
rm -f "$TARGETS_FILE"

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}         TEST COMPLETE${NC}"
echo -e "${GREEN}========================================${NC}"

# Print summary
echo ""
cat "$OUTPUT_DIR/report.txt"
