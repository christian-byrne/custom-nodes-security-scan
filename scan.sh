#!/usr/bin/env bash

set -e

SCAN_START_DIR=$1

if [[ -z $SCAN_START_DIR ]]; then
    SCAN_START_DIR=$COMFY_MAIN_DIR
fi
if [[ -z $SCAN_START_DIR ]]; then
    echo "Usage: $0 <SCAN_START_DIR>"
    exit 1
fi
if [[ $SCAN_START_DIR != *"/custom_nodes" ]]; then
    SCAN_START_DIR="$SCAN_START_DIR/custom_nodes"
fi

REPORTS_OUTPUT_DIR=$(dirname $0)/docs
TEMPLATES_DIR=$(dirname $0)/report-formatters/html-templates

if [[ ! -d $REPORTS_OUTPUT_DIR ]]; then
    mkdir -p $REPORTS_OUTPUT_DIR
fi

# --------------------------------------------------

python3 ./scan-yara/main.py
bash ./scan-bandit/bandit-scan.sh $SCAN_START_DIR $REPORTS_OUTPUT_DIR
# npm run scan-dependency-check
# node ./scan-blacklists/index.js
python3 ./scoring/calculate_scores.py $SCAN_START_DIR $REPORTS_OUTPUT_DIR $TEMPLATES_DIR
python3 ./scripts/remove_path_roots_in_html.py $SCAN_START_DIR $REPORTS_OUTPUT_DIR