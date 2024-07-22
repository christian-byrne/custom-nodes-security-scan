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

sed -i "s|\\\$TARGET_DIR|$SCAN_START_DIR|g" ./config.json

REPORTS_OUTPUT_DIR=$(dirname $0)/docs
TEMPLATES_DIR=$(dirname $0)/report-templates

if [[ ! -d $REPORTS_OUTPUT_DIR ]]; then
    mkdir -p $REPORTS_OUTPUT_DIR
fi

# --------------------------------------------------

if [[ ! -d venv ]]; then
    python3 -m venv venv
fi

source venv/bin/activate
cd src
python ./main.py
deactivate

# cd scan-blacklists
# npm run scan-dependency-check
# node ./scan-blacklists/index.js

cd ..
python3 ./scripts/remove_path_roots_in_html.py $SCAN_START_DIR $REPORTS_OUTPUT_DIR

escaped_target_dir=$(printf '%s\n' "$SCAN_START_DIR" | sed 's:[\/&]:\\&:g')
sed -i "s|$escaped_target_dir|\\\$TARGET_DIR|g" ./config.json

echo "Scan completed. Reports are available in $REPORTS_OUTPUT_DIR"