#!/bin/bash

CUSTOM_NODES_DIR=$1
HTML_DIR=$(dirname $0)/node-scan-results

mkdir -p $HTML_DIR
if [ -d "$HTML_DIR" ]; then
    rm -rf $HTML_DIR/*
else
    mkdir -p $HTML_DIR
fi

EXCLUDED_FOLDERS=("__pycache__" "node_modules" "dist" "build" "public" "src" "assets" "scripts" "styles" "images" "fonts" "node_modules" "dist" "build" "public" "src" "assets" "scripts" "styles" "images" "fonts")
CUSTOM_NODES=$(ls $CUSTOM_NODES_DIR | grep -v -E '(__pycache__|node_modules|dist|build|public|src|assets|scripts|styles|images|fonts)')

echo "$CUSTOM_NODES" | while read -r line; do
    if [ ! -d "$CUSTOM_NODES_DIR/$line" ]; then
        continue
    fi
    echo "Running bandit on $line"
    bandit --format html -o $HTML_DIR/$line.html -r $CUSTOM_NODES_DIR/$line
done

python3 ./score/bandit_scan_score.py $CUSTOM_NODES_DIR $HTML_DIR