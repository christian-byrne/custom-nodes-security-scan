#!/usr/bin/env bash

CUSTOM_NODES_DIR=$1
HTML_DIR=$(dirname $0)/docs

if [[ $CUSTOM_NODES_DIR != *"/custom_nodes" ]]; then
    CUSTOM_NODES_DIR="$CUSTOM_NODES_DIR/custom_nodes"
fi

mkdir -p $HTML_DIR
if [ -d "$HTML_DIR" ]; then
    rm -rf $HTML_DIR/*.html
else
    mkdir -p $HTML_DIR
fi

EXCLUDED_FOLDERS=("__pycache__" "node_modules" "dist" "build" "public" "src" "assets" "scripts" "styles" "images" "fonts" "node_modules" "dist" "build" "public" "src" "assets" "scripts" "styles" "images" "fonts")
CUSTOM_NODES=$(ls $CUSTOM_NODES_DIR | grep -v -E '(__pycache__|node_modules|dist|build|public|src|assets|scripts|styles|images|fonts)')

SKIP_TESTS="B101,B112,B311"
MAX_SNIPPET_LINES=32

echo "$CUSTOM_NODES" | while read -r line; do
    if [ ! -d "$CUSTOM_NODES_DIR/$line" ]; then
        continue
    fi
    echo "Running bandit on $line"
    bandit --format html --ignore-nosec --skip $SKIP_TESTS --number $MAX_SNIPPET_LINES -o $HTML_DIR/$line.html -r $CUSTOM_NODES_DIR/$line
done

python3 ./score/bandit_scan_score.py $CUSTOM_NODES_DIR $HTML_DIR
python3 ./clean/remove_path_roots.py