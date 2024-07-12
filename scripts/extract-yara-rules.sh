#!/usr/bin/env bash

ROOT_DIR=$1
COPY_TO_DIR=$2

if [ -z "$ROOT_DIR" ]; then
    echo "Usage: $0 <root_dir> <copy_to_dir>"
    exit 1
fi

if [ -z "$COPY_TO_DIR" ]; then
    echo "Usage: $0 <root_dir> <copy_to_dir>"
    exit 1
fi

if [ ! -d "$ROOT_DIR" ]; then
    echo "Directory $ROOT_DIR does not exist"
    exit 1
fi

if [ ! -d "$COPY_TO_DIR" ]; then
    echo "Directory $COPY_TO_DIR does not exist"
    exit 1
fi

echo "Copying all .yara or .yar files from $ROOT_DIR to $COPY_TO_DIR"
# Detect .yara or .yar files and copy them to the COPY_TO_DIR
for file in $(find $ROOT_DIR -type f -name "*.yara" -o -name "*.yar"); do
    echo Copying ruleset: $file
    cp $file $COPY_TO_DIR
done