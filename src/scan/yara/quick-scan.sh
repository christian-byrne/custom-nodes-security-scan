TARGET_FILE=$1

if [ -z $TARGET_FILE ]; then
    echo "Usage: $0 <target_file>"
    exit 1
fi

if [ ! -f $TARGET_FILE ]; then
    echo "File not found: $TARGET_FILE"
    echo "Usage: $0 <target_file>"
    exit 1
fi

YARA_RULES_DIR=yara-rules

if [ ! -d $YARA_RULES_DIR ]; then
    echo "Directory not found: $YARA_RULES_DIR"
    echo "Usage: $0 <target_file>"
    exit 1
fi

THIS_DIR=$(dirname $0)

for file in $(find $YARA_RULES_DIR -type f -name "*.yara" -o -name "*.yar"); do
    echo Running ruleset: $file
    yara -r $file $TARGET_FILE | tee -a yara.log
done