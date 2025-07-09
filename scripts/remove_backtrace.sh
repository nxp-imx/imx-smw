#!/bin/sh

# Set the directory to search (default is current directory)
SEARCH_DIR="${1:-.}"

# Find all CTestTestfile.cmake files and process them
find "$SEARCH_DIR" -name "CTestTestfile.cmake" | while read -r file; do
    echo "Processing: $file"

    # Remove lines containing _BACKTRACE_TRIPLES
    sed -i 's/_BACKTRACE_TRIPLES\s*".*"\s*//g' "$file"
done
