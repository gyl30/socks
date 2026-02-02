#!/bin/bash
set -e
cd build_coverage

if [[ "$OSTYPE" == "darwin"* ]]; then
    xcrun llvm-profdata merge -sparse tests/default.profraw -o default.profdata
    
    OBJECTS=""
    for test_bin in tests/*_test; do
        if [[ -x "$test_bin" ]]; then
             OBJECTS="$OBJECTS -object $test_bin"
        fi
    done
    IGNORE_REGEX="tests/|third/|/usr/|test.cpp"

    xcrun llvm-cov show $OBJECTS -instr-profile=default.profdata -format=html -output-dir=coverage_report -ignore-filename-regex="$IGNORE_REGEX"
    echo "Coverage report generated in build_coverage/coverage_report/index.html"
    
    xcrun llvm-cov report $OBJECTS -instr-profile=default.profdata -ignore-filename-regex="$IGNORE_REGEX"
else
    echo "This manual report generation script is for macOS currently."
fi
