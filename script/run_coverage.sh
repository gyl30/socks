#!/bin/bash
set -e

if [ ! -d "build_coverage" ]; then
    mkdir build_coverage
fi
cd build_coverage

cmake -DCMAKE_BUILD_TYPE=Debug -DENABLE_COVERAGE=ON ..

cmake --build . -j$(nproc)

ctest --output-on-failure

if [[ "$OSTYPE" == "darwin"* ]]; then
    xcrun llvm-profdata merge -sparse default.profraw -o default.profdata
    
    OBJECTS=""
    for test_bin in tests/*_test; do
        if [[ -x "$test_bin" ]]; then
             OBJECTS="$OBJECTS -object $test_bin"
        fi
    done
    
    xcrun llvm-cov show $OBJECTS -instr-profile=default.profdata -format=html -output-dir=coverage_report ../src
    echo "Coverage report generated in build_coverage/coverage_report/index.html"
    
    xcrun llvm-cov report $OBJECTS -instr-profile=default.profdata ../src
else
    lcov --capture --directory . --output-file coverage.info
    lcov --remove coverage.info '/usr/*' '*/third/*' '*/tests/*' --output-file coverage_cleaned.info
    genhtml coverage_cleaned.info --output-directory coverage_report
    echo "Coverage report generated in build_coverage/coverage_report/index.html"
fi
