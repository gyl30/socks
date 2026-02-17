if(NOT DEFINED PROJECT_SOURCE_DIR OR PROJECT_SOURCE_DIR STREQUAL "")
    message(FATAL_ERROR "PROJECT_SOURCE_DIR is required")
endif()

if(NOT DEFINED RG_EXECUTABLE OR RG_EXECUTABLE STREQUAL "")
    message(FATAL_ERROR "RG_EXECUTABLE is required")
endif()

execute_process(
    COMMAND
        "${RG_EXECUTABLE}"
        -n
        "\\bthrow\\b|\\btry\\b|\\bcatch\\b"
        --glob
        "*.{cpp,h}"
        --glob
        "!third/**"
        --glob
        "!build/**"
        --glob
        "!build_coverage/**"
        --glob
        "!cmake-build-debug/**"
        .
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
    RESULT_VARIABLE rg_result
    OUTPUT_VARIABLE rg_output
    ERROR_VARIABLE rg_error
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_STRIP_TRAILING_WHITESPACE
)

if(rg_result EQUAL 1)
    message(STATUS "no exception keywords found")
elseif(rg_result EQUAL 0)
    message(FATAL_ERROR "forbidden exception keywords found:\n${rg_output}")
else()
    message(FATAL_ERROR "failed to run rg with code ${rg_result}:\n${rg_error}")
endif()
