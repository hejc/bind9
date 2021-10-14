#!/bin/sh
CLANG_TIDY_CHECKS="-*"
CLANG_TIDY_CHECKS="$CLANG_TIDY_CHECKS,bugprone-macro-parentheses"
CLANG_TIDY_CHECKS="$CLANG_TIDY_CHECKS,readability-braces-around-statements"
CLANG_TIDY_CHECKS="$CLANG_TIDY_CHECKS,readability-redundant-control-flow"
CLANG_TIDY_CHECKS="$CLANG_TIDY_CHECKS,readability-uppercase-literal-suffix"
CLANG_TIDY_CHECKS="$CLANG_TIDY_CHECKS${*:+,}${*}"

python3 ./util/run-clang-tidy.py \
	-clang-tidy-binary "${CLANG_TIDY:-clang-tidy-13}" \
	-clang-apply-replacements-binary "${CLANG_APPLY_REPLACEMENTS:-clang-apply-replacements-13}" \
	-checks="$CLANG_TIDY_CHECKS" \
	-j 9 \
	-fix \
	-quiet
