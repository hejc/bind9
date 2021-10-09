#!/bin/sh
python3 ./util/run-clang-tidy.py \
	-clang-tidy-binary "${CLANG_TIDY:-clang-tidy-13}" \
	-clang-apply-replacements-binary "${CLANG_APPLY_REPLACEMENTS:-clang-apply-replacements-13}" \
	-checks="-*,readability-braces-around-statements${*:+,}${*}" \
	-j 9 \
	-fix \
	-quiet
