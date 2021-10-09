#!/bin/sh
${CLANG_FORMAT:-clang-format-13} \
	-i \
	-style=file \
	$(git ls-files '*.c')
${CLANG_FORMAT:-clang-format-13} \
	-i \
	-style="{BasedOnStyle: InheritParentConfig, AlignConsecutiveAssignments: AcrossEmptyLinesAndComments, AlignConsecutiveDeclarations: AcrossEmptyLinesAndComments, AlignConsecutiveMacros: AcrossEmptyLinesAndComments}" \
	$(git ls-files '*.h')
