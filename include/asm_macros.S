#ifndef JIT_MACROS_H
#define JIT_MACROS_H

.macro SNIPPET_DECLARE name
.align 4
.global \name
\name:
.endm

.macro SNIPPET_ALIGN name
.global __\name\()_align
__\name\()_align:
.endm

.macro SNIPPET_END name
.global __\name\()_end
__\name\()_end:
padding_nop 1
.endm

#endif