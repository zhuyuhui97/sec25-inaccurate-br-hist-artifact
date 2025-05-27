#ifndef C_MACROS_H
#define C_MACROS_H

#define MACRO_TO_STR(x) #x
#define VOIDPTR(x) (void*)(x)
#define JMP_TO(x) ((void (*)())(x))()
#define MEM_ACCESS(p) *(volatile unsigned char *)p

#endif