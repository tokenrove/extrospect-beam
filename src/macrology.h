#pragma once

#define CONCAT_HELPER(x,y) x##y
#define CONCAT(x,y) CONCAT_HELPER(x,y)
#define GENSYM(x) CONCAT(x, __COUNTER__)
#define UNUSED GENSYM(_) __attribute((unused))

#define STRINGIFY_HELPER(x) #x
#define STRINGIFY(x) STRINGIFY_HELPER(x)

#define N_ELEMS(x) (sizeof(x) / sizeof((x)[0]))
