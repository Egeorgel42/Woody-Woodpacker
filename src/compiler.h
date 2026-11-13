#ifndef COMPILER_H
#define COMPILER_H
#include "stdbool.h"
#include "terminal_output.h"

#if defined(__has_builtin)
	#if __has_builtin(__builtin_expect)
		#define BRANCH_LIKELY(x) __builtin_expect(!!(x), true)
		#define BRANCH_UNLIKELY(x) __builtin_expect(!!(x), false)
	#endif

	#if __has_builtin(__builtin_unreachable)
		#define COMPILER_UNREACHABLE() __builtin_unreachable()
	#endif
#elif defined(__GNUC__) && (__GNUC__ >= 3)
	#define BRANCH_LIKELY(x) __builtin_expect(!!(x), true)
	#define BRANCH_UNLIKELY(x) __builtin_expect(!!(x), false)
    #define COMPILER_UNREACHABLE() __builtin_unreachable()
#elif defined(_MSC_VER)
    #define BRANCH_LIKELY(x) (x)
    #define BRANCH_UNLIKELY(x) (x)
    #define COMPILER_UNREACHABLE() __assume(0)
#endif

#if !defined(BRANCH_LIKELY)
	#define BRANCH_LIKELY(x) (x)
    #define BRANCH_UNLIKELY(x) (x)
#endif

#if !defined(COMPILER_UNREACHABLE)
    #define COMPILER_UNREACHABLE() ((void)0)
#endif

#define ASSERT_UNREACHABLE(format, ...) \
	libassert(false, format, ##__VA_ARGS__); \
	COMPILER_UNREACHABLE()

#endif