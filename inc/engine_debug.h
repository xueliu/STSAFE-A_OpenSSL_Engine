#ifndef __STSAFE_ENGINE_DEBUG__
#define __STSAFE_ENGINE_DEBUG__

#define BLACK 			"\033[0;30m"
#define RED 			"\033[0;31m"
#define GREEN			"\033[0;32m"
#define ORANGE			"\033[0;33m"
#define BLUE			"\033[0;34m"
#define PURPLE			"\033[0;35m"
#define CYAN			"\033[0;36m"
#define LIGTH_GRAY		"\033[0;37m"

#define DARK_GRAY		"\033[1;30m"
#define LIGHT_RED		"\033[1;31m"
#define LIGHT_GREEN		"\033[1;32m"
#define YELLOW			"\033[1;33m"
#define LIGHT_BLUE		"\033[1;34m"
#define LIGHT_PURPLE	"\033[1;35m"
#define LIGHT_CYAN		"\033[1;36m"
#define WHITE			"\033[1;37m"

#define NO_C "\033[0m"

#ifndef DEBUG_LEVEL
#define DEBUG_LEVEL 0
#endif

extern int debug_level;

#define DEBUG_FPRINTF(fd, fmt, ...) { if (debug_level > 3) { fprintf(fd, DARK_GRAY fmt NO_C __VA_OPT__(,) __VA_ARGS__); }}
#define DEBUG_PRINTF(fmt, ...) { if (debug_level > 2) { printf(fmt __VA_OPT__(,) __VA_ARGS__);}}

#define CMD_PRINTF(fmt, ...) { printf(ORANGE fmt NO_C __VA_OPT__(,) __VA_ARGS__); }
#define CMD_FPRINTF(fd, fmt, ...) { fprintf(fd, ORANGE fmt NO_C __VA_OPT__(,) __VA_ARGS__); }


#define DEBUG_PRINTF_API(fmt, ...) { DEBUG_PRINTF(YELLOW fmt NO_C __VA_OPT__(,) __VA_ARGS__);}
#define DEBUG_PRINTF_INFO(fmt, ...) { DEBUG_PRINTF(GRAY fmt NO_C __VA_OPT__(,) __VA_ARGS__);}
#define DEBUG_PRINTF_ERROR(fmt, ...) { DEBUG_PRINTF(RED fmt NO_C __VA_OPT__(,) __VA_ARGS__);}
#define DEBUG_PRINTF_DEBUG(fmt, ...) { DEBUG_PRINTF(BLUE fmt NO_C __VA_OPT__(,) __VA_ARGS__);}

#define DEBUG_BN_PRINTF(_fd, _bn) { if (debug_level > 3) { fprintf(_fd, PURPLE "--"); BN_print_fp(_fd, _bn); fprintf(_fd, NO_C); }}
#endif
