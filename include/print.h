#ifndef _PRINT_
#define _PRINT_

#define print_errno(fmt, args...) printf("\033[;31m[errno = %d(%s)]:\033[0m"#fmt"\r\n", errno, strerror(errno), ##args)
#define print_error(fmt, args...) printf("\033[;31m"#fmt"\033[0m\r\n", ##args)

#endif
