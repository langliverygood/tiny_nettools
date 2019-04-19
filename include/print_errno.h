#ifndef _PRINT_ERRNO_
#define _PRINT_ERRNO_

#define print_errno(fmt, ...) \
    printf("[%d] errno=%d (%s) #" fmt, \
        __LINE__, errno, strerror(errno), ####__VA_ARGS__)

#endif
