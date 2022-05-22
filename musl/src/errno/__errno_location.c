#include <errno.h>
#include "pthread_impl.h"

int penglai_errno = 0;

int *__errno_location(void)
{
	return &penglai_errno;
}

weak_alias(__errno_location, ___errno_location);
