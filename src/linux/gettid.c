#define _GNU_SOURCE
#include <unistd.h>
#include "pthread_impl.h"
#include "tyche.h"

pid_t gettid(void)
{
	return __pthread_self()->tid;
}
