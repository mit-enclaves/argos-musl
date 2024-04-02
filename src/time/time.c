#include <time.h>
#include "syscall.h"

#include "../internal/tyche.h"

#ifdef TYCHE_NO_SYSCALL
static unsigned long long tyche_monotonic = 0;
#endif

time_t time(time_t *t)
{
	struct timespec ts;
#ifdef TYCHE_NO_SYSCALL
  ts.tv_sec = tyche_monotonic++;
  ts.tv_nsec = 0;
#else
	__clock_gettime(CLOCK_REALTIME, &ts);
#endif
	if (t) *t = ts.tv_sec;
	return ts.tv_sec;
}
