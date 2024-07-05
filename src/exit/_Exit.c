#include <stdlib.h>
#include "syscall.h"
#include "tyche.h"

_Noreturn void _Exit(int ec)
{
	tyche_exit(ec);	
	//__syscall(SYS_exit_group, ec);
	//for (;;) __syscall(SYS_exit, ec);
}
