#include <stdio.h>
#include <unistd.h>

int main()
{
	fprintf(stderr, "max iov cnt is %d\n", sysconf(_SC_IOV_MAX));
	return 0;
}
