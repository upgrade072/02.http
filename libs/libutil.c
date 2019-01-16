#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

void DumpHex(const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			printf(" ");
			if ((i+1) % 16 == 0) {
				printf("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}

// schlee,
unsigned long create_unique_id(unsigned long u_id) // u_id == seed, 0 also ok
{
	struct timeval t;
	unsigned long id;
	gettimeofday(&t,NULL);
	id = (t.tv_sec * 1000 * 1000) + (t.tv_usec * 1000) << 42;
	id |= (u_id % 16777216) << 24;
	return id;
}
