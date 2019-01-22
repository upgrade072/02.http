#include "http_vhdr.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

hdr_index_t *search_vhdr(hdr_index_t hdr_index[], int array_size, char *vhdr_name);

hdr_index_t HDR_INDEX[MAX_HDR_RELAY_CNT] = {0,};
int main()
{
	fprintf(stderr, "res set_relay_vhdr() is %d\n", set_relay_vhdr(HDR_INDEX, VH_END));
	fprintf(stderr, "set_relay_vhdr() result is\n");
	print_relay_vhdr(HDR_INDEX, VH_END);

	fprintf(stderr, "res sort_relay_vhdr() is %d\n", sort_relay_vhdr(HDR_INDEX, VH_END));
	fprintf(stderr, "sort_relay_vhdr() result is\n");
	print_relay_vhdr(HDR_INDEX, VH_END);

	hdr_index_t *ptr = search_vhdr(HDR_INDEX, VH_END, "VH_TEST_6");
	if (ptr != NULL)
		fprintf(stderr, "search %s res %s %d\n", "VH_TEST_6", ptr->vheader_name, ptr->vheader_id);

	ptr = search_vhdr(HDR_INDEX, VH_END, "VH_START");
	if (ptr != NULL)
		fprintf(stderr, "search %s res %s %d\n", "VH_START", ptr->vheader_name, ptr->vheader_id);

	ptr = search_vhdr(HDR_INDEX, VH_END, "VH_END");
	if (ptr != NULL)
		fprintf(stderr, "search %s res %s %d\n", "VH_END", ptr->vheader_name, ptr->vheader_id);

	ptr = search_vhdr(HDR_INDEX, VH_END, "FUCKYOU");
	if (ptr != NULL)
		fprintf(stderr, "search %s res %s %d\n", "FUCKYOU", ptr->vheader_name, ptr->vheader_id);

}
