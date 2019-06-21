#include "http_vhdr.h"
#include "http_comm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int set_relay_vhdr(hdr_index_t hdr_index[], int array_size)
{
	if (array_size < VH_START || array_size > VH_END) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} array size (%d) too long with [%d~%d]", array_size, VH_START, VH_END);
		return (-1);
	}

	char *line = strtok(strdup(HTTP_VHEADER), "\n");
	for (int i = 0, copy_index = 0; i < VH_END; i++) {
		int len = sprintf(hdr_index[copy_index].vheader_name, "%s", line);
		hdr_index[copy_index].vheader_name[len] = '\0';
		hdr_index[copy_index].vheader_id = i;
		copy_index++;

		line = strtok(NULL, "\n");
	}

	return (0);
}

int print_relay_vhdr(hdr_index_t hdr_index[], int array_size)
{
	if (array_size < VH_START || array_size > VH_END) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} array size (%d) too long with [%d~%d]", array_size, VH_START, VH_END);
		return (-1);
	}

	APPLOG(APPLOG_ERR, "{{{DBG}}} check virtual-header enum:str list.. ");
	for (int i = 0; i < VH_END; i++) {
		APPLOG(APPLOG_ERR, "relay vhdr [%s][%d]", 
				hdr_index[i].vheader_name, hdr_index[i].vheader_id);
	}

	return (0);
}

static int cmpstring(const void *ptr1, const void *ptr2)
{
	char *str1 = ((hdr_index_t *)ptr1)->vheader_name;
	char *str2 = ((hdr_index_t *)ptr2)->vheader_name;

	return strcmp(str1, str2);
}

int sort_relay_vhdr(hdr_index_t hdr_index[], int array_size)
{
	if (array_size < VH_START || array_size > VH_END) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} array size too long with [%d~%d]", VH_START, VH_END);
		return (-1);
	}

	qsort(&hdr_index[0], array_size, sizeof(hdr_index_t), cmpstring);

	return (0);
}

static int cmpstring_via_key(const void *ptr1, const void *ptr2)
{
	char *str1 = (char *)ptr1;
	char *str2 = ((hdr_index_t *)ptr2)->vheader_name;

	return strcmp(str1, str2);
}

hdr_index_t *search_vhdr(hdr_index_t hdr_index[], int array_size, char *vhdr_name)
{
	hdr_index_t *result = NULL;

	if (array_size < VH_START || array_size > VH_END) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} array size too long with [%d~%d]", VH_START, VH_END);
		return NULL;
	}

	if (strlen(vhdr_name) >= MAX_HDR_NAME_LEN) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} search name is too long with [%d]", MAX_HDR_NAME_LEN);
		return NULL;
	}

	result = (hdr_index_t *)bsearch(vhdr_name, &hdr_index[0], array_size, sizeof(hdr_index_t), cmpstring_via_key);

	return result;
}
