#include <http_comm.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern index_t INDEX[MAX_LIST_NUM];

int new_list(const char *name)
{
	int i;

	for (i = 1; i < MAX_LIST_NUM; i++) {
		if (INDEX[i].occupied == 0) {
			sprintf(INDEX[i].listname, "%s", name);
			INDEX[i].occupied = 1;
			return i;
		}
	}
	return (-1);
}
int get_list(const char *name)
{
	int i;

	for (i = 1; i < MAX_LIST_NUM; i++) {
		if (INDEX[i].occupied == 1) {
			if (!strcmp(name, INDEX[i].listname)) 
				return i;
		}
	}
	return (-1);
}
char* get_list_name(int list_id)
{
	if (INDEX[list_id].occupied == 1)
		return INDEX[list_id].listname;

	return (NULL);
}
int del_list(const char *name)
{
	int i;

	for (i = 1; i < MAX_LIST_NUM; i++) {
		if (INDEX[i].occupied == 1) {
			if(!strcmp(name, INDEX[i].listname)) {
				memset(&INDEX[i], 0x00, sizeof(index_t));
				return 0;
			}
		}
	}
	return (-1);
}
int new_item(int list_index, const char *name, int port)
{
	int i;

	for (i = 1; i < MAX_ITEM_NUM; i++) {
		if (INDEX[list_index].item_idx[i].occupied == 0) {
			sprintf(INDEX[list_index].item_idx[i].itemname, "%s", name);
			INDEX[list_index].item_idx[i].port = port;
			INDEX[list_index].item_idx[i].occupied = 1;
			return i;
		}
	}
	return (-1);
}
int get_item(int list_index, const char *name, int port)
{
	int i;

	for (i = 1; i < MAX_ITEM_NUM; i++) {
		if (INDEX[list_index].item_idx[i].occupied == 1) 
			if(!strcmp(name, INDEX[list_index].item_idx[i].itemname))
				if (INDEX[list_index].item_idx[i].port == port)
					return i;
	}
	return (-1);
}
int del_item(int list_index, const char *name, int port)
{
	int i;

	for (i = 1; i < MAX_ITEM_NUM; i++) {
		if (INDEX[list_index].item_idx[i].occupied == 1) {
			if(!strcmp(name, INDEX[list_index].item_idx[i].itemname)) {
				if (INDEX[list_index].item_idx[i].port == port) {
					memset(&INDEX[list_index].item_idx[i], 0x00, sizeof(item_index_t));
					return 0;
				}
			}
		}
	}
	return (-1);
}
