#include "lbengine.h"

static void add_write_item(write_list_t *write_list, write_item_t *write_item)
{
    write_item->next = NULL;

    if (write_list->root == NULL) {
        write_item->prev = write_list->root;
        write_list->root = write_item;
        write_list->last = write_item;
    } else {
        write_list->last->next = write_item;
        write_item->prev = write_list->last;
        write_list->last = write_item;
    }
    write_list->item_cnt++;
    write_list->item_bytes += write_item->iovec_item->remain_bytes;
}

static void remove_write_item(write_list_t *write_list, write_item_t *write_item)
{
    if (write_item->prev)
        write_item->prev->next = write_item->next;
    else
        write_list->root = write_item->next;

    if (write_item->next)
        write_item->next->prev = write_item->prev;
    else
        write_list->last = write_item->prev;
 
    write_list->item_cnt--;
    write_list->item_cnt -= write_item->iovec_item->remain_bytes;
}

write_item_t *create_write_item(write_list_t *write_list, iovec_item_t *iovec_item)
{
    write_item_t *write_item = malloc(sizeof(write_item_t));
    memset(write_item, 0x00, sizeof(write_item_t));
    write_item->iovec_item = iovec_item;

    add_write_item(write_list, write_item);

    return write_item;
}

static void delete_write_item(write_list_t *write_list, write_item_t *write_item)
{
    remove_write_item(write_list, write_item);
    free(write_item);
}

void print_write_item(write_list_t *write_list)
{
    fprintf(stderr, "%s cnt (%d) bytes (%d),\n", 
            __func__, write_list->item_cnt, write_list->item_bytes);

    write_item_t *write_item = write_list->root;

    while (write_item) {

        iovec_item_t *iovec_item = write_item->iovec_item;
        if (iovec_item != NULL) {
            fprintf(stderr, "have iovec cnt [%d]\n", iovec_item->iov_cnt);
            for (int i = 0; i < iovec_item->iov_cnt; i++) {
                fprintf(stderr, "iovec[%d]\n", i);
                util_dumphex(iovec_item->iov[i].iov_base, iovec_item->iov[i].iov_len);
            }
        }

        write_item_t *next = write_item->next;
        write_item = next;
    }
}

ssize_t push_write_item(int fd, write_list_t *write_list, int bundle_cnt, int bundle_bytes)
{
	if (fd < 0) 
		return -1;

    if (write_list->item_cnt <= 0 || write_list->item_bytes <= 0)
        return -1; 

    struct iovec iov[MAX_IOV_PUSH] = {0,};
    int slot_cnt = 0;
    write_item_t *write_item = write_list->root;

    for (int i = 0, bytes = 0; write_item && (i < bundle_cnt) ; i++) {
        iovec_item_t *iovec_item = write_item->iovec_item;

        for (int i = iovec_item->next_start_pos; i < MAX_IOV_CNT; i++) {
            if (!iovec_item->iov[i].iov_len) continue;

            iov[slot_cnt].iov_base = iovec_item->iov[i].iov_base;
            iov[slot_cnt].iov_len = iovec_item->iov[i].iov_len;
            bytes += iovec_item->iov[i].iov_len;
            slot_cnt ++;

            if (bytes >= bundle_bytes)
                goto PUSH_SEND;
        }

        write_item_t *next = write_item->next;
        write_item = next;
    }

PUSH_SEND:
    return writev(fd, iov, slot_cnt);
}

void unset_pushed_item(write_list_t *write_list, ssize_t nwritten)
{
    write_list->item_bytes -= nwritten;
    write_item_t *write_item = write_list->root;

    while (write_item && (nwritten > 0)) {
        /* for next loop ( write_item can be deleted ) */
        write_item_t *next = write_item->next;

        iovec_item_t *iovec_item = write_item->iovec_item;

        if (iovec_item->remain_bytes <= nwritten) {
            /* ctx send done */
            nwritten = nwritten - iovec_item->remain_bytes;
            iovec_item->iov_cnt = 0;
            iovec_item->next_start_pos = 0;
            iovec_item->remain_bytes = 0;

			/* unset ctx */
			if (iovec_item->ctx_unset_ptr != NULL)
				*iovec_item->ctx_unset_ptr = 0;
			if (iovec_item->unset_cb_func != NULL) 
				iovec_item->unset_cb_func(iovec_item->unset_cb_arg);

            /* remove from list */
            delete_write_item(write_list, write_item);
        } else {
            /* save remain to iovec_item */
            for (int i = iovec_item->next_start_pos; i < MAX_IOV_CNT; i++) {
                if (!iovec_item->iov[i].iov_len) continue; /* TEST MORE */
                if (iovec_item->iov[i].iov_len <= nwritten) {
                    /* total sended */
                    iovec_item->iov_cnt = iovec_item->iov_cnt - 1;
                    iovec_item->next_start_pos = iovec_item->next_start_pos + 1;
                    iovec_item->remain_bytes = iovec_item->remain_bytes - iovec_item->iov[i].iov_len;
                    nwritten = nwritten - iovec_item->iov[i].iov_len;
                } else {
                    /* partial sended */
                    iovec_item->iov[i].iov_base = iovec_item->iov[i].iov_base + nwritten;
                    iovec_item->iov[i].iov_len = iovec_item->iov[i].iov_len - nwritten;
                    iovec_item->remain_bytes = iovec_item->remain_bytes - nwritten;
                    nwritten = 0;
                }
            }
        }

        /* for next loop */
        write_item = next;
    }
}

