#include <client.h>

extern conn_list_t CONN_LIST[MAX_SVR_NUM];

int sn_cmp_type(void *input, void *compare)
{
    compare_input_t *comm_input = (compare_input_t *)input;
    select_node_t *node_data = (select_node_t *)compare;

    if (strlen(comm_input->type) == 0)
        return 0;
    else
        return (strcmp(comm_input->type, node_data->name));
}

int sn_cmp_host(void *input, void *compare)
{
    compare_input_t *comm_input = (compare_input_t *)input;
    select_node_t *node_data = (select_node_t *)compare;

    if (strlen(comm_input->host) == 0)
        return 0;
    else
        return (strcmp(comm_input->host, node_data->name));
}

int sn_cmp_ip(void *input, void *compare)
{
    compare_input_t *comm_input = (compare_input_t *)input;
    select_node_t *node_data = (select_node_t *)compare;

    if (strlen(comm_input->ip) == 0)
        return 0;
    else
        return (strcmp(comm_input->ip, node_data->name));
}

int sn_cmp_port(void *input, void *compare)
{
    compare_input_t *comm_input = (compare_input_t *)input;
    select_node_t *node_data = (select_node_t *)compare;

    if (comm_input->port == 0)
        return 0;
    else
        return (comm_input->port - node_data->val);
}

int sn_cmp_conn_id(void *input, void *compare)
{
    compare_input_t *comm_input = (compare_input_t *)input;
    select_node_t *node_data = (select_node_t *)compare;

    if (comm_input->index == 0)
        return 0;
    else
        return (comm_input->index - node_data->val);
}

GNode *new_select_data(compare_input_t *comm_input, int depth, conn_list_t *conn_list)
{
    if (depth < SN_TYPE || depth >= SN_MAX)
        return NULL;

    select_node_t *node_data = malloc(sizeof(select_node_t));
    memset(node_data, 0x00, sizeof(select_node_t));
    node_data->depth = depth;

    switch (depth) {
        case SN_TYPE:
            sprintf(node_data->name, "%s", comm_input->type == NULL ? "": comm_input->type);
            node_data->func_ptr = sn_cmp_type;
            node_data->node_ptr = g_node_new(node_data);
            break;
        case SN_HOST:
            sprintf(node_data->name, "%s", comm_input->host == NULL ? "": comm_input->host);
            node_data->func_ptr = sn_cmp_host;
            node_data->node_ptr = g_node_new(node_data);
            break;
        case SN_IP:
            sprintf(node_data->name, "%s", comm_input->ip == NULL ? "": comm_input->ip);
            node_data->func_ptr = sn_cmp_ip;
            node_data->node_ptr = g_node_new(node_data);
            break;
        case SN_PORT:
            node_data->val = comm_input->port;
            node_data->func_ptr = sn_cmp_port;
            node_data->node_ptr = g_node_new(node_data);
            break;
        case SN_CONN_ID:
            node_data->val = comm_input->index;
            node_data->func_ptr = sn_cmp_conn_id;
            node_data->leaf_ptr = conn_list;
            node_data->node_ptr = g_node_new(node_data);
            break;
        default:
            free(node_data);
            return NULL;
    }

    return (node_data->node_ptr);
}

int depth_compare(int depth, select_node_t *select_node, compare_input_t *comm_input)
{
    switch(depth) {
        case SN_TYPE:
            return sn_cmp_type(comm_input, select_node);
        case SN_HOST:
            return sn_cmp_host(comm_input, select_node);
        case SN_IP:
            return sn_cmp_ip(comm_input, select_node);
        case SN_PORT:
            return sn_cmp_port(comm_input, select_node);
        case SN_CONN_ID:
            return sn_cmp_conn_id(comm_input, select_node);
        default:
            return -1;
    }
}

select_node_t *search_select_node(GNode *parent_node, compare_input_t *comm_input, int depth)
{
    if (depth < SN_TYPE || depth >= SN_MAX) 
        return NULL;

    unsigned int child_num = g_node_n_children(parent_node);
    if (child_num == 0) 
        return NULL;

    for (int i = 0; i < child_num; i++) {
        GNode *nth_child = g_node_nth_child(parent_node, i);
        select_node_t *select_node = (select_node_t *)nth_child->data;
        if (depth_compare(depth, select_node, comm_input) == 0) {
            return select_node;
        }
    }

    return NULL;
}

select_node_t *add_select_node(GNode *parent_node, compare_input_t *comm_input, int depth, conn_list_t *conn_list)
{
    if (depth < SN_TYPE || depth >= SN_MAX)
        return NULL;

    GNode *new_node = new_select_data(comm_input, depth, conn_list);
    if (new_node == NULL) 
        return NULL;

    g_node_append(parent_node, new_node);

    return new_node->data;
}

void create_compare_data_with_list(conn_list_t *conn_list, compare_input_t *comm_input)
{
	comm_input->type = conn_list->type;
	comm_input->host = conn_list->host;
	comm_input->ip = conn_list->ip;
	comm_input->port = conn_list->port;
	comm_input->index = conn_list->index;
}

void create_compare_data_with_pkt(AhifHttpCSMsgHeadType *pkt_head, compare_input_t *comm_input)
{
    comm_input->type = pkt_head->destType;
    comm_input->host = pkt_head->destHost;
    comm_input->ip = pkt_head->destIp;
    comm_input->port = pkt_head->destPort;

}

void reorder_select_node(select_node_t *root_node)
{
    for (int i = 0; i < MAX_SVR_NUM; i++) {

        select_node_t *curr_node = root_node;
        conn_list_t *conn_list = &CONN_LIST[i];
        compare_input_t comm_input = {0,};

        if (conn_list->used != 1)
            continue;

        create_compare_data_with_list(conn_list, &comm_input);

        for (int depth = 0; depth < SN_MAX; depth++) {
            select_node_t *find_node = search_select_node(curr_node->node_ptr, &comm_input, depth);
            
            if (find_node == NULL) {
                find_node = add_select_node(curr_node->node_ptr, &comm_input, depth, conn_list);
            }
            curr_node = find_node;
        }
    }
}

gboolean traverse_memset(GNode *node, gpointer data)
{
    select_node_t *my_data = (select_node_t *)node->data;
    
    if (my_data != NULL) {
        free(my_data);
    }

    return 0; // continue traverse
}

conn_list_t *search_conn_list(GNode *curr_node, compare_input_t *comm_input, select_node_t *root_node)
{
    select_node_t *node_data = (select_node_t *)curr_node->data;

    if (G_NODE_IS_ROOT(curr_node)) {
        node_data = root_node;
    } else {
        node_data = (select_node_t *)curr_node->data;
    }

    if (G_NODE_IS_LEAF(curr_node)) {
        conn_list_t *leaf_conn_list = (conn_list_t *)node_data->leaf_ptr;
		if (leaf_conn_list == NULL) // root has none case
			return NULL;
#if 0
		else if (leaf_conn_list->act == 1 && leaf_conn_list->conn == CN_CONNECTED)
#else
		else if (leaf_conn_list->act == 1 && 
				(leaf_conn_list->conn == CN_CONNECTED && leaf_conn_list->reconn_candidate != 1))
#endif
            return leaf_conn_list;
        else
            return NULL;
    }

    unsigned int child_num = g_node_n_children(curr_node);
    if (child_num == 0) 
        return NULL;

    int start_line = node_data->last_selected;
    for (int i = 0; i < child_num; i++) {
        int nth = (start_line + i) % child_num;

        GNode *nth_child = g_node_nth_child(curr_node, nth);
        select_node_t *select_node = (select_node_t *)nth_child->data;

        if (select_node->func_ptr(comm_input, select_node) == 0) {
            conn_list_t *res_conn_list = search_conn_list(nth_child, comm_input, root_node);
            if (res_conn_list != NULL) {
                node_data->select_vector++;
                if (node_data->select_vector >= g_node_n_nodes(nth_child, G_TRAVERSE_LEAVES)) {
                    node_data->select_vector = 0;
                    node_data->last_selected = (node_data->last_selected + 1) % child_num;
                }
                return res_conn_list;
            }
        }
    }
    return NULL;
}

conn_list_t *find_packet_index(select_node_t *root_select, AhifHttpCSMsgHeadType *pkt_head)
{
	compare_input_t comm_input = {0,};

	create_compare_data_with_pkt(pkt_head, &comm_input);

	return search_conn_list(root_select->node_ptr, &comm_input, root_select);
}

void create_select_node(select_node_t *root_node)
{
    root_node->node_ptr = g_node_new(NULL);
}

void destroy_select_node(select_node_t *root_node)
{
	if (root_node->node_ptr == NULL)
		return;

    g_node_traverse(root_node->node_ptr, G_LEVEL_ORDER, G_TRAVERSE_ALL, -1, traverse_memset, NULL);
    g_node_destroy(root_node->node_ptr);
}

void rebuild_select_node(select_node_t *root_node)
{
	destroy_select_node(root_node);
	create_select_node(root_node);
	reorder_select_node(root_node);
}

void refresh_select_node(evutil_socket_t fd, short what, void *arg)
{
	select_node_t *root_node = (select_node_t *)arg;

	rebuild_select_node(root_node);
}

void set_refresh_select_node(GNode *root_node)
{
	unsigned int fep_num = g_node_n_children(root_node);

	for (int i = 0; i < fep_num; i++) {
		GNode *nth_fep = g_node_nth_child(root_node, i);
		tcp_ctx_t *tcp_ctx = (tcp_ctx_t *)nth_fep->data;

		struct event_base *evbase = tcp_ctx->evbase;

		struct timeval ten_sec = {10, 0};
		struct event *ev_tick;
		ev_tick = event_new(evbase, -1, EV_PERSIST, refresh_select_node, &tcp_ctx->root_select);
		event_add(ev_tick, &ten_sec);
	}
}

void init_refresh_select_node(lb_ctx_t *lb_ctx)
{
    set_refresh_select_node(lb_ctx->fep_rx_thrd);
	set_refresh_select_node(lb_ctx->peer_rx_thrd);
}

void once_refresh_select_node(GNode *root_node)
{
	unsigned int fep_num = g_node_n_children(root_node);

	for (int i = 0; i < fep_num; i++) {
		GNode *nth_fep = g_node_nth_child(root_node, i);
		tcp_ctx_t *tcp_ctx = (tcp_ctx_t *)nth_fep->data;

		struct event_base *evbase = tcp_ctx->evbase;
		if (event_base_once(evbase, -1, EV_TIMEOUT, refresh_select_node, &tcp_ctx->root_select, NULL) < 0) {
			APPLOG(APPLOG_ERR, "{{{TODO}}} %s() fail to add callback to dest evbase", __func__);
		}
	}
}

void trig_refresh_select_node(lb_ctx_t *lb_ctx)
{
    once_refresh_select_node(lb_ctx->fep_rx_thrd);
	once_refresh_select_node(lb_ctx->peer_rx_thrd);
}