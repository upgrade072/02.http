#include "header.h"

int check_success(parse_res_t *parse, char *name, char *value)
{
    for (int i = 0; i < MAX_PARSE_NUM; i++) {
        if (parse->result[i].state != JS_FOUND)
            continue;
        if (!strcmp(parse->result[i].name, name) &&
                !strcmp(parse->result[i].buf, value))
            return (1);
    }
    return (-1);
}

void print_parse_result(parse_res_t *parse)
{
    for (int i = 0; i < MAX_PARSE_NUM; i++) {
        if (parse->result[i].state != JS_FOUND)
            continue;
#ifdef DEBUG
        fprintf(stderr, "%s:%s\n", parse->result[i].name, parse->result[i].buf);
#endif
    }
#ifdef DEBUG
    fprintf(stderr, "\n");
#endif
}

void get_parse_data(const char *key, json_object *input_obj, parse_res_t *parse)
{
    for (int i = 0; i < MAX_PARSE_NUM; i++) {
        if (parse->result[i].state == JS_NONE ||
                parse->result[i].state == JS_FOUND)
            continue;
        if (!strcmp(key, parse->result[i].name)) {
            sprintf(parse->result[i].buf, "%s", json_object_to_json_string(input_obj));
            parse->result[i].state = JS_FOUND;
        }
    }
}

int set_parse_data(const char *key, json_object *input_obj, parse_res_t *parse)
{
    int replaced = 0;
    for (int i = 0; i < MAX_PARSE_NUM; i++) {
        if (parse->result[i].state != JS_REPLACE)
            continue;
        if (!strcmp(key, parse->result[i].name)) {
#ifdef DEBUG
            fprintf(stderr, "name (%s) will replace\n%s\n", key, parse->result[i].buf);
#endif
            json_object *new_obj;
            new_obj = json_tokener_parse(parse->result[i].buf);
            json_object_object_del(input_obj, key);
            json_object_object_add(input_obj, parse->result[i].name, new_obj);

            parse->result[i].state = JS_REPLACED;
#ifdef DEBUG
            fprintf(stderr, "name (%s) replace done\n", parse->result[i].name);
#endif
            replaced = 1;
        }
    }
    return replaced;
}

int set_key_change(const char *key, json_object *input_obj, parse_res_t *parse)
{
    int replaced = 0;
    for (int i = 0; i < MAX_PARSE_NUM; i++) {
        if (parse->result[i].state != JS_KEYVAL)
            continue;
        if (!strcmp(key, parse->result[i].name)) {
#ifdef DEBUG
            fprintf(stderr, "key (%s) will replace\n%s\n", key, parse->result[i].buf);
#endif
            json_object *new_obj;
            new_obj = json_tokener_parse(parse->result[i].buf);
            json_object_object_del(input_obj, key);
            json_object_object_add(input_obj, parse->result[i].name, new_obj);

            parse->result[i].state = JS_KEYCHANGED;
#ifdef DEBUG
            fprintf(stderr, "key (%s) replace done\n", parse->result[i].name);
#endif
            replaced = 1;
        }
    }
    return replaced;
}

void change_keyvalue(json_object *input_obj, parse_res_t *parse)
{
    for (int i = 0; i < MAX_PARSE_NUM; i++) {
        if (parse->result[i].state == JS_KEYVAL) {
#ifdef DEBUG
            fprintf(stderr, "DBG change key %s : %s\n", parse->result[i].name, parse->result[i].buf);
#endif
            recurse_obj(input_obj, parse, JS_WANT_KEYCHANGE);
        }
    }
}

void replace_obj(json_object *input_obj, parse_res_t *parse)
{
    parse_res_t check;
    int replace_count = 0;

    /* don't memcpy. buffer is too large */
    for (int i = 0; i < MAX_PARSE_NUM; i++) {
        if (parse->result[i].state == JS_FOUND) {
            check.result[i].state = JS_INIT;
            sprintf(check.result[i].name, "%s", parse->result[i].name);
        } else {
            check.result[i].state = JS_NONE;
        }
    }

    recurse_obj(input_obj, &check, JS_WANT_FIND);

    /* if JS_FOUND { already exist ==> del/add } else JS_INIT { not exist ==> just add } */
    for (int i = 0; i < MAX_PARSE_NUM; i++) {
        if (parse->result[i].state == JS_FOUND) {
            if (check.result[i].state != JS_FOUND) {
                parse->result[i].state = JS_ADD;
            } else {
                parse->result[i].state = JS_REPLACE;
                replace_count ++;
            }
        }
    }

    // add : just add to under root
    for (int i = 0; i < MAX_PARSE_NUM; i++) {
        if (parse->result[i].state == JS_ADD) {
#ifdef DEBUG
            fprintf(stderr, "name (%s) will add\n%s\n", parse->result[i].name, parse->result[i].buf);
#endif
            json_object *new_obj;
            new_obj = json_tokener_parse(parse->result[i].buf);
            json_object_object_add(input_obj, parse->result[i].name, new_obj);

#ifdef DEBUG
            fprintf(stderr, "name (%s) add done\n", parse->result[i].name);
#endif
        }
    }

    // replace : replace with same depth
    for (int i = 0; i < replace_count; i++)
        recurse_obj(input_obj, parse, JS_WANT_REPLACE);
}

/* MAIN PARSE FUNTION: find multiple keyword, in one function call */
/* caution, get object is not new-alloc(), so don't try clear by using json_object_put() */
void recurse_obj(json_object *input_obj, parse_res_t *parse, int action)
{
    json_object_object_foreach(input_obj, key, val) {

        json_object *obj = json_object_object_get(input_obj, key);
        if (obj == NULL) continue;

        enum json_type o_type = json_object_get_type(obj);

        if (action == JS_WANT_FIND) {
            /* compare with multiple keyword & save to buffer */
            get_parse_data(key, obj, parse);
        } else if (action == JS_WANT_REPLACE) {
            /* if replace success, foreach index move to last point, so we need restart */
            if (set_parse_data(key, input_obj, parse) > 0)
                return;
        } else if (action == JS_WANT_KEYCHANGE) {
            /* if replace success, foreach index move to last point, so we need restart */
            if (set_key_change(key, input_obj, parse) > 0)
                return;
        }

        switch (o_type) {
            case json_type_array:
                for (int i = 0; i < json_object_array_length(obj); i++) {
                    json_object *list = json_object_array_get_idx(obj, i);
                    json_type l_type = json_object_get_type(list);
                    if (l_type == json_type_array || l_type == json_type_object) {
                        recurse_obj(list, parse, action);
                    }
                }
                break;
            case json_type_object:
                recurse_obj(obj, parse, action);
                break;
            default:
                break;
        }
    }
}

void recurse_obj_single(json_object *input_obj, const char *farg, char *buff, size_t buff_len, int *find)
{
	if (strlen(farg) == 0) return;

    json_object_object_foreach(input_obj, key, val) {

        json_object *obj = json_object_object_get(input_obj, key);
        if (obj == NULL) continue;

        enum json_type o_type = json_object_get_type(obj);

		if (!strcmp(key, farg)) {
			//strncpy(buff, json_object_to_json_string(obj), buff_len);
			// --> https:\/\/192.168.70.56:9000
			strncpy(buff, json_object_get_string(obj), buff_len);
			// --> https://192.168.70.56:9000
			*find = 1;
			return;
		}

        switch (o_type) {
            case json_type_array:
                for (int i = 0; i < json_object_array_length(obj); i++) {
                    json_object *list = json_object_array_get_idx(obj, i);
                    json_type l_type = json_object_get_type(list);
                    if (l_type == json_type_array || l_type == json_type_object) {
                        recurse_obj_single(list, farg, buff, buff_len, find);
                    }
                }
                break;
            case json_type_object:
                recurse_obj_single(obj, farg, buff, buff_len, find);
                break;
            default:
                break;
        }
    }
}
