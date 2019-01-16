/* use this in later */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char hostname[128];
    int list_index;
} sort_test_t;

sort_test_t input[10] = {
    { "udmlb_a", 1 },
    { "udmlb_b", 2 },
    { "udmfe_c", 3 },
    { "udmfe_d", 4 } 
};

static int cmpstring(const void *p1, const void *p2)
{
    char *a = ((sort_test_t *)p1)->hostname;
    char *b = ((sort_test_t *)p2)->hostname;

    return strcmp(a, b);
}

void print_array()
{
    for (int i = 0; i < sizeof(input) / sizeof(sort_test_t) ; i++) {
        fprintf(stderr, "%s %d\n", input[i].hostname, input[i].list_index);
    }
}

int bsearch_test()
{
    sort_test_t search[1] = { "udmlb_a", 0 };
    sort_test_t *result = NULL;

    fprintf(stderr, "\nASIS]\n");
    print_array();

    qsort(&input[0], sizeof(input) / sizeof(sort_test_t), sizeof(sort_test_t), cmpstring);

    fprintf(stderr, "\nTOBE]\n");
    print_array();

    fprintf(stderr, "\nBESEARCH]\n");
    if ((result = (sort_test_t *)bsearch(search, &input[0], sizeof(input) / sizeof(sort_test_t), 
                    sizeof(sort_test_t), cmpstring)) != NULL) {
        fprintf(stderr, "%s exist have index %d\n\n", result->hostname, result->list_index);
    } else {
        fprintf(stderr, "null returned\n\n");
    }

    return 0;
}

