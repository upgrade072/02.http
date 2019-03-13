#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <jwt.h>

int test()
{
    jwt_t *jwt = NULL;
    const char key[] = "My Passphrase";
    int ret = 0;
    char *out;

    ret = jwt_new(&jwt);

    ret = jwt_set_alg(jwt, JWT_ALG_HS256, (unsigned char *)key,
              strlen(key));

    ret = jwt_add_grant(jwt, "iss", "files.cyphre.com");
    ret = jwt_add_grant(jwt, "sub", "user0");
    ret = jwt_add_grant(jwt, "ref", "XXXX-YYYY-ZZZZ-AAAA-CCCC");
    ret = jwt_add_grant_int(jwt, "iat", (long)time(NULL));

    out = jwt_dump_str(jwt, 1); /* pretty */
    fprintf(stderr, "output pretty]\n%s\n\n", out);
    free(out);

    out = jwt_dump_str(jwt, 0); /* unpretty */
    fprintf(stderr, "output unpretty]\n%s\n\n", out);
    free(out);

    out = jwt_encode_str(jwt);
    fprintf(stderr, "encoded str] : %s\n", out);
    free(out);

    jwt_free(jwt);

    return ret;
}
