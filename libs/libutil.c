#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <http_comm.h>
#include <ctype.h>

void DumpHex(const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		fprintf(stderr, "%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			fprintf(stderr, " ");
			if ((i+1) % 16 == 0) {
				fprintf(stderr, "|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					fprintf(stderr, " ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					fprintf(stderr, "   ");
				}
				fprintf(stderr, "|  %s \n", ascii);
			}
		}
	}
}

unsigned long create_unique_id(unsigned long u_id) // u_id == seed, 0 also ok
{
	struct timeval t;
	unsigned long id;
	gettimeofday(&t,NULL);
	id = (t.tv_sec * 1000 * 1000) + ((t.tv_usec * 1000) << 42);
	id |= (u_id % 16777216) << 24;
	return id;
}

char rfc3986[256] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,45,46,0,48,49,50,51,52,53,54,55,56,57,0,0,0,0,0,0,0,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,0,0,0,0,95,0,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,122,0,0,0,126,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
char html5[256] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,43,0,0,0,0,0,0,0,0,0,42,0,0,45,46,0,48,49,50,51,52,53,54,55,56,57,0,0,0,0,0,0,0,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,0,0,0,0,95,0,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,122,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
char xwww[256] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,38,0,0,0,42,0,0,45,46,0,48,49,50,51,52,53,54,55,56,57,0,0,0,61,0,0,0,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,0,0,0,0,95,0,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,122,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

int ishex(int x)
{
    return  (x >= '0' && x <= '9')  ||
        (x >= 'a' && x <= 'f')  ||
        (x >= 'A' && x <= 'F');
}

/* caller responsible for memory */
/* tb rfc3986 | html5 | xwww (CAUTION!!! for only NRF) */
void encode(const char *s, char *enc, int scheme)
{
	char *tb = NULL;

	switch (scheme) {
		case HTTP_EN_RFC3986:
			tb = rfc3986;
			break;
		case HTTP_EN_HTML5:
			tb = html5;
			break;
		case HTTP_EN_XWWW:
			tb = xwww;
			break;
		default:
			return;
	};

    for (; *s; s++) {
        if (tb[*s])
            sprintf(enc, "%c", tb[*s]);
        else
            sprintf(enc, "%%%02X", *s);
        while (*++enc);
    }
}

/* caller responsible for memory */
/* return length */
int decode(const char *s, char *dec)
{
    char *o;
    const char *end = s + strlen(s);
    int c;

    for (o = dec; s <= end; o++) {
        c = *s++;
        if (c == '+') c = ' ';
        else if (c == '%' && (  !ishex(*s++)    ||
                    !ishex(*s++)    ||
                    !sscanf(s - 2, "%2x", &c)))
            return -1;

        if (dec) *o = c;
    }

    return o - dec;
}

/* (no object-child) JSON parse in sigle for-loop */
void json_delimiter(char *string)
{
    int len = strlen(string);
    int pos = 0;
    for (int i = 0; i < len; i++) {
        if (string[i] == '{' || string[i] == '\"' || string[i] == ' '|| string[i] == '\n') {
			/* skip char */
            continue;
        } else if (string[i] == ',') {
			/* make space delimiter */
            string[pos++] = ' ';
        } else if (string[i] == '}') {
			/* make null termination */
            string[pos++] = '\0';
        } else {
			/* shift char */
            string[pos++] = string[i];
        }
    }
}

/* must free return value (if not null) */
char *replaceAll(char *s, const char *olds, const char *news) 
{
	char *result, *sr;
	size_t i, count = 0;
	size_t oldlen = strlen(olds); if (oldlen < 1) return s;
	size_t newlen = strlen(news);

	if (newlen != oldlen) {
		for (i = 0; s[i] != '\0';) {
			if (memcmp(&s[i], olds, oldlen) == 0) count++, i += oldlen;
			else i++;
		}
	} else i = strlen(s);

	result = (char *) malloc(i + 1 + count * (newlen - oldlen));
	if (result == NULL) return NULL;

	sr = result;
	while (*s) {
		if (memcmp(s, olds, oldlen) == 0) {
			memcpy(sr, news, newlen);
			sr += newlen;
			s  += oldlen;
		} else *sr++ = *s++;
	}
	*sr = '\0';

	return result;
}

/* cation! we overwrite input as lower case character */
char *strlwr(char *input, int str_len)
{
    for (int i = 0; i < str_len; i++) {
        input[i] = tolower(input[i]);
    }
    return input;
}
char *strupr(char *input, int str_len)
{
    for (int i = 0; i < str_len; i++) {
        input[i] = toupper(input[i]);
    }
    return input;
}

char *read_file_stream(char *filename)
{
	FILE *fh = fopen(filename, "rb");
	int length = 0;

	if (fh != NULL) {
		fseek(fh, 0L, SEEK_END);
		length = ftell(fh);
		rewind(fh);
		char *buffer = malloc(length);
		if (buffer != NULL) { 
			fread(buffer, length, 1, fh);
		}
		if (fh != NULL) 
			fclose(fh);
		return buffer;
	}

	return NULL;
}
