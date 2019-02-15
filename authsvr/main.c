
#include "auth.h"

extern char *__progname;

config_t CFG;

int main(int argc, char **argv) {
	if (argc < 4) {
		fprintf(stderr, "usage) %s port key_file cert_file\n", __progname);
		exit(EXIT_FAILURE);
	}

	if (init_cfg() < 0)
		exit(EXIT_FAILURE);

	struct sigaction act;
	memset(&act, 0, sizeof(struct sigaction));
	act.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &act, NULL);

	SSL_load_error_strings();
	SSL_library_init();

	/* loop ~! */
	run(argv[1], argv[2], argv[3]);

	return 0;
}
