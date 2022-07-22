/*
 * License MIT
 * Copyright (c) 2021 Devo Inc.
 * Copyright (c) 2022 Sebastien Tricaud
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libpcapng/io.h>

int main(int argc, char **argv)
{

	libpcapng_file_read_debug(argv[1]);

	return 0;
}
