/*
    libspawner, an MTA-side implementation of the Sendmail Milter protocol
    Copyright (C) 2005, 2006, 2011 Hilko Bengen

    License: GPL version 2.1
*/

#include "milter_proto.h"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <errno.h>
#include <stdlib.h>

#ifdef DEBUG
#include <stdio.h>
#include <string.h>
#define debug(x...) {fprintf(stderr,x);}
#else
#define debug(x...)
#endif

/*
    Writes a milter protocol message frommsg to socket s
*/
int write_msg(int s, smfi_msg* msg)
{
	u_int32_t total;
	u_int32_t offset = 0;
	int res;

	debug("milter write_msg(): Sending: '%c'\n", msg->cmd);
	total = ntohl(msg->size) + 4;
	while (offset < total) {
		/* FIXME */
		res = send(s, ((char*)msg)+offset, total-offset, 0);
		if (res < 0) {
			if (errno != EINTR)
				return -1;
		} else {
			offset -= res;
		}
	}
	return 0;
}

/*
    Reads a milter protocol message from socket s and puts it into
    a newly allocated structure msg

    SMFIR_PROGRESS messages are ignored.
*/
int read_msg(int s, smfi_msg** msg)
{
	int size;
	int total;
	int offset;
	int res;

	do {
		res = recv(s, &size, 4, 0);
		if (res < 4) {
			debug("milter read_msg(): Error, res: '%i', errno: '%i'\n",
                              res, errno);
			return -1;
		}
		total = ntohl(size);
		if (total < 1) {
			debug("milter read_msg(): Error, total: '%i'\n", total);
			return -1;
		}
		*msg = realloc(*msg, total + 4);
		if (msg == NULL) {
			debug("milter read_msg(): Error allocating memory\n");
			return -1;
		}
		(*msg)->size = size;
		offset = 0;
		while (offset < total) {
			/* XXX: Does this do the right thing? */
			res = recv(s, &((*msg)->cmd)+offset, total-offset, 0);
			debug("milter read_msg(): recv() -> %i\n", res);
			if (res < 0) {
				if (errno != EINTR) {
					return -1;
				}
			} else {
				offset += res;
			}
		}
		debug("milter read_msg(): Received: '%c' (%x)\n",
                      (*msg)->cmd, (*msg)->cmd);
	} while ((*msg)->cmd == SMFIR_PROGRESS);

	return 0;
}
