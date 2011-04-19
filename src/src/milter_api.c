/*
    libspawner, an MTA-side implementation of the Sendmail Milter protocol
    Copyright (C) 2005, 2006, 2011 Hilko Bengen

    License: GPL version 2.1
*/

#include "milter.h"
#include "milter_api.h"
#include "milter_proto.h"

#include <sys/socket.h>
#include <netdb.h>
/* struct sockaddr_un */
#include <sys/un.h>
/* malloc() */
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
/* For byte order conversion */
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>

#include <arpa/inet.h>

#ifdef DEBUG
#include <stdio.h>
#define debug(x...) fprintf(stderr, x);
#else
#define debug(x...)
#endif

#define is_valid_state(x,y) ( (!x&&!y) ? 1 : x&y )

/*
  Reads from the socket, expecting an "accept/reject action" as
  described in Todd Vierlings milter-protocol.txt (2004).

  If a custom replytext is sent by the milter, its text part is copied
  into sp->replytext.

  Returns: CONTINUE/ACCEPT/REJECT/DISCARD/TEMPFAIL
*/
int recv_response(milter* milt)
{
	smfi_msg* msg = NULL;
	char res;

	if (read_msg(milt->socket, &msg) != 0)
	{
		res = MILTER_ERROR_IO;
		goto exit;
	}

	if (milt->replytext != NULL)
	{
		free(milt->replytext);
		milt->replytext = NULL;
	}

	switch(msg->cmd) {
		case SMFIR_ACCEPT:    res = MILTER_ACCEPT; break;
		case SMFIR_CONTINUE:  res = MILTER_CONTINUE; break;
		case SMFIR_DISCARD:   res = MILTER_DISCARD; break;
		case SMFIR_REJECT:    res = MILTER_REJECT; break;
		case SMFIR_TEMPFAIL:  res = MILTER_TEMPFAIL; break;
		case SMFIR_REPLYCODE:
			milt->replytext = strdup(msg->data+4);
			/* Parse reply code. (only the first digit) */
			switch(msg->data[0]) {
				case '2': res = MILTER_CONTINUE; break;
				case '3': res = MILTER_CONTINUE; break;
				case '4': res = MILTER_TEMPFAIL; break;
				case '5': res = MILTER_REJECT; break;
				default:  res = MILTER_ERROR_PROTO; break;
			}
		default: res = MILTER_ERROR_PROTO; break;
	}

  exit:
	if (msg) free(msg);
	return res;
}

int recv_eom_response(milter* milt)
{
	smfi_msg* msg = NULL;
	char res;
	char *s1, *s2;
	int i;

	while (1)
	{
		if(read_msg(milt->socket, &msg) != 0) {
			res = MILTER_ERROR_IO;
			goto exit;
		}

		if (milt->replytext != NULL) {
			free(milt->replytext);
			milt->replytext = NULL;
		}

		switch(msg->cmd) {
			case SMFIR_ACCEPT:    res = MILTER_ACCEPT; break;
			case SMFIR_CONTINUE:  res = MILTER_CONTINUE; break;
			case SMFIR_DISCARD:   res = MILTER_DISCARD; break;
			case SMFIR_REJECT:    res = MILTER_REJECT; break;
			case SMFIR_TEMPFAIL:  res = MILTER_TEMPFAIL; break;
			case SMFIR_REPLYCODE:
				milt->replytext = strdup(msg->data+4);
				/* Parse reply code. (only the first digit) */
				switch(msg->data[0]) {
					case '2': res = MILTER_CONTINUE; break;
					case '3': res = MILTER_CONTINUE; break;
					case '4': res = MILTER_TEMPFAIL; break;
					case '5': res = MILTER_REJECT; break;
					default:  res = MILTER_ERROR_PROTO; break;
				}
			case SMFIR_ADDRCPT:
				s1 = msg->data;
				if (milt->add_rcpt != NULL)
					milt->add_rcpt(milt, s1);
				break;
			case SMFIR_DELRCPT:
				s1 = msg->data;
				if (milt->del_rcpt != NULL)
					milt->del_rcpt(milt, s1);
				break;
			case SMFIR_ADDHEADER:
				s1 = msg->data;
				for ( s2=s1; *s2!='\0'; s2++);
					s2++;
				if (milt->add_header != NULL)
					milt->add_header(milt, s1, s2);
				break;
			case SMFIR_CHGHEADER:
				i = *((int*)msg->data);
				s1 = msg->data+4;
				for ( s2=s1; *s2!='\0'; s2++);
					s2++;
				if (milt->change_header != NULL)
					milt->change_header(milt, i, s1, s2);
				break;
			case SMFIR_QUARANTINE:
				s1 = msg->data;
				if (milt->quarantine != NULL)
					milt->quarantine(milt, s1);
				break;
			case SMFIR_REPLBODY:
				i = msg->size - 1;
				s1 = msg->data;
				if (milt->replace_body != NULL)
					milt->replace_body(milt, i, s1);
				break;
			default: res = MILTER_ERROR_PROTO; break;
		}
	}
  exit:
	if (msg) free(msg);
	return res;
}

/* Utility function */
int send_cmd_twostrings(milter* milt, char cmd, char* s1, char* s2)
{
	int s;
	int size;
	int res = MILTER_OK;
	smfi_msg* msg = NULL;

	if (s1 == NULL)
		s1="";
	if (s2 == NULL)
		s2="";

	milt->error = 0;

	/* Strings need to be null-terminated */
	s = strlen(s1) + 1;
	size = s + strlen(s2) + 1;

	msg = malloc(sizeof(smfi_msg) + size);
	if (msg == NULL) {
		milt->error = ENOMEM;
		res = MILTER_ERROR;
		goto exit;
	}
	msg->cmd = cmd;
	msg->size = htonl(size + 1);
	strcpy(msg->data, s1);
	strcpy(msg->data+s, s2);

	if (write_msg(milt->socket, msg) != 0) {
		res = MILTER_ERROR_IO;
		goto exit;
	}

  exit:
	if (msg) free(msg);
	return res;
}

int send_cmd_simple(milter* milt, char cmd)
{
	int res = MILTER_OK;
	smfi_msg msg;

	msg.size = htonl(1);
	msg.cmd = cmd;
	if ( write_msg(milt->socket, &msg) != 0)
		res = MILTER_ERROR_IO;

	return res;
}

/*
    Allocates and initializes the milter structure which is used
    to identify a milter connection.
*/
milter* milter_init() {
	milter* milt;

	milt = malloc(sizeof(milter));
	if (milt == NULL) return NULL;
	milt->error = 0;
	milt->socket = 0;

	milt->version = 2;
	milt->flags = 0;
	milt->actions = 0;

	milt->replytext = NULL;

	milt->add_rcpt = NULL;
	milt->del_rcpt = NULL;
	milt->add_header = NULL;
	milt->change_header = NULL;
	milt->replace_body = NULL;
	milt->quarantine = NULL;

	milt->state = STATE_INIT;

	return milt;
}

/*
    Set steps that are to be skipped by the communication between
    MTA and milter.

    @param flags Flags, according to SMFIF_*
    Must be called before the connection to the milter is established
    using milter_open()
*/
int milter_set_protocol_flags(milter* milt, u_int32_t flags)
{
	if (!is_valid_state(milt->state, STATE_INIT))
		return MILTER_ERROR_STATE;

	milt->error = 0;
	milt->flags = flags;

	return MILTER_OK;
}

int milter_callback_add_rcpt(milter* milt, void (*add_rcpt)(milter*, char*))
{
	if (!is_valid_state(milt->state, STATE_INIT))
		return MILTER_ERROR_STATE;

	milt->add_rcpt = add_rcpt;
	if (add_rcpt != NULL)
		milt->actions |= SMFIF_ADDRCPT;
	else
		milt->actions &= -SMFIF_ADDRCPT;

	return MILTER_OK;
}

int milter_callback_del_rcpt(milter* milt, void (*del_rcpt)(milter*, char*))
{
	if (!is_valid_state(milt->state, STATE_INIT))
		return MILTER_ERROR_STATE;

	milt->del_rcpt = del_rcpt;
	if (del_rcpt != NULL)
		milt->actions |= SMFIF_DELRCPT;
	else
		milt->actions &= -SMFIF_DELRCPT;

	return MILTER_OK;
}

int milter_callback_add_header(milter* milt, void (*add_header)(milter*, char*, char*))
{
	if (!is_valid_state(milt->state, STATE_INIT))
		return MILTER_ERROR_STATE;

	milt->add_header = add_header;
	if (add_header != NULL)
		milt->actions |= SMFIF_ADDHDRS;
	else
		milt->actions &= -SMFIF_ADDHDRS;

	return MILTER_OK;
}

int milter_callback_change_header(milter* milt, void (*change_header)(milter*, int, char*, char*))
{
	if (!is_valid_state(milt->state, STATE_INIT))
		return MILTER_ERROR_STATE;

	milt->change_header = change_header;
	if (change_header != NULL)
		milt->actions |= SMFIF_CHGHDRS;
	else
		milt->actions &= -SMFIF_CHGHDRS;

	return MILTER_OK;
}

int milter_callback_replace_body(milter* milt, void (*replace_body)(milter*, int, char*))
{
	if (!is_valid_state(milt->state, STATE_INIT))
		return MILTER_ERROR_STATE;

	milt->replace_body = replace_body;
	if (replace_body != NULL)
		milt->actions |= SMFIF_CHGBODY;
	else
		milt->actions &= -SMFIF_CHGBODY;

	return MILTER_OK;
}

int milter_callback_quarantine(milter* milt, void(*quarantine)(milter*, char*))
{
	if (!is_valid_state(milt->state, STATE_INIT))
		return MILTER_ERROR_STATE;

	milt->quarantine = quarantine;
	if (quarantine != NULL)
		milt->actions |= SMFIF_QUARANTINE;
	else
		milt->actions &= -SMFIF_QUARANTINE;

	return MILTER_OK;
}

/*
    Determine valid next states that have been negotiated on initial
    socket connection.
    FIXME describe state machine
*/
void next_state(milter* milt, unsigned int state)
{
	unsigned int state_ack, state_nak;
	unsigned int states[] = { STATE_CONNECT, STATE_HELO, STATE_MAIL,
                                  STATE_RCPT, STATE_HEADER, STATE_EOH,
                                  STATE_BODY, STATE_EOM, 0};
	unsigned char i, j;

	/* Commands states that the milter will/won't accept */
	state_ack = state & (-(milt->flags) | STATE_EOM );
	state_nak = state & milt->flags;

	/* For each command state the milter wants skipped ... */
	for (i=0; states[i] != 0; i++) {
		if (states[i] & state_nak) {
			/* ... look for the first state after that ... */
			for (j=i+1; states[j] != 0; j++) {
				if (!(states[j] & milt->flags)) {
					/* and add that to state_ack */
					state_ack |= states[j];
					break;
				}
			}
		}
	}
	/* FIXME -------------------v */
	milt->state = state_ack;
	debug("next_state(): Setting milt->state to 0x%.2x\n", milt->state);
}

/*
    Open socket to milter
    @param spec
    * Supported formats:
      - "inet: port @ host"
      - "inet6: port @ host"
      - "local: /path/to/socket"
      - "unix: /path/to/socket"
    * Negotiates protocol options
*/
int milter_open(milter* milt, char* spec)
{
	int res = MILTER_OK;
	struct sockaddr* sa;
	int salen;
	int domain;
	char* port;
	char* host;
	char* tmpstr;
	struct addrinfo hints;
	struct addrinfo *lookupresult = NULL;
	struct addrinfo *r;
	smfi_msg *msg = NULL;

	if (milt->state != STATE_INIT)
		return MILTER_ERROR_STATE;

	milt->error = 0;

	/* Make a working copy of spec */
	port = tmpstr = strdup(spec);
	if (tmpstr == NULL) {
		milt->error = ENOMEM;
		res = MILTER_ERROR;
		goto exit;
	}

	/* Skip over leading whitespace */
	while (isspace(*port)) port++;

	/* Determine address family */
	if (strncmp(port, "local:", 6 == 0) ||
            strncmp(port, "unix:", 5 == 0) ) {
		domain = AF_UNIX;
		salen = sizeof(struct sockaddr_un);
		port += 6;
	} else if (strncmp(port, "inet:", 5) == 0) {
		domain = AF_INET;
		salen = sizeof(struct sockaddr_in);
		port += 5;
	} else if (strncmp(port, "inet6:", 6) == 0) {
		domain = AF_INET6;
		salen = sizeof(struct sockaddr_in6);
		port += 6;
	} else {
		res = MILTER_ERROR_ARG;
		goto exit;
	}
	if ((sa = malloc(salen)) == NULL) {
		milt->error = ENOMEM;
		res = MILTER_ERROR;
		goto exit;
	}

	while(isspace(*port)) port++; /* port points to path / port now */

	if (domain == AF_UNIX) {
		((struct sockaddr_un*)sa)->sun_family = AF_UNIX;
		/* FIXME: unix(7) suggest that
                     #define UNIX_PATH_MAX 108
                   should be found in sys/un.h, but that's at least
                   not the case on Debian
                */
		strncpy( ((struct sockaddr_un*)sa)->sun_path, port, 108 );
	} else {
		host = port;
		/* FIXME: should symbolic service names be allowed? */
		/* Check for port number */
		while(isdigit(*host)) host++;
		if (port == host) {
			res = MILTER_ERROR_ARG;
			goto exit;
		}
		while(isspace(*host)) host++;
		/* check for trailing garbage before @ sign */
		if (*host != '@') {
			res = MILTER_ERROR_ARG;
			goto exit;
		}
		*host = '\0'; host++;
		/* host points to host now. */

		/* Hostname lookup */
		hints.ai_flags = 0;
		hints.ai_family = domain;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = 0;
		/* FIXME: This needs decent error codes */
		if (getaddrinfo(host, port, &hints, &lookupresult) != 0) {
			milt->error = EINVAL; /* FIXME: find better error code */
			res = MILTER_ERROR_IO;
			goto exit;
		}
		for(r=lookupresult; r->ai_next != NULL; r = r->ai_next) {
			if (r->ai_family == domain) break;
		}
		if (r->ai_family != domain) {
			milt->error = EINVAL; /* FIXME: find better error code */
			res = MILTER_ERROR_IO;
			goto exit;
		}
		memcpy(sa, r->ai_addr, salen);
	}

	/* Create socket */
	milt->socket = socket(domain, SOCK_STREAM, 0);
	if (milt->socket == -1) {
		milt->error = errno;
		res = MILTER_ERROR_IO;
		goto exit;
	}

	/* Connect socket */
	if(connect(milt->socket, sa, salen) == -1) {
		milt->error = errno;
		res = MILTER_ERROR_IO;
		goto exit;
	}

	/* Send optneg packet: naked packet + 3*uint32 */
	msg = malloc(sizeof(smfi_msg)+12);
	if (msg == NULL) {
		milt->error = ENOMEM;
		res = MILTER_ERROR;
		goto exit;
	}
	msg->size = htonl(13);
	msg->cmd = SMFIC_OPTNEG;

	OPTNEG_VERSION(msg) = htonl(2);
	OPTNEG_ACTIONS(msg) = htonl(milt->flags);
	OPTNEG_FLAGS(msg) = htonl(milt->actions);

	if (write_msg(milt->socket, (smfi_msg*)msg) != 0) {
		debug("milter_open(): Could not write OPTNEG packet\n");
		res = MILTER_ERROR_IO;
		goto exit;
	}
	free(msg); msg = NULL;
	/* Find out what the milter wants to do */
	/* FIXME: Unclear cast */
	if (read_msg(milt->socket, &msg) != 0) {
		debug("milter_open(): Could not read packet (OPTNEG expected).\b\n");
		res = MILTER_ERROR_IO;
		goto exit;
	}
	if (msg->cmd != SMFIC_OPTNEG) {
		debug("milter_open(): Invalid packet (OPTNEG expected).\b");
		res = MILTER_ERROR_PROTO;
		goto exit;
	}
	if (msg->size != htonl(sizeof(smfi_msg)+8)) {
		debug("milter_open(): Invalid packet size (OPTNEG expected).\b");
		res = MILTER_ERROR_PROTO;
		goto exit;
	}
	debug("milter_open(): Got OPTNEG_FLAGS(msg)=0x%x, msg_actions=0x%x\n",
	      ntohl(OPTNEG_FLAGS(msg)), ntohl(OPTNEG_ACTIONS(msg)));
	/* If the milter has bigger requirements than we are able/willing
           to satisfy, exit with an error */
	if ( ((ntohl(OPTNEG_FLAGS(msg)) & milt->flags) != ntohl(OPTNEG_FLAGS(msg))) ||
	     ((ntohl(OPTNEG_ACTIONS(msg)) & milt->actions) != ntohl(OPTNEG_ACTIONS(msg))) ) {
		debug("milter_open(): OPTNEG failed, milter wants more than we provide\n");
		res = MILTER_ERROR_PROTO;
		goto exit;
	} else {
		milt->flags = ntohl(OPTNEG_FLAGS(msg));
		milt->actions = ntohl(OPTNEG_ACTIONS(msg));
		debug("milter_open(): Setting milt->flags=0x%x, milt->actions=0x%x\n",
		      milt->flags, milt->actions);
	}

	next_state(milt, STATE_CONNECT);

  exit:
	/* free() all dynamic data structures. */
	if (sa) free(sa);
	freeaddrinfo(lookupresult);
	if (tmpstr) free(tmpstr);
	if (msg) free(msg);

	if (res != MILTER_OK) {
		if (milt->socket != 0)
			(void) milter_close(milt);
	}
	return res;
}

/*
    Gracefully close the connection to the milter
*/
int milter_close(milter* milt)
{
	/* Can be called from any state -- ask no questions */
	milt->error = 0;

	if (milt->socket != 0) {
		send_cmd_simple(milt, SMFIC_QUIT);
		close(milt->socket);
		milt->socket = 0;
		return MILTER_OK;
	} else {
		return MILTER_ERROR;
	}
}

int milter_send_macro(milter* milt, char cmd, char** macros)
{
	smfi_msg* msg = NULL;
	int i, j;
	int res = MILTER_OK;
	milt->error = 0;

	/* State check: Does the macro context match any valid next
	   state at this point? */
	if ( !((cmd == SMFIC_CONNECT) && is_valid_state(milt->state, STATE_CONNECT)) ||
	      ((cmd == SMFIC_HELO)    && is_valid_state(milt->state, STATE_HELO)) ||
	      ((cmd == SMFIC_MAIL)    && is_valid_state(milt->state, STATE_MAIL)) ||
	      ((cmd == SMFIC_RCPT)    && is_valid_state(milt->state, STATE_RCPT)) )
		return MILTER_ERROR_STATE;
	/* Calculate total length of key/value strings (j) */
	for (i=0, j=1; macros[i] != NULL; i+=2) {
		j += strlen(macros[i]) + 1;
		j += strlen(macros[i+1]) + 1;
	}
	msg = malloc(sizeof(smfi_msg) + j);
	if (msg == NULL) {
		milt->error = ENOMEM;
		res = MILTER_ERROR;
		goto exit;
	}
	msg->size = htonl(j + 1);
	msg->cmd = SMFIC_MACRO;
	msg->data[0] = cmd;
	/* fill structure */
	for (i=0, j=1; macros[i] != NULL; i+=2) {
		strcpy(&msg->data[j], macros[i]);
		j += strlen(macros[i]) + 1;
		strcpy(&msg->data[j], macros[i+1]);
		j += strlen(macros[i+1]) + 1;
	}
	/* send it */
	if (write_msg(milt->socket, msg) != 0) {
		res = MILTER_ERROR_IO;
		goto exit;
	}

  exit:
	if (msg) free(msg);
	return res;
}

/*
	Send info about newly accepted SMTP connection
	@param hostname
	@param family Address family (AF_INET, AF_INET6, AF_UNIX, AF_UNSPEC)
	@param port
	@param address textual representation of the numeric address
*/
int milter_new_connection(milter* milt, char* hostname, int family, u_int16_t port, char* address)
{
	int h, a, size;
	int res;
	u_int16_t p;
	smfi_msg* msg = NULL;

	if (!is_valid_state(milt->state, STATE_CONNECT))
		return MILTER_ERROR_STATE;

	if (hostname == NULL)
		hostname = "";
	if (address == NULL)
		address = "";

	milt->error = 0;

	h = strlen(hostname) + 1;
	a = strlen(address) + 1;
	/* host + 1 byte family + 2 bytes port + address */
	size = h + 3 + a;

	msg = malloc(sizeof(smfi_msg) + size);
	bzero(msg, sizeof(smfi_msg) + size);

	if (msg == NULL) {
		milt->error = ENOMEM;
		res = MILTER_ERROR;
		goto exit;
	}
	msg->size = htonl(size + 1);
	msg->cmd = SMFIC_CONNECT;

	strcpy(msg->data, hostname);
	switch(family) {
		case AF_UNIX:   msg->data[h] = SMFIA_UNIX;    break;
		case AF_INET:   msg->data[h] = SMFIA_INET;    break;
		case AF_INET6:  msg->data[h] = SMFIA_INET6;   break;
		case AF_UNSPEC: msg->data[h] = SMFIA_UNKNOWN; break;
		default: res = MILTER_ERROR;
			goto exit;
	}

	/* Fill in port and address field */
	if ((family == AF_INET) || (family == AF_INET6)) {
		p = htons(port);
		memcpy(&(msg->data[h+1]), &p, sizeof(p));
		strcpy(&(msg->data[h+3]), address);
	} else {
		msg->data[h+1] = msg->data[h+2] = 0;
		strcpy(&(msg->data[h+3]), "");
	}

	if (write_msg(milt->socket, (smfi_msg*)msg) != 0) {
		res = MILTER_ERROR_IO;
		goto exit;
	}

	res = recv_response(milt);
	if (res >= 0)
		next_state(milt, STATE_HELO);
  exit:
	if (msg) free(msg);
	return res;
}

/*
    Send HELO string
*/
int milter_helo(milter* milt, char* helostr)
{
	int h;
	int res;
	smfi_msg* msg = NULL;

	if (!is_valid_state(milt->state, STATE_HELO))
		return MILTER_ERROR_STATE;

	milt->error = 0;

	if (helostr == NULL)
		helostr="";

	/* Strings need to be null-terminated */
	h = strlen(helostr) + 1;

	msg = malloc(sizeof(smfi_msg) + h);
	if (msg == NULL) {
		milt->error = ENOMEM;
		res = MILTER_ERROR;
		goto exit;
	}
	msg->size = htonl(h + 1);
	msg->cmd = SMFIC_HELO;

	strcpy(msg->data, helostr);

	if (write_msg(milt->socket, msg) != 0) {
		res = MILTER_ERROR_IO;
		goto exit;
	}

	res = recv_response(milt);
	if (res >= 0)
		next_state(milt, STATE_MAIL);
  exit:
	if (msg) free(msg);
	return res;
}

/*
    Set envelope header
*/
int milter_set_from(milter* milt, char* sender, char* extra)
{
	int res;

	if (!is_valid_state(milt->state, STATE_MAIL))
		return MILTER_ERROR_STATE;

	milt->error = 0;

	res = send_cmd_twostrings(milt, SMFIC_MAIL, sender, extra);
	res = recv_response(milt);
	if (res >= 0)
		next_state(milt, STATE_RCPT);

	return res;
}

/*
    Add envelope recipient
*/
int milter_add_rcpt(milter* milt, char* rcpt, char* extra)
{
	int res;

	if (!is_valid_state(milt->state, STATE_RCPT))
		return MILTER_ERROR_STATE;

	milt->error = 0;
	res = send_cmd_twostrings(milt, SMFIC_RCPT, rcpt, extra);
	res = recv_response(milt);

	if (res >= 0)
		next_state(milt, STATE_RCPT | STATE_HEADER);

	return res;
}

/*
    Send header
    @param name Header name, not including ':' character
    @param body Header body
*/
int milter_send_header(milter* milt, char* name, char* body)
{
	int res;

	if (!is_valid_state(milt->state, STATE_HEADER))
		return MILTER_ERROR_STATE;
	/* Strip trailing newline */
	if (body[strlen(body)-1] == '\n')
		body[strlen(body)-1] = '\0';

	milt->error = 0;
	res = send_cmd_twostrings(milt, SMFIC_HEADER, name, body);
	res = recv_response(milt);

	if (res >= 0)
		next_state(milt, STATE_HEADER | STATE_EOH);

	return res;
}

/*
    End of headers
*/
int milter_send_eoh(milter* milt)
{
	int res;

	if (!is_valid_state(milt->state, STATE_EOH))
		return MILTER_ERROR_STATE;

	milt->error = 0;
	res = send_cmd_simple(milt, SMFIC_EOH);
	res = recv_response(milt);
	if (res >= 0)
		next_state(milt, STATE_BODY | STATE_EOM);

	return res;
}

/*
    Send body chunk
    @param size Chunk size
    @param buf Chunk
*/
int milter_send_body_chunk(milter* milt, int size, char* buf)
{
	int res;
	smfi_msg* msg = NULL;

	if (!is_valid_state(milt->state, STATE_BODY))
		return MILTER_ERROR_STATE;

	milt->error = 0;

	msg = malloc(sizeof(smfi_msg) + size);
	if (msg == NULL) {
		milt->error = ENOMEM;
		res = MILTER_ERROR;
		goto exit;
	}
	memcpy(msg->data, buf, size);
	msg->size = htonl(size + 1);
	msg->cmd = SMFIC_BODY;

	if (write_msg(milt->socket, (smfi_msg*)msg) != 0) {
		res = MILTER_ERROR_IO;
		goto exit;
	}

	res = recv_response(milt);
	if (res >= 0)
		next_state(milt, STATE_BODY | STATE_EOM);

  exit:
	if (msg) free(msg);
	return res;
}

/*
    End of message
*/
int milter_send_eom(milter* milt)
{
	int res;

	if (!is_valid_state(milt->state, STATE_EOM))
		return MILTER_ERROR_STATE;

	milt->error = 0;

	res = send_cmd_simple(milt, SMFIC_BODYEOB);
	res = recv_eom_response(milt);

	if (res >= 0)
		next_state(milt, STATE_CONNECT);

	return res;
}

/*
    read mail body from file descriptor and send it to mail filter,
    including end of mail message.
    @param fd file descriptor
*/
int milter_send_body_fd(milter* milt, int fd)
{
	int res;
	char buf[MILTER_CHUNKSIZE];
	int s;

	while ( (s=read(fd, buf, MILTER_CHUNKSIZE)) != 0 ) {
		if (s == -1) {
			if (errno == EINTR) {
				continue;
			}
			else
			{
				res = MILTER_ERROR_IO;
				goto exit;
			}
		}
		res=milter_send_body_chunk(milt, s, buf);
		if (res != MILTER_CONTINUE)
			goto exit;
	}
	res = milter_send_eom(milt);

  exit:
	return res;
}

/*
    read mail body from filehandle and send it to mail filter,
    including end-of-mail message
    @param fh filehandle
*/
int milter_send_body_fh(milter* milt, FILE* fh)
{
	int res;
	char buf[MILTER_CHUNKSIZE];
	int s;

	while ( !feof(fh) ) {
		s=fread(buf, 1, MILTER_CHUNKSIZE, fh);

		if (s < MILTER_CHUNKSIZE) {
			if (ferror(fh))
			{
				res=MILTER_ERROR_IO;
				goto exit;
			}
		}
		res=milter_send_body_chunk(milt, s, buf);
		if (res != MILTER_CONTINUE)
			goto exit;
	}
	res = milter_send_eom(milt);

  exit:
	return res;
}

/*
    Reset mail filter connection.
*/
int milter_reset(milter* milt)
{
	int res = MILTER_OK;
	/* No state check necessary */
	milt->error = 0;

	/* No response expected */
	res = send_cmd_simple(milt, SMFIC_BODYEOB);
	if (res >= 0)
		next_state(milt, STATE_CONNECT);

	return res;
}
