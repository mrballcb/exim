/*
    libspawner, an MTA-side implementation of the Sendmail Milter protocol
    Copyright (C) 2005, 2006, 2011 Hilko Bengen

    License: GPL version 2.1
*/

#include <stdint.h>

/* State information */
#define STATE_INIT       0x00
#define STATE_CONNECT    0x01
#define STATE_HELO       0x02
#define STATE_RCPT       0x04
#define STATE_MAIL       0x08
#define STATE_HEADER     0x20
#define STATE_BODY       0x10
#define STATE_EOH        0x40
#define STATE_EOM        0x80000000

#define MILTER_CHUNKSIZE 8192

/*
    Structure associated with a connection to a milter process.
    This structure is opaque to programs using this library.
*/

struct milter {
	int socket;
	int error;
	/** internal state */
	uint32_t state;
	/** Milter protocol API version */
	uint32_t version;
	/** Modifier flags for this connection */
	uint32_t flags;    /* modification flags SMFIF_* */
	/** Modification actions that the mail filter may perform
            on message(s). */
	uint32_t actions;  /* protocol actions SMFIP_* */
	/** Custom reply text that should be passed to the SMTP
            client */
	char* replytext;
	/** Callback for "add envelope recipient" modification action */
	void (*add_rcpt)(struct milter*, char*);
	/** Callback for "remove envelope recipient" modification action */
	void (*del_rcpt)(struct milter*, char*);
	/** Callback for "add header" modification action */
	void (*add_header)(struct milter*, char*, char*);
	/** Callback for "change header" modification action */
	void (*change_header)(struct milter*, int, char*, char*);
	/** Callback for "replace body" modification action */
	void (*replace_body)(struct milter*, int, char*);
	/** Callback for "quarantine" modification action */
	void (*quarantine)(struct milter*, char*);
};
