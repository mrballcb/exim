/*
    libspawner, an MTA-side implementation of the Sendmail Milter protocol
    Copyright (C) 2005, 2006, 2011 Hilko Bengen

    License: GPL version 2.1
*/

#include <stdint.h>

/* Commands that are passed from MTA to mail filter */
#define SMFIC_ABORT      'A'
#define SMFIC_QUIT       'Q'
#define SMFIC_MACRO      'D'
#define SMFIC_OPTNEG     'O'
#define SMFIC_CONNECT    'C'
#define SMFIC_HELO       'H'
#define SMFIC_MAIL       'M'
#define SMFIC_RCPT       'R'
#define SMFIC_HEADER     'L'
#define SMFIC_EOH        'N'
#define SMFIC_BODY       'B'
#define SMFIC_BODYEOB    'E'

/* Address specification for SMFIC_CONNECT */
#define SMFIA_UNKNOWN    'U'
#define SMFIA_UNIX       'L'
#define SMFIA_INET       '4'
#define SMFIA_INET6      '6'

/* Responses that are sent from mail filter to MTA */
#define SMFIR_ADDRCPT    '+'
#define SMFIR_DELRCPT    '-'
#define SMFIR_ACCEPT     'a'
#define SMFIR_REPLBODY   'b'
#define SMFIR_CONTINUE   'c'
#define SMFIR_DISCARD    'd'
#define SMFIR_ADDHEADER  'h'
#define SMFIR_CHGHEADER  'm'
#define SMFIR_PROGRESS   'p'
#define SMFIR_QUARANTINE 'q'
#define SMFIR_REJECT     'r'
#define SMFIR_TEMPFAIL   't'
#define SMFIR_REPLYCODE  'y'

/*
    Generic Milter message packet structure.
*/
typedef struct smfi_msg {
	/** size of the packet, not including the size field */
	uint32_t size;
	/** command byte (SMFIC_*) */
	char cmd;
	/** generic payload */
	char data[0];
} __attribute__((__packed__)) smfi_msg;

#define OPTNEG_VERSION(i) *(int*)(i->data)
#define OPTNEG_ACTIONS(i) *(int*)(i->data+4)
#define OPTNEG_FLAGS(i)   *(int*)(i->data+8)

/* Low level functions */
int read_msg(int s, smfi_msg** msg);
int write_msg(int s, smfi_msg* msg);

