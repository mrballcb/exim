/*
    libspawner, an MTA-side implementation of the Sendmail Milter protocol
    Copyright (C) 2005, 2006, 2011 Hilk Bengen

    License: GPL version 2.1
*/

#include <stdint.h>
#include <stdio.h>

/* Return codes */
#define MILTER_OK           0
#define MILTER_ERROR       -1 /* Probably indicates bug in libspawner */
#define MILTER_ERROR_ARG   -2
#define MILTER_ERROR_STATE -3
#define MILTER_ERROR_IO    -4
#define MILTER_ERROR_PROTO -5 /* Milter sent nonsensical message */
#define MILTER_CONTINUE     0
#define MILTER_ACCEPT       1
#define MILTER_TEMPFAIL     2
#define MILTER_REJECT       3
#define MILTER_DISCARD      4

/* Actions that may be performed by the milter */
#define SMFIF_ADDHDRS    0x01
#define SMFIF_CHGBODY    0x02
#define SMFIF_ADDRCPT    0x04
#define SMFIF_DELRCPT    0x08
#define SMFIF_CHGHDRS    0x10
#define SMFIF_QUARANTINE 0x20

/* Protocol steps that are to be skipped in MTA <-> milter
   communication */
#define SMFIP_NOCONNECT 0x01
#define SMFIP_NOHELO    0x02
#define SMFIP_NOMAIL    0x04
#define SMFIP_NORCPT    0x08
#define SMFIP_NOBODY    0x10
#define SMFIP_NOHDRS    0x20
#define SMFIP_NOEOH     0x40

/* Each connection to a milter is represented by an instance of
   the milter structure */
typedef struct milter milter;

milter* milter_init();

/* Set milter connection parameters */
int milter_set_flags(milter* milt, uint32_t flags);

/*
    Set callback for adding an envelope recipient
    Must be called before the connection to the milter is
    established using milter_open()
*/
int milter_callback_add_rcpt(milter* milt, void(*add_rcpt)(milter*, char*));

/*
    Set callback for removing an envelope recipient
    Must be called before the connection tot he milter is
    established using milter_open()
*/
int milter_callback_del_rcpt(milter* milt, void(*del_rcpt)(milter*, char*));

/*
    Set callback for adding a message header
    Must be called before the connection to the milter is
    established using milter_open()
*/
int milter_callback_add_header(milter* milt, void(*add_header)(milter*, char*, char*));

/*
    Set callback for changing a message header
    Must be called before the connection to the milter is
    established using milter_open()
*/
int milter_callback_change_header(milter* milt, void(*func)(milter*, int, char*, char*));

/*
    Set callback for replacing the message body
    Must be called before the connection to the milter is
    established using milter_open()
*/
int milter_callback_replace_body(milter* milt, void(*func)(milter*, int, char*));

/*
    Set callback for quarantining the message
    Must be called before the connection to the milter is
    established using milter_open()
*/
int milter_callback_quarantine(milter* milt, void(*quarantine)(milter*, char*));

/* FIXME implement this */
void milter_callback_debug(milter* milt, void(*debug_print)(char*, ...));

/* Open/close connection to milter */
int milter_open(milter* milt, char* spec);
int milter_close(milter* milt);

int milter_send_macros(milter* milt, char state, char **nameval);

/* New connection */
int milter_new_connection(milter* milt, char hostname[], int family, uint16_t port, char address[]);

/* HELO / EHLO */
int milter_helo(milter* milt, char* helostr);

/* MAIL FROM, RCPT TO */
int milter_set_from(milter* milt, char* sender, char* extra);
int milter_add_rcpt(milter* milt, char* rcpt, char* extra);

/* Headers */
int milter_send_header(milter* milt, char* name, char* body);
int milter_send_eoh(milter* milt);

/* Body */
int milter_send_body_chunk(milter* milt, int size, char* buf);
int milter_send_body_fd(milter* milt, int fd);
int milter_send_body_fh(milter* milt, FILE* fh);
int milter_send_eom(milter* milt);

/* Return to first state */
int milter_reset(milter* milt);

/* Accessor functions for determining what the OPTNEG stage
   determined */
uint32_t milter_get_flags(milter* milt);
uint32_t milter_get_actions(milter* milt);
