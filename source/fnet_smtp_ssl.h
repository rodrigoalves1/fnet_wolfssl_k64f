/*
- * fnet_smtp_ssl.h
 *
 *  Created on: 17/05/2016
 *      Author: RodrigoA
 */

#ifndef _FNET_SMTP_SSL_H_
#define _FNET_SMTP_SSL_H_
#include "fnet.h"
#define SMTP_OK                   (0)
#define SMTP_ERR_BAD_PARAM        (1)
#define SMTP_ERR_CONN_FAILED      (2)
#define SMTP_WRONG_RESPONSE       (3)
#define SMTP_RESPONSE_BUFFER_SIZE (512)
#define SMTP_COMMAND_BUFFER_SIZE  (128)

#define SET_ERR_STR(x,y,l) if(x != NULL) snprintf(x, l, "%s", y+4);

typedef struct smtp_email_envelope
{
    char    *from;
    char    *to;
}SMTP_EMAIL_ENVELOPE, * SMTP_EMAIL_ENVELOPE_PTR;

typedef struct smtp_param_struct
{
    SMTP_EMAIL_ENVELOPE envelope;
    char *text;
    struct sockaddr server;
    char *login;
    char *pass;
}SMTP_PARAM_STRUCT, * SMTP_PARAM_STRUCT_PTR;

#ifdef __cplusplus
extern "C" {
#endif

fnet_return_t SMTP_ssl_send_email (fnet_shell_desc_t desc,SMTP_PARAM_STRUCT_PTR param, char *err_string, fnet_uint32_t err_string_size);

#ifdef __cplusplus
}
#endif



#endif /* _FNET_SMTP_SSL_H_ */
