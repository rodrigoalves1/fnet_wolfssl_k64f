/*
 * fnet_smtp.h
 *
 *  Created on: 16/05/2016
 *      Author: RodrigoA
 */

#ifndef _FNET_SMTP_H_
#define _FNET_SMTP_H_

#include "fnet.h"
/*HEADER**********************************************************************
*
* Copyright 2013 Freescale Semiconductor, Inc.
*
* This software is owned or controlled by Freescale Semiconductor.
* Use of this software is governed by the Freescale MQX RTOS License
* distributed with this Material.
* See the MQX_RTOS_LICENSE file distributed for more details.
*
* Brief License Summary:
* This software is provided in source form for you to use free of charge,
* but it is not open source software. You are allowed to use this software
* but you cannot redistribute it or derivative works of it in source form.
* The software may be used only in connection with a product containing
* a Freescale microprocessor, microcontroller, or digital signal processor.
* See license agreement file for full license terms including other
* restrictions.
*****************************************************************************
*
* Comments:
*
*   Simple Mail Transfer Protocol definitions.
*
*
*END************************************************************************/

#define SMTP_OK                   (0)
#define SMTP_ERR_BAD_PARAM        (1)
#define SMTP_ERR_CONN_FAILED      (2)
#define SMTP_WRONG_RESPONSE       (3)
#define SMTP_RESPONSE_BUFFER_SIZE (512)
#define SMTP_COMMAND_BUFFER_SIZE  (128)
#define IPPORT_SMTP        25
#define IPPORT_SMTP_SSL    465
#define IPPORT_SMTP_TLS    587

#define SOCKET_EWOULDBLOCK  11
#define SOCKET_EAGAIN       FNET_ERR_AGAIN
#define SOCKET_ECONNRESET   FNET_ERR_CONNRESET
#define SOCKET_EINTR        4
#define SOCKET_EPIPE        32
#define SOCKET_ECONNREFUSED FNET_ERR_NETUNREACH
#define SOCKET_ECONNABORTED FNET_ERR_CONNABORTED

#define FAPP_BENCH_COMPLETED_STR            "Test completed."
#define FAPP_SERVER_PORT                         (FNET_HTONS(7007))      /* Port used by the server application (in network byte order).*/
#define FAPP_BENCH_PACKET_SIZE_MAX              (8*1024)    /* Defines size of Applacation and Socket TX&RX buffers.*/
#define FAPP_BENCH_SOCKET_BUF_SIZE          (FAPP_BENCH_PACKET_SIZE_MAX)
/* Keepalive probe retransmit limit.*/
#define FAPP_BENCH_TCP_KEEPCNT              (2)

/* Keepalive retransmit interval.*/
#define FAPP_BENCH_TCP_KEEPINTVL            (5) /*sec*/

/* Time between keepalive probes.*/
#define FAPP_BENCH_TCP_KEEPIDLE             (5) /*sec*/


#ifndef FNET_SMTP_PORT
    #define FNET_SMTP_PORT IPPORT_SMTP
    #define FNET_SMTP_SSL_PORT IPPORT_SMTP_SSL

#endif

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
/*
struct smtp_param_struct
{
    SMTP_EMAIL_ENVELOPE envelope;
    char *text;
    struct sockaddr server;
    char *login;
    char *pass;
};*/

#ifdef __cplusplus
extern "C" {
#endif

fnet_uint32_t SMTP_send_email (SMTP_PARAM_STRUCT_PTR params, char *err_string, fnet_uint32_t err_string_size);

#ifdef __cplusplus
}
#endif


#endif /* SOURCE_FNET_SMTP_H_ */
