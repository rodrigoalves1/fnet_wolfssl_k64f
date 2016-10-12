/*
 * fnet_smtp_ssl.c
 *
 *  Created on: 17/05/2016
 *      Author: RodrigoA
 */


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
*   This file contains an implementation of a secure SMTP client.
*
*
*END************************************************************************/

#include <wolfssl/ssl.h>
#include <fnet_base64.h>

#include "fnet_smtp.h"
#include "fnet_config.h"

typedef struct smtp_find_line_context
{
    char *last_start;
    char *last_end;
    fnet_uint32_t first;
}SMTP_FIND_LINE_CONTEXT;

static fnet_uint32_t SMTP_ssl_send_command (WOLFSSL* ssl, char *command, char *response, fnet_uint32_t max_size);
static fnet_uint32_t SMTP_ssl_send_string (WOLFSSL* ssl, char *s);
static fnet_uint32_t SMTP_get_response_code(char *response);
static fnet_uint32_t SMTP_connect (fnet_shell_desc_t desc,struct sockaddr* server);
static void SMTP_ssl_cleanup(WOLFSSL* ssl,WOLFSSL_CTX* ctx, void *a, ...);
static char *SMTP_findline(char *s, char **line_start, fnet_uint32_t *line_length, SMTP_FIND_LINE_CONTEXT* context);
static void SMTP_findline_init(SMTP_FIND_LINE_CONTEXT* context);

const unsigned char certificate_gmail[]={
0x2d,0x2d,0x2d,0x2d,0x2d,0x42,0x45,0x47,0x49,0x4e,0x20,0x43,0x45,0x52,0x54,0x49,0x46,0x49,0x43,0x41,0x54,0x45,0x2d,0x2d,0x2d,0x2d,0x2d,0x0d,0x0a,0x4d,0x49,0x49,0x44
,0x49,0x44,0x43,0x43,0x41,0x6f,0x6d,0x67,0x41,0x77,0x49,0x42,0x41,0x67,0x49,0x45,0x4e,0x64,0x37,0x30,0x7a,0x7a,0x41,0x4e,0x42,0x67,0x6b,0x71,0x68,0x6b,0x69,0x47
,0x39,0x77,0x30,0x42,0x41,0x51,0x55,0x46,0x41,0x44,0x42,0x4f,0x4d,0x51,0x73,0x77,0x43,0x51,0x59,0x44,0x56,0x51,0x51,0x47,0x45,0x77,0x4a,0x56,0x0d,0x0a,0x55,0x7a
,0x45,0x51,0x4d,0x41,0x34,0x47,0x41,0x31,0x55,0x45,0x43,0x68,0x4d,0x48,0x52,0x58,0x46,0x31,0x61,0x57,0x5a,0x68,0x65,0x44,0x45,0x74,0x4d,0x43,0x73,0x47,0x41,0x31
,0x55,0x45,0x43,0x78,0x4d,0x6b,0x52,0x58,0x46,0x31,0x61,0x57,0x5a,0x68,0x65,0x43,0x42,0x54,0x5a,0x57,0x4e,0x31,0x63,0x6d,0x55,0x67,0x51,0x32,0x56,0x79,0x0d,0x0a
,0x64,0x47,0x6c,0x6d,0x61,0x57,0x4e,0x68,0x64,0x47,0x55,0x67,0x51,0x58,0x56,0x30,0x61,0x47,0x39,0x79,0x61,0x58,0x52,0x35,0x4d,0x42,0x34,0x58,0x44,0x54,0x6b,0x34
,0x4d,0x44,0x67,0x79,0x4d,0x6a,0x45,0x32,0x4e,0x44,0x45,0x31,0x4d,0x56,0x6f,0x58,0x44,0x54,0x45,0x34,0x4d,0x44,0x67,0x79,0x4d,0x6a,0x45,0x32,0x4e,0x44,0x45,0x31
,0x0d,0x0a,0x4d,0x56,0x6f,0x77,0x54,0x6a,0x45,0x4c,0x4d,0x41,0x6b,0x47,0x41,0x31,0x55,0x45,0x42,0x68,0x4d,0x43,0x56,0x56,0x4d,0x78,0x45,0x44,0x41,0x4f,0x42,0x67
,0x4e,0x56,0x42,0x41,0x6f,0x54,0x42,0x30,0x56,0x78,0x64,0x57,0x6c,0x6d,0x59,0x58,0x67,0x78,0x4c,0x54,0x41,0x72,0x42,0x67,0x4e,0x56,0x42,0x41,0x73,0x54,0x4a,0x45
,0x56,0x78,0x0d,0x0a,0x64,0x57,0x6c,0x6d,0x59,0x58,0x67,0x67,0x55,0x32,0x56,0x6a,0x64,0x58,0x4a,0x6c,0x49,0x45,0x4e,0x6c,0x63,0x6e,0x52,0x70,0x5a,0x6d,0x6c,0x6a
,0x59,0x58,0x52,0x6c,0x49,0x45,0x46,0x31,0x64,0x47,0x68,0x76,0x63,0x6d,0x6c,0x30,0x65,0x54,0x43,0x42,0x6e,0x7a,0x41,0x4e,0x42,0x67,0x6b,0x71,0x68,0x6b,0x69,0x47
,0x39,0x77,0x30,0x42,0x0d,0x0a,0x41,0x51,0x45,0x46,0x41,0x41,0x4f,0x42,0x6a,0x51,0x41,0x77,0x67,0x59,0x6b,0x43,0x67,0x59,0x45,0x41,0x77,0x56,0x32,0x78,0x57,0x47
,0x63,0x49,0x59,0x75,0x36,0x67,0x6d,0x69,0x30,0x66,0x43,0x47,0x32,0x52,0x46,0x47,0x69,0x59,0x43,0x68,0x37,0x2b,0x32,0x67,0x52,0x76,0x45,0x34,0x52,0x69,0x49,0x63
,0x50,0x52,0x66,0x4d,0x36,0x66,0x0d,0x0a,0x42,0x65,0x43,0x34,0x41,0x66,0x42,0x4f,0x4e,0x4f,0x7a,0x69,0x69,0x70,0x55,0x45,0x5a,0x4b,0x7a,0x78,0x61,0x31,0x4e,0x66
,0x42,0x62,0x50,0x4c,0x5a,0x34,0x43,0x2f,0x51,0x67,0x4b,0x4f,0x2f,0x74,0x30,0x42,0x43,0x65,0x7a,0x68,0x41,0x42,0x52,0x50,0x2f,0x50,0x76,0x77,0x44,0x4e,0x31,0x44
,0x75,0x6c,0x73,0x72,0x34,0x52,0x2b,0x41,0x0d,0x0a,0x63,0x4a,0x6b,0x56,0x56,0x35,0x4d,0x57,0x38,0x51,0x2b,0x58,0x61,0x72,0x66,0x43,0x61,0x43,0x4d,0x63,0x7a,0x45
,0x31,0x5a,0x4d,0x4b,0x78,0x52,0x48,0x6a,0x75,0x76,0x4b,0x39,0x62,0x75,0x59,0x30,0x56,0x37,0x78,0x64,0x6c,0x66,0x55,0x4e,0x4c,0x6a,0x55,0x41,0x38,0x36,0x69,0x4f
,0x65,0x2f,0x46,0x50,0x33,0x67,0x78,0x37,0x6b,0x43,0x0d,0x0a,0x41,0x77,0x45,0x41,0x41,0x61,0x4f,0x43,0x41,0x51,0x6b,0x77,0x67,0x67,0x45,0x46,0x4d,0x48,0x41,0x47
,0x41,0x31,0x55,0x64,0x48,0x77,0x52,0x70,0x4d,0x47,0x63,0x77,0x5a,0x61,0x42,0x6a,0x6f,0x47,0x47,0x6b,0x58,0x7a,0x42,0x64,0x4d,0x51,0x73,0x77,0x43,0x51,0x59,0x44
,0x56,0x51,0x51,0x47,0x45,0x77,0x4a,0x56,0x55,0x7a,0x45,0x51,0x0d,0x0a,0x4d,0x41,0x34,0x47,0x41,0x31,0x55,0x45,0x43,0x68,0x4d,0x48,0x52,0x58,0x46,0x31,0x61,0x57
,0x5a,0x68,0x65,0x44,0x45,0x74,0x4d,0x43,0x73,0x47,0x41,0x31,0x55,0x45,0x43,0x78,0x4d,0x6b,0x52,0x58,0x46,0x31,0x61,0x57,0x5a,0x68,0x65,0x43,0x42,0x54,0x5a,0x57
,0x4e,0x31,0x63,0x6d,0x55,0x67,0x51,0x32,0x56,0x79,0x64,0x47,0x6c,0x6d,0x0d,0x0a,0x61,0x57,0x4e,0x68,0x64,0x47,0x55,0x67,0x51,0x58,0x56,0x30,0x61,0x47,0x39,0x79
,0x61,0x58,0x52,0x35,0x4d,0x51,0x30,0x77,0x43,0x77,0x59,0x44,0x56,0x51,0x51,0x44,0x45,0x77,0x52,0x44,0x55,0x6b,0x77,0x78,0x4d,0x42,0x6f,0x47,0x41,0x31,0x55,0x64
,0x45,0x41,0x51,0x54,0x4d,0x42,0x47,0x42,0x44,0x7a,0x49,0x77,0x4d,0x54,0x67,0x77,0x0d,0x0a,0x4f,0x44,0x49,0x79,0x4d,0x54,0x59,0x30,0x4d,0x54,0x55,0x78,0x57,0x6a
,0x41,0x4c,0x42,0x67,0x4e,0x56,0x48,0x51,0x38,0x45,0x42,0x41,0x4d,0x43,0x41,0x51,0x59,0x77,0x48,0x77,0x59,0x44,0x56,0x52,0x30,0x6a,0x42,0x42,0x67,0x77,0x46,0x6f
,0x41,0x55,0x53,0x4f,0x5a,0x6f,0x2b,0x53,0x76,0x53,0x73,0x70,0x58,0x58,0x52,0x39,0x67,0x6a,0x0d,0x0a,0x49,0x42,0x42,0x50,0x4d,0x35,0x69,0x51,0x6e,0x39,0x51,0x77
,0x48,0x51,0x59,0x44,0x56,0x52,0x30,0x4f,0x42,0x42,0x59,0x45,0x46,0x45,0x6a,0x6d,0x61,0x50,0x6b,0x72,0x30,0x72,0x4b,0x56,0x31,0x30,0x66,0x59,0x49,0x79,0x41,0x51
,0x54,0x7a,0x4f,0x59,0x6b,0x4a,0x2f,0x55,0x4d,0x41,0x77,0x47,0x41,0x31,0x55,0x64,0x45,0x77,0x51,0x46,0x0d,0x0a,0x4d,0x41,0x4d,0x42,0x41,0x66,0x38,0x77,0x47,0x67
,0x59,0x4a,0x4b,0x6f,0x5a,0x49,0x68,0x76,0x5a,0x39,0x42,0x30,0x45,0x41,0x42,0x41,0x30,0x77,0x43,0x78,0x73,0x46,0x56,0x6a,0x4d,0x75,0x4d,0x47,0x4d,0x44,0x41,0x67
,0x62,0x41,0x4d,0x41,0x30,0x47,0x43,0x53,0x71,0x47,0x53,0x49,0x62,0x33,0x44,0x51,0x45,0x42,0x42,0x51,0x55,0x41,0x0d,0x0a,0x41,0x34,0x47,0x42,0x41,0x46,0x6a,0x4f
,0x4b,0x65,0x72,0x38,0x39,0x39,0x36,0x31,0x7a,0x67,0x4b,0x35,0x46,0x37,0x57,0x46,0x30,0x62,0x6e,0x6a,0x34,0x4a,0x58,0x4d,0x4a,0x54,0x45,0x4e,0x41,0x4b,0x61,0x53
,0x62,0x6e,0x2b,0x32,0x6b,0x6d,0x4f,0x65,0x55,0x4a,0x58,0x52,0x6d,0x6d,0x2f,0x6b,0x45,0x64,0x35,0x6a,0x68,0x57,0x36,0x59,0x0d,0x0a,0x37,0x71,0x6a,0x2f,0x57,0x73
,0x6a,0x54,0x56,0x62,0x4a,0x6d,0x63,0x56,0x66,0x65,0x77,0x43,0x48,0x72,0x50,0x53,0x71,0x6e,0x49,0x30,0x6b,0x42,0x42,0x49,0x5a,0x43,0x65,0x2f,0x7a,0x75,0x66,0x36
,0x49,0x57,0x55,0x72,0x56,0x6e,0x5a,0x39,0x4e,0x41,0x32,0x7a,0x73,0x6d,0x57,0x4c,0x49,0x6f,0x64,0x7a,0x32,0x75,0x46,0x48,0x64,0x68,0x0d,0x0a,0x31,0x76,0x6f,0x71
,0x5a,0x69,0x65,0x67,0x44,0x66,0x71,0x6e,0x63,0x31,0x7a,0x71,0x63,0x50,0x47,0x55,0x49,0x57,0x56,0x45,0x58,0x2f,0x72,0x38,0x37,0x79,0x6c,0x6f,0x71,0x61,0x4b,0x48
,0x65,0x65,0x39,0x35,0x37,0x30,0x2b,0x73,0x42,0x33,0x63,0x34,0x0d,0x0a,0x2d,0x2d,0x2d,0x2d,0x2d,0x45,0x4e,0x44,0x20,0x43,0x45,0x52,0x54,0x49,0x46,0x49,0x43,0x41
,0x54,0x45,0x2d,0x2d,0x2d,0x2d,0x2d,0x0d,0x0a};

const int certificate_gmail_size=1162;

/*
** Function for sending email
** IN:
**      SMTP_PARAM_STRUCT_PTR params - Pointer to structure with all required params set up
**                                      (email envelope, email text etc).
**
** OUT:
**      char *err_string - Pointer to string in which error string should be saved (can be NULL -
**                            error string is thrown away in that case).
**
** Return value:
**      fnet_return_t - Error code or SMTP_OK.
*/
fnet_return_t SMTP_ssl_send_email (fnet_shell_desc_t desc,SMTP_PARAM_STRUCT_PTR params, char *err_string, fnet_uint32_t err_string_size)
{
    char *response = NULL;
    char *command = NULL;
    char *location = NULL;
    fnet_uint32_t code = 0;
    fnet_uint32_t socket = 0;
    WOLFSSL_CTX* ctx = 0;
    WOLFSSL* ssl =0 ;
    int error = 0;
    int i = 0;
    char errorString[80];
    fnet_shell_println(desc,"Iniciou send mail ssl");
    /* Check params and envelope content for NULL */
       if ((params == NULL) || (params->envelope.from == NULL) || (params->envelope.to == NULL))
       {
    	   fnet_shell_println(desc,"parametros incorretos");
           return(SMTP_ERR_BAD_PARAM);
       }

       /* Allocate buffers */
       response = (char *) fnet_malloc(sizeof(char)*SMTP_RESPONSE_BUFFER_SIZE);
       if (response == NULL)
       {
    	   fnet_shell_println(desc,"no mem 1");
           return(FNET_ERR_NOMEM);
       }
       command = (char *) fnet_malloc(sizeof(char)*SMTP_COMMAND_BUFFER_SIZE);
       if (command == NULL)
       {
    	   fnet_shell_println(desc,"no mem 2");
       	SMTP_ssl_cleanup(ssl,ctx, response, NULL);
           return(FNET_ERR_NOMEM);
       }

       /* Connect to server */
       socket = SMTP_connect(desc,&params->server);
       if (socket == 0)
       {
    	   fnet_shell_println(desc,"error connecting to server ");
       	SMTP_ssl_cleanup(ssl, ctx, response, command, NULL);
           return(SMTP_ERR_CONN_FAILED);
       }

	wolfSSL_Init();

	 /* make new ssl context */
	ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
	    if ( ctx == NULL) {
	    	fnet_shell_println(desc," wolfSSL_CTX_new error");
	    	SMTP_ssl_cleanup(ssl, ctx, response, command, NULL);
			return(SMTP_ERR_CONN_FAILED);
	    }
	    /* make new wolfSSL struct */
	ssl = wolfSSL_new(ctx);
	       if ( ssl == NULL) {
	    	   fnet_shell_println(desc," wolfSSL_new error");
	       	SMTP_ssl_cleanup(ssl, ctx, response, command, NULL);
	   		return(SMTP_ERR_CONN_FAILED);
	       }

	       /* Add cert to ctx */
	       error = wolfSSL_CTX_load_verify_buffer(ctx,certificate_gmail, certificate_gmail_size,SSL_FILETYPE_PEM);
	       if (error != SSL_SUCCESS) {
	       	SMTP_ssl_cleanup(ssl, ctx, response, command, NULL);
	       	fnet_shell_println(desc," Error loading certificates: 0x%x\n",error);
	   		return(SMTP_ERR_CONN_FAILED);
	       }

	       /* Connect wolfssl to the socket, server, then read message */
	           wolfSSL_set_fd(ssl, socket);

	           /* Read greeting message */
	               i=wolfSSL_read(ssl, response, SMTP_RESPONSE_BUFFER_SIZE);
	               if(i<0)
	               {
	               	error = wolfSSL_get_error(ssl, i);
	           		wolfSSL_ERR_error_string(error, errorString);
	           		fnet_shell_println(desc,"%s",errorString);
	           		SMTP_ssl_cleanup(ssl, ctx, response, command, NULL);
	           		return(SMTP_ERR_CONN_FAILED);
	               }

	               /* Get response code */
	                   code = SMTP_get_response_code(response);
	                   if (code > 299)
	                   {
	                       SET_ERR_STR(err_string, response, err_string_size);
	                       SMTP_ssl_cleanup(ssl, ctx, response, command, NULL);
	                       return(SMTP_WRONG_RESPONSE);
	                   }
	                   fnet_shell_println(desc,"");
	                   fnet_shell_println(desc,"%s",response);
	                   fnet_shell_println(desc,"");

	                   /* Get server extensions */
	                      fnet_sprintf(command, "EHLO FreescaleTower");
	                      code = SMTP_ssl_send_command(ssl, command, response, SMTP_RESPONSE_BUFFER_SIZE);

	                      /* If server does not support EHLO, try HELO */
	                      if (code > 399)
	                      {
	                          fnet_sprintf(command, "HELO FreescaleTower");
	                          code = SMTP_ssl_send_command(ssl, command, response, SMTP_RESPONSE_BUFFER_SIZE);
	                          if (code != 399)
	                          {
	                              SET_ERR_STR(err_string, response, err_string_size);
	                              SMTP_ssl_cleanup(ssl, ctx, response, command, NULL);
	                              return(SMTP_WRONG_RESPONSE);
	                          }
	                      }
	                      /* Try to determine if authentication is supported, authenticate if needed */

	                      fnet_shell_println(desc,"%s",response);

	                      location = fnet_strstr(response, "AUTH");

	                      if ((location != NULL) && fnet_strstr(location, "LOGIN") && (params->login != NULL))
	                      {
	                          char *b64_data = NULL;
	                          fnet_uint32_t b64_length = 0;

	                          /* Send AUTH command */
	                          fnet_sprintf(command, "AUTH LOGIN");
	                          code = SMTP_ssl_send_command(ssl, command, response, SMTP_RESPONSE_BUFFER_SIZE);
	                          if ((code > 399) || (code == 0))
	                          {
	                              SET_ERR_STR(err_string, response, err_string_size);
	                              SMTP_ssl_cleanup(ssl, ctx, response, command, NULL);
	                              return(SMTP_WRONG_RESPONSE);
	                          }

	                          /* Send base64 encoded username */
	                          b64_length = (fnet_strlen(params->login) / 3) * 4 + ((fnet_strlen(params->login) % 3) ? (1) : (0)) + 1;
	                          b64_data = (char *) fnet_malloc(sizeof(char)*b64_length);
	                          if (b64_data == NULL)
	                          {
	                              SMTP_ssl_cleanup(ssl, ctx, response, command, NULL);
	                              return(FNET_ERR_NOMEM);
	                          }
	                          fnet_sprintf(command, "%s", base64_encode(params->login, b64_data));
	                          fnet_free(b64_data);
	                          code = SMTP_ssl_send_command(ssl, command, response, SMTP_RESPONSE_BUFFER_SIZE);
	                          if ((code > 399) || (code == 0))
	                          {
	                              SET_ERR_STR(err_string, response, err_string_size);
	                              SMTP_ssl_cleanup(ssl, ctx, response, command, NULL);
	                              return(SMTP_WRONG_RESPONSE);
	                          }

	                          /* Send base64 encoded password */
	                          b64_length = (fnet_strlen(params->login) / 3) * 4 + ((fnet_strlen(params->pass) % 3) ? (1) : (0)) + 1;
	                          b64_data = (char *) fnet_malloc(sizeof(char)*b64_length);
	                          if (b64_data == NULL)
	                          {
	                              SMTP_ssl_cleanup(ssl, ctx, response, command, NULL);
	                              return(FNET_ERR_NOMEM);
	                          }
	                          fnet_sprintf(command, "%s", base64_encode(params->pass, b64_data));
	                          fnet_free(b64_data);
	                          code = SMTP_ssl_send_command(ssl, command, response, SMTP_RESPONSE_BUFFER_SIZE);
	                          if ((code > 299) || (code == 0))
	                          {
	                              SET_ERR_STR(err_string, response, err_string_size);
	                              SMTP_ssl_cleanup(ssl, ctx, response, command, NULL);
	                              return(SMTP_WRONG_RESPONSE);
	                          }
	                      }
	                      /* Send Email */
	                      fnet_sprintf(command, "MAIL FROM:<%s>", params->envelope.from);
	                      code = SMTP_ssl_send_command(ssl, command, response, SMTP_RESPONSE_BUFFER_SIZE);
	                      if ((code > 299) || (code == 0))
	                      {
	                          SET_ERR_STR(err_string, response, err_string_size);
	                          SMTP_ssl_cleanup(ssl, ctx, response, command, NULL);
	                          return(SMTP_WRONG_RESPONSE);
	                      }
	                      fnet_sprintf(command, "RCPT TO:<%s>", params->envelope.to);
	                      code = SMTP_ssl_send_command(ssl, command, response, SMTP_RESPONSE_BUFFER_SIZE);

	                      /* Mail receiver not OK nor server will forward */
	                      if ((code > 299) || (code == 0))
	                      {
	                          SET_ERR_STR(err_string, response, err_string_size);
	                          SMTP_ssl_cleanup(ssl, ctx, response, command, NULL);
	                          return(SMTP_WRONG_RESPONSE);
	                      }

	                      /* Send message data */
	                      fnet_sprintf(command, "DATA");
	                      code = SMTP_ssl_send_command(ssl, command, response, SMTP_RESPONSE_BUFFER_SIZE);
	                      if ((code > 399) || (code == 0))
	                      {
	                          SET_ERR_STR(err_string, response, err_string_size);
	                          SMTP_ssl_cleanup(ssl, ctx, response, command, NULL);
	                          return(SMTP_WRONG_RESPONSE);
	                      }
	                      /* Send email text */
	                      code = SMTP_ssl_send_string(ssl, params->text);

	                      /* Send terminating sequence for DATA command */
	                      code = SMTP_ssl_send_command(ssl, "\r\n.", response, SMTP_RESPONSE_BUFFER_SIZE);
	                      if ((code > 299) || (code == 0))
	                      {
	                          SET_ERR_STR(err_string, response, err_string_size);
	                          SMTP_ssl_cleanup(ssl, ctx, response, command, NULL);
	                          return(SMTP_WRONG_RESPONSE);
	                      }

	                      /* Write response to user buffer */
	                      SET_ERR_STR(err_string, response, err_string_size);

	                      /* Disconnect from server */
	                      fnet_sprintf(command, "QUIT");
	                      code = SMTP_ssl_send_command(ssl, command, response, SMTP_RESPONSE_BUFFER_SIZE);

	                      /* Cleanup */
	                      SMTP_ssl_cleanup(ssl, ctx, response, command, NULL);


	return(SMTP_OK);
}

/*
** Function for sending string to SMTP server
** IN:
**      int socket - socket used for communication with server.
**      char* s- string to send.
**
** OUT:
**      none
**
** Return value:
**      uint32 - number of bytes send
*/
static fnet_uint32_t SMTP_ssl_send_string(WOLFSSL* ssl, char *s)
{
	fnet_uint32_t               send_total = 0;
	fnet_int32_t                send_step;
    char                   *line = NULL;
    fnet_uint32_t               line_length = 0;
    char                   *last_loc = s;
    fnet_uint32_t               last_length = 0;
    int                    dot = '.';
    SMTP_FIND_LINE_CONTEXT context;

    if (s == NULL) return(0);

    SMTP_findline_init(&context);

    /* Send all lines of text */
    while (SMTP_findline(s, &line, &line_length, &context))
    {
        /* If first character is dot, send another dot to ensure email transparency */
        /* See RFC 5321 section 4.5.2 for details why this must be done */
        if (line[0] == '.')
        {
            //send_step = send(socket, &dot, 1, 0);
        	send_step = wolfSSL_write(ssl,  &dot, 1);
        }
        //send_step = send(socket, line, line_length, 0);
        send_step = wolfSSL_write(ssl,  line, line_length);
        if (send_step > 0)
        {
            send_total += send_step;
        }
        else
        {
            break;
        }
        last_loc = line;
        last_length = line_length;
    }

    /* Send rest which might not end with \n\r sequence */
    if (send_step > 0)
    {
        if (send_total < fnet_strlen(s))
        {
            //send_step = send(socket, last_loc + last_length, strlen(s) - send_total, 0);
        	send_step = wolfSSL_write(ssl,last_loc + last_length, fnet_strlen(s) - send_total);
        	if (send_step > 0)
            {
                send_total += send_step;
            }
        }
    }

    return(send_total);
}

/*
** Function for sending single command to SMTP server
** IN:
**      int socket - socket used for communication with server.
**      char* command - command to send.
**      char* response - response string from server
**      uint32_t max_size - size of response buffer
**
** OUT:
**      char **- pointer to string in which full server response will be saved (can be NULL).
**
** Return value:
**      uint32 - numeric response value
*/
static fnet_uint32_t SMTP_ssl_send_command (WOLFSSL* ssl, char *command, char *response, fnet_uint32_t max_size)
{
    char *out_string;
    fnet_uint32_t rec_len = 0;

    if ((response == NULL) || (command == NULL))
    {
        return(0);
    }
    /* Allocate buffer for output text */
    out_string = (char *) fnet_malloc_zero(fnet_strlen(command)+3);
    if (out_string == NULL)
    {
        return(0);
    }
    /* Add terminating sequence and send command to server */
    fnet_sprintf(out_string, "%s\r\n", command);
    //send(socket, out_string, strlen(out_string), 0);
    printf("Sending: %s",command);
    wolfSSL_write(ssl, out_string, fnet_strlen(out_string));

    /* Read response */
    //rec_len = recv(socket, response, max_size, 0);
    rec_len = wolfSSL_read(ssl, response, max_size);
    response[rec_len] = '\0';
    printf("Received %d bytes: %s",command);
    /* Cleanup and return */
    fnet_free(out_string);
    return(SMTP_get_response_code(response));
}
/*
** Function for reading numeric server response to command
** IN:
**      char* response - response string from server.
**
** OUT:
**      none
**
** Return value:
**      uint32 - numeric response code if valid, zero otherwise
*/
static fnet_uint32_t SMTP_get_response_code(char *response)
{
    char code_str[] = "000";
    if (response != NULL)
    {
    	fnet_strncpy(code_str, response, fnet_strlen(code_str));
    }
    return (fnet_strtoul(code_str, NULL, 10));
}

/*
** Function for connecting to to SMTP server.
** IN:
**      char *server - server to connect to.
**
** OUT:
**      none
**
** Return value:
**      uint32 - socket created and connected to server on port 25 or zero.
*/

static fnet_uint32_t SMTP_connect (fnet_shell_desc_t desc,struct sockaddr* server)
{
	fnet_int32_t   retval = 0;
	fnet_uint32_t  sfd = 0;

    /* Create socket */
    sfd = socket(server->sa_family, SOCK_STREAM, 0);
    if (sfd == FNET_ERR)
    {
        return(0);
    }
    /* Set port for connection */
    switch(server->sa_family)
    {
        case AF_INET:
            ((struct sockaddr_in*) server)->sin_port = RTCS_SMTP_SSL_PORT;
            break;
        case AF_INET6:
            ((struct sockaddr_in6*) server)->sin6_port = RTCS_SMTP_SSL_PORT;
            break;
    }
    /* Connect socket */
    retval = connect(sfd, server, sizeof(*server));
    if (retval != FNET_OK)
    {
        struct linger l_options;

        fnet_shell_printf(desc, "SMTPClient - Connection failed. Error: 0x%X\n", retval);

        /* Set linger options for RST flag sending. */
        l_options.l_onoff = 1;
        l_options.l_linger = 0;
        setsockopt(sfd, SOL_SOCKET, SO_LINGER, &l_options, sizeof(l_options));
        closesocket(sfd);
        return(0);
    }
    return(sfd);


}
/*
** Function for line searching lines in strings. After each call pointer to next line start
** is returned. When no next line can be found NULL is returned.
**
** IN:
**      char *s - email text to search.
**
** OUT:
**      char *line_start - pointer to start of line
**      uint32_t *line_length - pointer to variable i which length of line should be saved
**
** Return value:
**      char *- pointer to start of line
*/

static char *SMTP_findline(char *s, char **line_start, fnet_uint32_t *line_length, SMTP_FIND_LINE_CONTEXT* context)
{
    char *line_end;

    /* Check parameters */
    if (line_length == NULL)
    {
        return(NULL);
    }
    /* First run on string */
    if (!context->first)
    {
        context->first = FNET_TRUE;
        context->last_start = s;
        context->last_end = s;
        *line_start = s;
    }
    else
    {
        *line_start = context->last_end;
    }
    /* Find line end */
    line_end = fnet_strstr(*line_start, "\n\r");
    /* If end of string is reached */
    if (line_end == NULL)
    {
        *line_start = NULL;
        *line_length = 0;
        context->first = FNET_FALSE;
    }
    else
    {
        line_end += 2;
        *line_length = line_end - *line_start;
    }
    /* Update line ending position */
    context->last_end = line_end;
    return(*line_start);
}
/*
** Function for SMTP cleanup - free memory, close sockets etc.
** IN:
**      int socket - Socket to shutdown.
**      pointer a ... - Pointers to deallocate.
**
** OUT:
**      none
**
** Return value:
**      None
*/

static void SMTP_ssl_cleanup(WOLFSSL* ssl,WOLFSSL_CTX* ctx, void *a, ...)
{
    va_list ap;
    /* Close socket */
    if (ssl != 0)
    {
    	wolfSSL_free(ssl);
    }
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();

    /* Free pointers */
    va_start(ap, a);
    while(a != NULL)
    {
        fnet_free(a);
        a = va_arg(ap, void *);
    }
    va_end(ap);
}

/*
 * Initialize context for line searching.
 */

static void SMTP_findline_init(SMTP_FIND_LINE_CONTEXT* context)
{
    context->last_start = NULL;
    context->last_end = NULL;
    context->first = FNET_FALSE;
}
