/**************************************************************************
*
* Copyright 2014 by Andrey Butok. FNET Community.
*
***************************************************************************
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License Version 3
* or later (the "LGPL").
*
* As a special exception, the copyright holders of the FNET project give you
* permission to link the FNET sources with independent modules to produce an
* executable, regardless of the license terms of these independent modules,
* and to copy and distribute the resulting executable under terms of your
* choice, provided that you also meet, for each linked independent module,
* the terms and conditions of the license of that module.
* An independent module is a module which is not derived from or based
* on this library.
* If you modify the FNET sources, you may extend this exception
* to your version of the FNET sources, but you are not obligated
* to do so. If you do not wish to do so, delete this
* exception statement from your version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*
* You should have received a copy of the GNU General Public License
* and the GNU Lesser General Public License along with this program.
* If not, see <http://www.gnu.org/licenses/>.
*
**********************************************************************/ /*!
*
* @file fnet_ssl.c
*
* @author Andrey Butok
*
* @brief FNET SSL API.
*
***************************************************************************/

#include "fnet_config.h"

#if FNET_CFG_SSL // TBD under development

#include "fnet_ssl.h"
#include "wolfssl/ssl.h"


/* Initialize WolfSSL */
fnet_ssl_session_desc_t fnet_ssl_session_init(struct fnet_ssl_session_params *params)
{
    fnet_ssl_session_desc_t result = 0;
    WOLFSSL_CTX              *ctx = FNET_NULL;

    if(params)
    {
        /* WolfSSL_Init() is optional; Called by WolfSSL_CTX_new() */

    switch (params->session_role)
    {
        case FNET_SSL_SESSION_ROLE_SERVER:
            /* Server method call. Allow use highest possible version from SSLv3 - TLS 1.2*/
            ctx = wolfSSL_CTX_new(wolfSSLv23_server_method());
            break;
        case FNET_SSL_SESSION_ROLE_CLIENT:
            /* Client method call. Use highest possible version from SSLv3 - TLS 1.2*/
            ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
            break;
        default:
            break;
    }

        if (ctx)
        {
            /* Loading Client or Server Certificate chane.*/
            if((params->cert_file_path && (wolfSSL_CTX_use_certificate_chain_file(ctx, params->cert_file_path) != SSL_SUCCESS))
               /* Loading Private Key into the SSL context. */
               || (params->priv_key_file_path && (wolfSSL_use_PrivateKey_file(ctx, params->priv_key_file_path, SSL_FILETYPE_PEM) != SSL_SUCCESS))
               /* Loading CA (Certificate Authority), or trusted root,  certificates.*/
               /* Used to verify certs received from peers during the SSL handshake.*/
               || (params->ca_cert_file_path && (wolfSSL_CTX_load_verify_locations(ctx, params->ca_cert_file_path, FNET_NULL) != SSL_SUCCESS)) )
            {
                /* Error of loading.*/
            	wolfSSL_CTX_free(ctx);
                ctx = FNET_NULL;
            }
        }

        result = (fnet_ssl_session_desc_t) ctx;
    }

    return(result);
}

/* Release WolfSSL */
void fnet_ssl_session_release(fnet_ssl_session_desc_t ssl_desc)
{
    if(ssl_desc)
    {
        /*  Free the WOLFSSL_CTX object.*/
    	wolfSSL_CTX_free((WOLFSSL_CTX *)ssl_desc);

        /* WolfSSL_Cleanup(); Doesn’t have to be called: http://www.yassl.com/yaSSL/Docs-cyassl-manual-17-1-cyassl-api-init-shutdown.html */
    }
}


/* Create SSL connection using sock, return SSL connection handle. */
SSL_SOCKET fnet_ssl_socket(fnet_ssl_session_desc_t session_desc, fnet_socket_t sock)
{
    SSL_SOCKET  retval = FNET_ERR;
    WOLFSSL_CTX  *ssl_ctx;
    WOLFSSL      *ssl_sock;

    ssl_ctx = (WOLFSSL_CTX *) session_desc;

    /* Create the WOLFSSL object after TCP connect.*/
    if ((ssl_sock = wolfSSL_new(ssl_ctx)) != FNET_NULL)
    {
        /* Associate the socket (file descriptor) with the session.*/
        if (wolfSSL_set_fd(ssl_sock, sock) == SSL_SUCCESS)
        {
            retval = (SSL_SOCKET) ssl_sock;
        }
        else
        {
            wolfSSL_free(ssl_sock);
        }
    }

    return(retval);
}

/* Shutdown SSL connection. */
int fnet_ssl_closesocket(SSL_SOCKET ssl_sock)
{
    int   result = FNET_ERR; /* FNET_ERR = SOCKET_ERROR*/

    if((ssl_sock != FNET_ERR) && (wolfSSL_shutdown((WOLFSSL *)ssl_sock) == SSL_SUCCESS))
    {
        wolfSSL_free((WOLFSSL *)ssl_sock);
        result = FNET_OK;
    }

    return result;
}

/* Receive data from SSL layer. */
int fnet_ssl_recv(SSL_SOCKET ssl_sock, char *buf, int len, int flags)
{
    int     result = FNET_ERR;

    if(ssl_sock != FNET_ERR)
    {
        result = wolfSSL_recv((WOLFSSL *) ssl_sock, buf, len, flags);
    }

    return result;
}

/* Send data through SSL layer. */
int fnet_ssl_send(SSL_SOCKET ssl_sock, char *buf, int len, int flags)
{
    int     result = FNET_ERR;

    if(ssl_sock != FNET_ERR)
    {
        result = wolfSSL_send((WOLFSSL *) ssl_sock, buf, len, flags);
    }

    return result;
}


#endif /* FNET_CFG_SSL */
