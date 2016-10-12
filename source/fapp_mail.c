
/*!
*
* @file fapp_mail.c
*
* @author Rodrigo Alves
*
* @brief New FNET shell functionality (Mail).
*
***************************************************************************/

#include "fapp.h"
#include "fapp_prv.h"
#include "fapp_dns.h"
#include "fnet.h"
#include "build_defs.h"
#include "stdio.h"
#if FAPP_CFG_MAIL_CMD

#include "fapp_mail.h"
#include "fnet_smtp.h"

#include <wolfssl/ssl.h>
#include <wolfssl/certs_test.h>
/************************************************************************
*     Definitions.
*************************************************************************/
#define DATE_LENGTH 128
#define ERR_MSG_BUFF_SIZE 512

/************************************************************************
*    Benchmark server control structure.
*************************************************************************/
struct fapp_bench_t
{
    fnet_socket_t socket_listen;                   /* Listening socket.*/
    fnet_socket_t socket_foreign;                  /* Foreign socket.*/

    fnet_uint8_t buffer[FAPP_BENCH_PACKET_SIZE_MAX];    /* Transmit circular buffer */

    fnet_time_t first_time;
    fnet_time_t last_time;
    fnet_size_t bytes;
    fnet_size_t remote_bytes;
};

static struct fapp_bench_t fapp_bench;

SMTP_PARAM_STRUCT params = { 0 };
char *server = NULL;
char *email_text = NULL;
fnet_int32_t retval = 0;
fnet_int32_t err_code = 0;

const char *months[] =
{
   "Jan", "Feb", "Mar", "Apr", "May", "Jun",
   "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};
/************************************************************************
*     Function Prototypes
*************************************************************************/
static void fapp_dns_handler_resolved (const struct fnet_dns_resolved_addr *addr_list, fnet_size_t addr_list_size, fnet_uint32_t cookie);
static void fapp_bench_print_results (fnet_shell_desc_t desc);
static int CbIORecv(WOLFSSL *ssl, char *buf, int sz, void *ctx);
static int CbIOSend(WOLFSSL *ssl, char *buf, int sz, void *ctx);
static void ShowCiphers(void);

/************************************************************************
* NAME: fapp_bench_print_results
*
* DESCRIPTION: Print Benchmark results.
************************************************************************/
static void fapp_bench_print_results (fnet_shell_desc_t desc)
{
    /* Print benchmark results.*/
    fnet_time_t interval = fnet_timer_get_interval(fapp_bench.first_time, fapp_bench.last_time);

    fnet_shell_println(desc, "Results:");

    if(fapp_bench.remote_bytes == 0)
    {
        fnet_shell_println(desc, "\t%u bytes in %u.%u seconds = %u Kbits/sec\n", fapp_bench.bytes,
                           ((interval * FNET_TIMER_PERIOD_MS) / 1000),
                           ((interval * FNET_TIMER_PERIOD_MS) % 1000) / 100,
                           (interval == 0) ? (fnet_size_t) - 1 : (fnet_size_t)((fapp_bench.bytes * 8/**(1000*/ / FNET_TIMER_PERIOD_MS/*)*/) / interval)/*/1000*/);
    }
    else /* UDP TX only */
    {
        fnet_shell_println(desc, "\t%u [%u] bytes in %u.%u seconds = %u [%u] Kbits/sec\n", fapp_bench.bytes, fapp_bench.remote_bytes,
                           ((interval * FNET_TIMER_PERIOD_MS) / 1000),
                           ((interval * FNET_TIMER_PERIOD_MS) % 1000) / 100,
                           (interval == 0) ? (fnet_size_t) - 1 : (fnet_size_t)((fapp_bench.bytes * 8/**(1000*/ / FNET_TIMER_PERIOD_MS/*)*/) / interval)/*/1000*/,
                           (interval == 0) ? (fnet_size_t) - 1 : (fnet_size_t)((fapp_bench.remote_bytes * 8/**(1000*/ / FNET_TIMER_PERIOD_MS/*)*/) / interval)/*/1000*/);
    }
}


/************************************************************************
* NAME: fapp_client
* DESCRIPTION: TLS+TCP TX benchmark.
************************************************************************/
void fapp_client( fnet_shell_desc_t desc, fnet_index_t argc, fnet_char_t **argv ){
	 fnet_int32_t            send_result;
		    fnet_char_t             ip_str[FNET_IP_ADDR_STR_SIZE];
		    const struct linger     linger_option = {FNET_TRUE, /*l_onoff*/ 4  /*l_linger*/   };
		    const fnet_size_t       bufsize_option = FAPP_BENCH_SOCKET_BUF_SIZE;
		    const fnet_int32_t      keepalive_option = 1;
		    const fnet_int32_t      keepcnt_option = FAPP_BENCH_TCP_KEEPCNT;
		    const fnet_int32_t      keepintvl_option = FAPP_BENCH_TCP_KEEPINTVL;
		    const fnet_int32_t      keepidle_option = FAPP_BENCH_TCP_KEEPIDLE;
		    struct sockaddr         foreign_addr;
		    fnet_bool_t             exit_flag = FNET_FALSE;
		    fnet_int32_t            sock_err ;
		    fnet_size_t             option_len;
		    fnet_socket_state_t     connection_state;
		    fnet_size_t             packet_size = 1460;
		    fnet_index_t            cur_packet_number;
		    fnet_size_t             buffer_offset;
		    fnet_size_t             packet_number = 10000;
		    fnet_index_t            iterations = 5;

		    fnet_time_t conn_time;
		    fnet_time_t conn_start;
		    WOLFSSL_CTX* ctx = 0;
		   	    WOLFSSL* ssl =0 ;

		   	    /*Initilize WolfSSL library*/
		   	    wolfSSL_Init();
		   	  //  wolfSSL_Debugging_ON();



		   	    /* make new ssl context */
		   	    ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());

		   		/* Load client certs into ctx*/
		   		//if (wolfSSL_CTX_use_certificate_buffer(ctx, client_cert_der_2048 ,sizeof_client_cert_der_2048,SSL_FILETYPE_ASN1) != SSL_SUCCESS){
		   	    if (wolfSSL_CTX_use_certificate_buffer(ctx, client_ecc_cert ,sizeof_client_ecc_cert,SSL_FILETYPE_PEM) != SSL_SUCCESS){
		   			FNET_DEBUG("Error loading certs/client-cert.pem");
		   			goto ERROR_1;}

		   		/* Load client key into ctx*/
		   		//if (wolfSSL_CTX_use_PrivateKey_buffer(ctx,client_key_der_2048,sizeof_client_key_der_2048,SSL_FILETYPE_ASN1) != SSL_SUCCESS){
		   	 if (wolfSSL_CTX_use_PrivateKey_buffer(ctx,client_ecc_key,sizeof_client_ecc_key,SSL_FILETYPE_PEM) != SSL_SUCCESS){
		   			FNET_DEBUG("Error loading certs/client-key.pem");
		   			goto ERROR_1;}

		  /* 	  load CA certificates into wolfSSL_CTX. which will verify the server*/
		   	    //if (wolfSSL_CTX_load_verify_buffer(ctx,ca_cert_der_2048, sizeof_ca_cert_der_2048,SSL_FILETYPE_ASN1) != SSL_SUCCESS) {
		   		if (wolfSSL_CTX_load_verify_buffer(ctx,server_ecc_cert, sizeof_server_ecc_cert,SSL_FILETYPE_PEM) != SSL_SUCCESS) {
		   		FNET_DEBUG("Error loading %s. Please check the file.\n");
		   	        goto ERROR_1;
		   	    }

		   	  wolfSSL_CTX_set_verify(ctx, (SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT),0);
		   	// wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE,0);

		    fnet_memset_zero(&foreign_addr, sizeof(foreign_addr));

		    if(packet_size > (8*1024)) /* Check max size.*/
		        packet_size = (8*1024);
		    //fe80::98f4:1bd1:fdf8:c4f8%3 192.168.3.100
		    if(fnet_inet_ptos("192.168.3.100", &foreign_addr) == FNET_OK)
		      {
		    	foreign_addr.sa_port = FAPP_SERVER_PORT;
		      }
		    fnet_address_family_t   family = foreign_addr.sa_family;


		    fapp_bench.socket_listen = FNET_ERR;
		   // ShowCiphers();

		    /* ------ Start test.----------- */
		    fnet_shell_println(desc, FAPP_DELIMITER_STR);
		    fnet_shell_println(desc, " TLS+TCP TX Test" );
		    fnet_shell_println(desc, FAPP_DELIMITER_STR);
		    fnet_shell_println(desc, FAPP_SHELL_INFO_FORMAT_S, "Remote IP Addr", fnet_inet_ntop(family, foreign_addr.sa_data, ip_str, sizeof(ip_str)));
		    fnet_shell_println(desc, FAPP_SHELL_INFO_FORMAT_D, "Remote Port", fnet_ntohs(foreign_addr.sa_port));
		    fnet_shell_println(desc, FAPP_SHELL_INFO_FORMAT_D, "Message Size", packet_size);
		    fnet_shell_println(desc, FAPP_SHELL_INFO_FORMAT_D, "Num. of messages", packet_number);
		    fnet_shell_println(desc, FAPP_SHELL_INFO_FORMAT_D, "Num. of iterations", iterations);
		    fnet_shell_println(desc, FAPP_TOCANCEL_STR);
		    fnet_shell_println(desc, FAPP_DELIMITER_STR);

		    ssl = wolfSSL_new(ctx);
		     if ( ssl == NULL) {
		    	  fnet_shell_println(desc," wolfSSL_new error");
		     }
		     wolfSSL_SetIORecv(ctx, CbIORecv);
		     wolfSSL_SetIOSend(ctx, CbIOSend);

		    while(iterations--)
		    {
		        /* Create socket */
		        if((fapp_bench.socket_foreign = fnet_socket(family, SOCK_STREAM, 0)) == FNET_ERR)
		        {
		            FNET_DEBUG("BENCH: Socket creation error.\n");
		            iterations = 0;
		            goto ERROR_1;
		        }

		        /* Set Socket options. */
		        if( /* Setup linger option. */
		            (fnet_socket_setopt (fapp_bench.socket_foreign, SOL_SOCKET, SO_LINGER, (fnet_uint8_t *)&linger_option, sizeof(linger_option)) == FNET_ERR) ||
		            /* Set socket buffer size. */
		            (fnet_socket_setopt(fapp_bench.socket_foreign, SOL_SOCKET, SO_RCVBUF, (fnet_uint8_t *) &bufsize_option, sizeof(bufsize_option)) == FNET_ERR) ||
		            (fnet_socket_setopt(fapp_bench.socket_foreign, SOL_SOCKET, SO_SNDBUF, (fnet_uint8_t *) &bufsize_option, sizeof(bufsize_option)) == FNET_ERR) ||
		            /* Enable keepalive_option option. */
		            (fnet_socket_setopt (fapp_bench.socket_foreign, SOL_SOCKET, SO_KEEPALIVE, (fnet_uint8_t *)&keepalive_option, sizeof(keepalive_option)) == FNET_ERR) ||
		            /* Keepalive probe retransmit limit. */
		            (fnet_socket_setopt (fapp_bench.socket_foreign, IPPROTO_TCP, TCP_KEEPCNT, (fnet_uint8_t *)&keepcnt_option, sizeof(keepcnt_option)) == FNET_ERR) ||
		            /* Keepalive retransmit interval.*/
		            (fnet_socket_setopt (fapp_bench.socket_foreign, IPPROTO_TCP, TCP_KEEPINTVL, (fnet_uint8_t *)&keepintvl_option, sizeof(keepintvl_option)) == FNET_ERR) ||
		            /* Time between keepalive probes.*/
		            (fnet_socket_setopt (fapp_bench.socket_foreign, IPPROTO_TCP, TCP_KEEPIDLE, (fnet_uint8_t *)&keepidle_option, sizeof(keepidle_option)) == FNET_ERR)
		        )
		        {
		            FNET_DEBUG("BENCH: Socket setsockopt error.\n");
		            iterations = 0;
		            goto ERROR_2;
		        }

		        /* Connect to the server.*/
		        fnet_shell_println(desc, "Connecting.");

		        fnet_memcpy(&foreign_addr, &foreign_addr, sizeof(foreign_addr));

		        fnet_socket_connect(fapp_bench.socket_foreign, (struct sockaddr *)(&foreign_addr), sizeof(foreign_addr));

		        do
		        {
		            option_len = sizeof(connection_state);
		            fnet_socket_getopt(fapp_bench.socket_foreign, SOL_SOCKET, SO_STATE, (fnet_uint8_t *)&connection_state, &option_len);
		        }
		        while (connection_state == SS_CONNECTING);

		        if(connection_state != SS_CONNECTED)
		        {
		            fnet_shell_println(desc, "Connection failed.");
		            iterations = 0;
		            goto ERROR_2;
		        }

		        conn_start = fnet_timer_ticks();
		        wolfSSL_set_fd(ssl, fapp_bench.socket_foreign);
		           if (wolfSSL_connect(ssl) != SSL_SUCCESS) {
		        	   fnet_shell_println(desc, "Wolfssl connect failed.");
		           }
		           else{
		        conn_time = fnet_timer_ticks();
		        fnet_time_t interval = fnet_timer_get_interval(conn_start, conn_time);
		        fnet_shell_println(desc, "Connection to server took %u.%u seconds",  ((interval * FNET_TIMER_PERIOD_MS) / 1000),
		        	                         ((interval * FNET_TIMER_PERIOD_MS) % 1000) / 100);

		        /* Sending.*/
		        fnet_shell_println(desc, "Sending.");
		        fapp_bench.bytes = 0;
		        fapp_bench.remote_bytes = 0;
		        cur_packet_number = 0;
		        buffer_offset = 0;

		        fapp_bench.first_time = fnet_timer_ticks();
		        while(1)
		        {
		            send_result = wolfSSL_write( ssl , (fnet_uint8_t *)(&fapp_bench.buffer[buffer_offset]), (packet_size - buffer_offset));
		            fapp_bench.last_time = fnet_timer_ticks();

		            if ( send_result == FNET_ERR )
		            {
		                option_len = sizeof(sock_err);
		                fnet_socket_getopt(fapp_bench.socket_foreign, SOL_SOCKET, SO_ERROR, &sock_err, &option_len);
		                fnet_shell_println(desc, "Socket error = %d", sock_err);

		                iterations = 0;
		#if 0
		                /* Print benchmark results.*/
		                fapp_bench_print_results (desc);
		#endif
		                break;
		            }
		            else if(send_result)
		            {
		                fapp_bench.bytes += send_result;
		                buffer_offset += send_result;

		                if(buffer_offset == packet_size)
		                {
		                    cur_packet_number ++;
		                    buffer_offset = 0;
		                }

		                exit_flag = fnet_shell_ctrlc(desc); /* Check [Ctrl+c]*/

		                if((cur_packet_number >= packet_number) || exit_flag)
		                {
		                    if(exit_flag)
		                    {
		                        fnet_shell_println(desc, FAPP_SHELL_CANCELED_CTRL_C);
		                        iterations = 0;
		                    }

		                    /* Print benchmark results.*/
		                    fapp_bench_print_results (desc);
		                    break;
		                }
		            }
		            else
		            {}
		        }
		           }

		    ERROR_2:
		        fnet_socket_close(fapp_bench.socket_foreign);
		    }
		ERROR_1:
		    fnet_shell_println(desc, FAPP_BENCH_COMPLETED_STR);

            wolfSSL_free(ssl);
           		wolfSSL_CTX_free(ctx);
           		wolfSSL_Cleanup();
            fnet_socket_close(fapp_bench.socket_foreign);
}

/************************************************************************
* NAME: fapp_server
* DESCRIPTION: TLS+TCP RX benchmark.
************************************************************************/
void fapp_server( fnet_shell_desc_t desc, fnet_index_t argc, fnet_char_t **argv ){


	 fnet_address_family_t family;

	 family = AF_SUPPORTED;

	  struct sockaddr     local_addr;
	    fnet_int32_t        received;
	    fnet_char_t         ip_str[FNET_IP_ADDR_STR_SIZE];
	    struct linger       linger_option = {FNET_TRUE, /*l_onoff*/
	               4  /*l_linger*/
	    };
	    fnet_size_t         bufsize_option = FAPP_BENCH_SOCKET_BUF_SIZE;
	    fnet_int32_t        keepalive_option = 1;
	    fnet_int32_t        keepcnt_option = FAPP_BENCH_TCP_KEEPCNT;
	    fnet_int32_t        keepintvl_option = FAPP_BENCH_TCP_KEEPINTVL;
	    fnet_int32_t        keepidle_option = FAPP_BENCH_TCP_KEEPIDLE;
	    struct sockaddr     foreign_addr;
	    fnet_size_t         addr_len;
	    fnet_bool_t         exit_flag = FNET_FALSE;
	    WOLFSSL_CTX* ctx = 0;
	    WOLFSSL* ssl =0 ;

	    /*Initilize WolfSSL library*/
	    wolfSSL_Init();
		/*Enable debug mode*/
		//wolfSSL_Debugging_ON();


	    /* make new ssl context */
	    ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method());

	    if (wolfSSL_CTX_set_cipher_list(ctx, "AES128-GCM-SHA256") != SSL_SUCCESS){
	   	    	fnet_shell_println(desc, "Erro cipher.");
	    }

		/* Load server certs into ctx */
		//if (wolfSSL_CTX_use_certificate_buffer(ctx, server_ecc_cert ,sizeof_server_ecc_cert,SSL_FILETYPE_PEM) != SSL_SUCCESS){
		if (wolfSSL_CTX_use_certificate_buffer(ctx, server_cert_der_2048 ,sizeof_server_cert_der_2048,SSL_FILETYPE_ASN1) != SSL_SUCCESS){
			FNET_DEBUG("Error loading certs/server-cert.pem");
			goto ERROR_1;}

		/* Load server key into ctx */
		//if (wolfSSL_CTX_use_PrivateKey_buffer(ctx,ecc_key,sizeof_ecc_key,SSL_FILETYPE_PEM) != SSL_SUCCESS){
		if (wolfSSL_CTX_use_PrivateKey_buffer(ctx,server_key_der_2048,sizeof_server_key_der_2048,SSL_FILETYPE_ASN1) != SSL_SUCCESS){
			FNET_DEBUG("Error loading certs/server-key.pem");
			goto ERROR_1;}

		/*This certificate will be treated as trusted root certificates and used to verify certs received from peers during the SSL handshake.*/
		wolfSSL_CTX_set_verify(ctx, (SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT),0);
	      // if (wolfSSL_CTX_load_verify_buffer(ctx, client_ecc_cert, sizeof_client_ecc_cert,SSL_FILETYPE_PEM) != SSL_SUCCESS)
         if (wolfSSL_CTX_load_verify_buffer(ctx, client_cert_der_2048, sizeof_client_cert_der_2048,SSL_FILETYPE_ASN1) != SSL_SUCCESS)
	    	   FNET_DEBUG("can't load ca file, Please run from wolfSSL home dir");

	    fapp_bench.socket_foreign = FNET_ERR;

	    /* Create listen socket */
	    if((fapp_bench.socket_listen = fnet_socket(family, SOCK_STREAM, 0)) == FNET_ERR)
	    {
	        FNET_DEBUG("BENCH: Socket creation error.");
	        goto ERROR_1;
	    }

	    /* Bind socket.*/
	    fnet_memset_zero(&local_addr, sizeof(local_addr));

	    local_addr.sa_port = FAPP_SERVER_PORT;
	    local_addr.sa_family = family;

	    if(fnet_socket_bind(fapp_bench.socket_listen, &local_addr, sizeof(local_addr)) == FNET_ERR)
	    {
	        FNET_DEBUG("BENCH: Socket bind error.");
	        goto ERROR_2;
	    }

	    /* Set Socket options. */
	    if( /* Setup linger option. */
	        (fnet_socket_setopt (fapp_bench.socket_listen, SOL_SOCKET, SO_LINGER, (fnet_uint8_t *)&linger_option, sizeof(linger_option)) == FNET_ERR) ||
	        /* Set socket buffer size. */
	        (fnet_socket_setopt(fapp_bench.socket_listen, SOL_SOCKET, SO_RCVBUF, (fnet_uint8_t *) &bufsize_option, sizeof(bufsize_option)) == FNET_ERR) ||
	        (fnet_socket_setopt(fapp_bench.socket_listen, SOL_SOCKET, SO_SNDBUF, (fnet_uint8_t *) &bufsize_option, sizeof(bufsize_option)) == FNET_ERR) ||
	        /* Enable keepalive_option option. */
	        (fnet_socket_setopt (fapp_bench.socket_listen, SOL_SOCKET, SO_KEEPALIVE, (fnet_uint8_t *)&keepalive_option, sizeof(keepalive_option)) == FNET_ERR) ||
	        /* Keepalive probe retransmit limit. */
	        (fnet_socket_setopt (fapp_bench.socket_listen, IPPROTO_TCP, TCP_KEEPCNT, (fnet_uint8_t *)&keepcnt_option, sizeof(keepcnt_option)) == FNET_ERR) ||
	        /* Keepalive retransmit interval.*/
	        (fnet_socket_setopt (fapp_bench.socket_listen, IPPROTO_TCP, TCP_KEEPINTVL, (fnet_uint8_t *)&keepintvl_option, sizeof(keepintvl_option)) == FNET_ERR) ||
	        /* Time between keepalive probes.*/
	        (fnet_socket_setopt (fapp_bench.socket_listen, IPPROTO_TCP, TCP_KEEPIDLE, (fnet_uint8_t *)&keepidle_option, sizeof(keepidle_option)) == FNET_ERR)
	    )
	    {
	        FNET_DEBUG("BENCH: Socket setsockopt error.\n");
	        goto ERROR_2;
	    }


	    /* Listen. */
	    if(fnet_socket_listen(fapp_bench.socket_listen, 1) == FNET_ERR)
	    {
	        FNET_DEBUG("BENCH: Socket listen error.\n");
	        goto ERROR_2;
	    }

	    /* ------ Start test.----------- */
	    fnet_shell_println(desc, FAPP_DELIMITER_STR);
	    fnet_shell_println(desc, " TCP+TLS RX Test");
	    fnet_shell_println(desc, FAPP_DELIMITER_STR);
	    fapp_print_netif_addr(desc, family, fnet_netif_get_default(), FNET_FALSE);
	    fnet_shell_println(desc, FAPP_SHELL_INFO_FORMAT_D, "Local Port", FNET_NTOHS(FAPP_SERVER_PORT));
	    fnet_shell_println(desc, FAPP_TOCANCEL_STR);
	    fnet_shell_println(desc, FAPP_DELIMITER_STR);

	    while(exit_flag == FNET_FALSE)
	    {
	        fnet_shell_println(desc, "Waiting.");

	        fapp_bench.bytes = 0;
	        fapp_bench.remote_bytes = 0;
	        if(fapp_bench.socket_foreign != FNET_ERR)
	        {
	            fnet_socket_close(fapp_bench.socket_foreign);
	            fapp_bench.socket_foreign = FNET_ERR;
	        }

	        ssl = wolfSSL_new(ctx);
	      	            if ( ssl == NULL) {
	      	            	fnet_shell_println(desc," wolfSSL_new error");
	      				}
	      	wolfSSL_SetIORecv(ctx, CbIORecv);
	      	wolfSSL_SetIOSend(ctx, CbIOSend);
	        while((fapp_bench.socket_foreign == FNET_ERR) && (exit_flag == FNET_FALSE))
	        {
	            /*Accept*/
	            addr_len = sizeof(foreign_addr);
	            fapp_bench.socket_foreign = fnet_socket_accept(fapp_bench.socket_listen, &foreign_addr, &addr_len);



	 	       /* Connect wolfssl to the socket, server, then read message */
	 	       wolfSSL_set_fd(ssl, fapp_bench.socket_foreign);



	            exit_flag = fnet_shell_ctrlc (desc);

	            if(fapp_bench.socket_foreign != FNET_ERR)
	            {

	                fnet_shell_println(desc, "Receiving from %s:%d", fnet_inet_ntop(foreign_addr.sa_family, (fnet_uint8_t *)(foreign_addr.sa_data), ip_str, sizeof(ip_str)), fnet_ntohs(foreign_addr.sa_port));

	                fapp_bench.first_time = fnet_timer_ticks();

	                while(1) /* Receiving data. fnet_socket_recv*/
	                {

	                    received = wolfSSL_read(ssl, (fnet_uint8_t *)(&fapp_bench.buffer[0]), FAPP_BENCH_PACKET_SIZE_MAX);


	                    /*if (wolfSSL_write(ssl, msg, sizeof(msg)) != sizeof(msg))
	                         fnet_shell_println(desc, "SSL_write failed");*/

	                    if ((received == FNET_ERR) || exit_flag)
	                    {
	                        fapp_bench.last_time = fnet_timer_ticks();

	                        /* Print benchmark results.*/
	                        fapp_bench_print_results (desc);
	                        break;
	                    }
	                    else
	                    {
	                        fapp_bench.bytes += received;
	                        //fnet_shell_println(desc,"Received content %s",fapp_bench.buffer);
	                    }

	                    exit_flag = fnet_shell_ctrlc (desc); /* Check [Ctrl+c]*/
	                }
	                WOLFSSL_CIPHER* cipher;
	               	                                   cipher = wolfSSL_get_current_cipher(ssl);
	               	                                   fnet_shell_println(desc,"SSL cipher suite is %s\n", wolfSSL_CIPHER_get_name(cipher));
	            }
	        }
	    }

	    wolfSSL_free(ssl);
	    fnet_socket_close(fapp_bench.socket_foreign);
		wolfSSL_CTX_free(ctx);
		wolfSSL_Cleanup();

	ERROR_2:
	    fnet_socket_close(fapp_bench.socket_listen);

	ERROR_1:

	    fnet_shell_println(desc, FAPP_BENCH_COMPLETED_STR);

}


void fapp_mail( fnet_shell_desc_t desc, fnet_index_t argc, fnet_char_t **argv ){
    fnet_uint32_t email_size = 0;


    		char date_str[DATE_LENGTH];
    		char* subject = NULL;
    		server = "smtp.gmail.com";
    		params.envelope.from = "";
    		params.envelope.to = "";
    		params.login = "";
    		if(argc == 3)
    		{
    		params.pass = argv[1];
    		subject = argv[2];
    		params.text = argv[3];
    		}
    		else{
        		params.pass = "pass";
        		subject = "Subject";
        		params.text = "Message";
    		}

    		//printf("%04d-%02d-%02dT%02d:%02d:%02d\n",BUILD_YEAR, BUILD_MONTH, BUILD_DAY, BUILD_HOUR, BUILD_MIN, BUILD_SEC);
    		fnet_snprintf(date_str, DATE_LENGTH, "%d %s %d %02d:%02d:%02d", BUILD_DAY, months[BUILD_MONTH-1],BUILD_YEAR, BUILD_HOUR, BUILD_MIN, BUILD_SEC);
    		    /* Evaluate email size */
    		    email_size = fnet_strlen(params.envelope.from) +
    		    		fnet_strlen(params.envelope.to) +
    					fnet_strlen(params.text) +
    					fnet_strlen(subject) +
    					fnet_strlen(date_str) +
    					fnet_strlen("From: <>\r\n") +
    					fnet_strlen("To: <>\r\n") +
    					fnet_strlen("Subject: \r\n") +
    					fnet_strlen("Date: \r\n\r\n") +
    					fnet_strlen("\r\n") + 1;
    		    /* Allocate space */
    		    fnet_shell_println(desc, date_str);
    		    email_text = (char *) fnet_malloc_zero(email_size);
    		    if (email_text == NULL)
    		     {
    		    	fnet_shell_println(desc, FAPP_SHELL_INFO_FORMAT_S, "Unable to allocate memory for email message.\n","");
    		         //return(FNET_ERR);
    		     }
    		    /* Prepare email message */
    		      fnet_snprintf(email_text, email_size, "From: <%s>\r\n"
    		                                       "To: <%s>\r\n"
    		                                       "Subject: %s\r\n"
    		                                       "Date: %s\r\n\r\n"
    		                                       "%s\r\n",
    		                                       params.envelope.from,
    		                                       params.envelope.to,
    		                                       subject,
    		                                       date_str,
    		                                       params.text);
    		      params.text = email_text;

	struct fnet_dns_params      dns_params;

        char *errstr = NULL;
        fnet_uint32_t retval = 0;


		fnet_memset_zero(&params.server, sizeof(params.server));

		/*if server is an already resolved IP*/
		 if(fnet_inet_ptos(server, &params.server) == FNET_OK){

   	    	params.server.sa_port = FNET_HTONS(465);
   	    	params.server.sa_family = AF_INET;

   	    	retval = SMTP_ssl_send_email(desc,&params, errstr, ERR_MSG_BUFF_SIZE);

   	    	fnet_shell_println(desc," Return value = %d",retval);

		 }else{/*If not try to resolve address*/

	      	fnet_memset_zero(&dns_params, sizeof(struct fnet_dns_params));
	      	dns_params.addr_family = AF_INET;
	      	fnet_netif_desc_t           netif = fnet_netif_get_default();
#if FNET_CFG_IP6
        /* IPv6 DNS has higher priority over IPv4.*/
        if(fnet_netif_get_ip6_dns(netif, 0U, (fnet_ip6_addr_t *)&dns_params.dns_server_addr.sa_data) == FNET_TRUE)
        {
            dns_params.dns_server_addr.sa_family = AF_INET6;
        }
        else
#endif
#if FNET_CFG_IP4
            if( (((struct sockaddr_in *)(&dns_params.dns_server_addr))->sin_addr.s_addr = fnet_netif_get_ip4_dns(netif)) != (fnet_ip4_addr_t)0)
            {
                dns_params.dns_server_addr.sa_family = AF_INET;
            }
            else
#endif
            {
                fnet_shell_println(desc, "DNS server is unknown");
                return;
            }

	      	dns_params.host_name = server;                 /* Host name to resolve.*/
	        dns_params.handler = fapp_dns_handler_resolved; /* Callback function.*/
	        dns_params.cookie = (fnet_uint32_t)desc;                 /* Application-specific parameter
	                                                           which will be passed to fapp_dns_handler_resolved().*/
	       retval = fnet_dns_init(&dns_params);
	       if (retval == FNET_ERR)
	       {
	    	   fnet_shell_println(desc, FAPP_SHELL_INFO_FORMAT_S,( "DNS Init failed. Error: 0x%X\n",retval), "");
	           err_code = -5;
	           return(err_code);
	       }else{
	    	   fnet_char_t                 ip_str[FNET_IP_ADDR_STR_SIZE];
	    	   fnet_shell_println(desc, FAPP_SHELL_INFO_FORMAT_S, "DNS Server",
	    	                              fnet_inet_ntop(dns_params.dns_server_addr.sa_family, dns_params.dns_server_addr.sa_data, ip_str, sizeof(ip_str)));
	       }
	       fnet_shell_println(desc, "passou dns", "");
		 }



}
/************************************************************************
* NAME: fapp_dhcp_handler_updated
*
* DESCRIPTION: Event handler on new IP from DHCP client.
************************************************************************/
static void fapp_dns_handler_resolved (const struct fnet_dns_resolved_addr *addr_list, fnet_size_t addr_list_size, fnet_uint32_t cookie)
{
    fnet_char_t                ip_str[FNET_IP_ADDR_STR_SIZE_MAX];
    fnet_shell_desc_t   desc = (fnet_shell_desc_t) cookie;
    fnet_index_t        i;


    fnet_shell_unblock((fnet_shell_desc_t)cookie); /* Unblock the shell. */

    if(addr_list && addr_list_size)
    {
       /* for(i = 0u; i < addr_list_size; i++)
        {
            fnet_shell_printf(desc, FAPP_SHELL_INFO_FORMAT_S, "Resolved address",fnet_inet_ntop(addr_list->resolved_addr.sa_family, addr_list->resolved_addr.sa_data, ip_str, sizeof(ip_str)) );
            fnet_shell_println(desc, "\t TTL=%d", addr_list->resolved_addr_ttl);
            addr_list++;
        }*/
        fnet_shell_println(desc," All resolved IPs printed");
        char *errstr = NULL;
        fnet_uint32_t retval = 0;
        /* Allocate buffer for error message */
    	      	       errstr = (char *) fnet_malloc_zero(ERR_MSG_BUFF_SIZE);
    	      	       /* Try to send email using one of addresses. If it fails try another one. */
    	      	     for(i = 0u; i < addr_list_size; i++)
    	      	       {
    	      	    	fnet_shell_println(desc," Try #%d",i);
    	      	    	//fnet_memset_zero(&params.server, sizeof(params.server));
    	      	        fnet_memcpy( &params.server, &addr_list->resolved_addr, sizeof(params.server));

    	      	    	//fnet_inet_ptos("64.233.186.108", &params.server);
    	      	    	params.server.sa_port = FNET_HTONS(FNET_SMTP_SSL_PORT);
    	      	    	params.server.sa_family = AF_INET;

    	      	         fnet_shell_printf(desc, FAPP_SHELL_INFO_FORMAT_S, "Resolved address 2",
    	      	                    		fnet_inet_ntop(params.server.sa_family, params.server.sa_data, ip_str, sizeof(ip_str)) );
    	      	           // Try to send email

    	      	       //fnet_inet_ptos(fnet_inet_ntop(params.server.sa_family, params.server.sa_data, ip_str, sizeof(ip_str)), &params.server);

    	      	         retval = SMTP_ssl_send_email(desc,&params, errstr, ERR_MSG_BUFF_SIZE);
    	      	           fnet_shell_println(desc," Return value = %d",retval);
    	      	           // If connection failed try another address
    	      	           if (retval != SMTP_ERR_CONN_FAILED)
    	      	           {
    	      	               break;
    	      	           }
    	      	         addr_list++;
    	      	       }
    	      	       /* No address succeeded*/
    	      	       if (addr_list == NULL)
    	      	       {
    	      	    	   fnet_shell_println(desc,  "  Unable to connect to %s.", server);
    	      	           err_code = -5;
    	      	       }

    	      	       if (retval != SMTP_OK)
    	      	       {
    	      	    	   fnet_shell_println(desc, "  Email sending failed%s %s", (fnet_strlen(errstr) > 0) ? ":":".", errstr);
    	      	           err_code = -5;
    	      	       }
    	      	       else
    	      	       {
    	      	    	   fnet_shell_println(desc,"  Email sent.");
    	      	       }
    	      	       /* Cleanup */
    	      	       //freeaddrinfo(result);
    	      	       fnet_free(errstr);
    	      	       fnet_free(email_text);


    }
    else
    {
        fnet_shell_println(desc, "Resolution is FAILED");
    }
}

/*
 * function with specific parameters : inbetween process of receiving msg
 * based from embeded receive in src/io.c
 */
static int CbIORecv(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    int recvd;
    int sd = *(int*)ctx;

    recvd = recv(sd, buf, sz, 0);

    if (recvd < 0) {

        	fnet_printf("IO Recv error %d \n",fnet_error_get());
    }

    //fnet_printf("Received %d bytes\n", sz);

    return recvd;
}


/*
 *function with specific parameters : inbetween process of sending out msg
 *based from embeded receive in src/io.c
 */
static int CbIOSend(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    int sd = *(int*)ctx;
    int sent;
    int len = sz;

    sent =send(sd, &buf[sz - len], len, 0);

    if (sent < 0) {
        fnet_printf("IO Send error %d\n",fnet_error_get());
            return WOLFSSL_CBIO_ERR_GENERAL;
    }

   // fnet_printf("CbIOSend: sent %d bytes to %d\n", sz, sd);

    return sent;
}
static void ShowCiphers(void)
{
    char ciphers[4096];

    int ret = wolfSSL_get_ciphers(ciphers, (int)sizeof(ciphers));

    if (ret == SSL_SUCCESS)
        fnet_printf("%s\n", ciphers);
}

#endif /* FAPP_CFG_MAIL_CMD */






