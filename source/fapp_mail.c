
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
* NAME: fapp_mail
*
* DESCRIPTION: Mail command.
************************************************************************/
void fapp_server( fnet_shell_desc_t desc, fnet_index_t argc, fnet_char_t **argv ){
	fnet_shell_println(desc, FAPP_SHELL_INFO_FORMAT_S, "Santa Cruz Futebol Clube"," Terror do Nordeste");


	 int socket_desc , client_sock , c , read_size;
	    struct sockaddr_in server , client;
	    char client_message[2000];

	    //Create socket
	    socket_desc = socket(AF_INET , SOCK_STREAM , 0);
	    if (socket_desc == FNET_ERR)
	    {
	    	fnet_shell_println(desc, FAPP_SHELL_INFO_FORMAT_S, "Socket"," Could not create socket");
	    }else{
	    fnet_shell_println(desc, FAPP_SHELL_INFO_FORMAT_S, "Socket"," Socket created");
	    }
	    //Prepare the sockaddr_in structure
	    server.sin_family = AF_INET;
	    server.sin_addr.s_addr = INADDR_ANY;
	    fnet_shell_println(desc, FAPP_SHELL_INFO_FORMAT_S, "IP"," Socket created");
	    server.sin_port = FNET_HTONS( 8888 );

	    fnet_memset_zero(&server,sizeof(server));

	    //Bind
	    if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) == FNET_ERR)
	    {
	        //print the error message
	    	fnet_shell_println(desc, FAPP_SHELL_INFO_FORMAT_S, "Socket"," bind failed. Error");
	        return 1;
	    }
	    fnet_shell_println(desc, FAPP_SHELL_INFO_FORMAT_S, "Socket"," bind done");

	    //Listen
	    listen(socket_desc , 5);

	   /* //Accept and incoming connection
	    fnet_shell_println(desc, FAPP_SHELL_INFO_FORMAT_S, "Connection","Waiting for incoming connections...");
	    }*/
	    c = sizeof(client);

	    //accept connection from an incoming client

	    if ( (client_sock = accept((fnet_socket_t) socket_desc, (struct sockaddr *)&client, (fnet_size_t) &c)) == FNET_ERR)
	    {
	    	fnet_shell_println(desc, FAPP_SHELL_INFO_FORMAT_S, "Connection","accept failed");
	    	return 1;
	    }
	    fnet_shell_println(desc, FAPP_SHELL_INFO_FORMAT_S, "Connection","accepted");

	    //Receive a message from client
	    while( (read_size = recv(client_sock , client_message , 2000 , 0)) > 0 )
	    {
	        //Send the message back to client
	        send(client_sock , client_message , strlen(client_message),0);
	    }
	    if(read_size == 0)
	    {
	    	fnet_shell_println(desc, FAPP_SHELL_INFO_FORMAT_S, "Client","disconnected");
	        fflush(stdout);
	    }
	    else if(read_size == -1)
	    {
	    	fnet_shell_println(desc, FAPP_SHELL_INFO_FORMAT_S, "recv","failed");
	    }

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

#endif /* FAPP_CFG_MAIL_CMD */






