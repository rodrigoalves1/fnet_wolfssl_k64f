
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
	struct fnet_dns_params      dns_params;
	fnet_uint32_t email_size = 0;
	char date_str[DATE_LENGTH];
	char* subject = NULL;
	server = "smtp.live.com";
	params.envelope.from = "";
	params.envelope.to = "";
	subject = "agora vai";
	params.text = "ui papai o santinha ja chegou, é o terror do nordeste!!";
	params.login = "";
	params.pass = "";
	//printf("%04d-%02d-%02dT%02d:%02d:%02d\n",BUILD_YEAR, BUILD_MONTH, BUILD_DAY, BUILD_HOUR, BUILD_MIN, BUILD_SEC);
	fnet_snprintf(date_str, DATE_LENGTH, "%d %d %d %02d:%02d:%02d", BUILD_DAY, months[BUILD_MONTH],BUILD_YEAR, BUILD_HOUR, BUILD_MIN, BUILD_SEC);
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
	      snprintf(email_text, email_size, "From: <%s>\r\n"
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
	    	   fnet_shell_println(desc, FAPP_SHELL_INFO_FORMAT_S,( "getaddrinfo failed. Error: 0x%X\n",retval), "");
	           err_code = -5;
	           return(err_code);
	       }else{
	    	   fnet_char_t                 ip_str[FNET_IP_ADDR_STR_SIZE];
	    	   fnet_shell_println(desc, FAPP_SHELL_INFO_FORMAT_S, "DNS Server",
	    	                              fnet_inet_ntop(dns_params.dns_server_addr.sa_family, dns_params.dns_server_addr.sa_data, ip_str, sizeof(ip_str)));
	       }
	       fnet_shell_println(desc, "passou dns", "");




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
        for(i = 0u; i < addr_list_size; i++)
        {
        	 //
            fnet_shell_printf(desc, FAPP_SHELL_INFO_FORMAT_S, "Resolved address",
            		fnet_inet_ntop(addr_list->resolved_addr.sa_family, addr_list->resolved_addr.sa_data, ip_str, sizeof(ip_str)) );
            fnet_shell_println(desc, "\t TTL=%d", addr_list->resolved_addr_ttl);

            addr_list++;
        }
        fnet_shell_println(desc," All resolved IPs printed");
        char *errstr = NULL;
        fnet_uint32_t retval = 0;
        /* Allocate buffer for error message */
    	      	       errstr = (char *) fnet_malloc_zero(ERR_MSG_BUFF_SIZE);
    	      	       /* Try to send email using one of addresses. If it fails try another one. */
    	      	     for(i = 0u; i < addr_list_size; i++)
    	      	       {
    	      	    	fnet_shell_println(desc," Try #%d",i);
    	      	           fnet_memcpy(&addr_list->resolved_addr, &params.server, sizeof(params.server));
    	      	           // Try to send email
    	      	           retval = SMTP_send_email(&params, errstr, ERR_MSG_BUFF_SIZE);
    	      	           fnet_shell_println(desc," Return value = %d",retval);
    	      	           // If connection failed try another address
    	      	           if (retval != SMTP_ERR_CONN_FAILED)
    	      	           {
    	      	               break;
    	      	           }
    	      	         addr_list++;
    	      	       }
    	      	       /* No address succeeded
    	      	       if (rp == NULL)
    	      	       {
    	      	    	   fnet_shell_println(desc,  "  Unable to connect to %s.\n", server);
    	      	           err_code = -5;
    	      	       }*/

    	      	       if (retval != SMTP_OK)
    	      	       {
    	      	    	   fnet_shell_println(desc, "  Email sending failed%s %s\n", (strlen(errstr) > 0) ? ":":".", errstr);
    	      	           err_code = -5;
    	      	       }
    	      	       else
    	      	       {
    	      	    	   fnet_shell_println(desc,"  Email send. Server response: %s", errstr);
    	      	       }
    	      	       /* Cleanup */
    	      	       //freeaddrinfo(result);
    	      	       fnet_free(errstr);
    	      	       fnet_free(email_text);
    	      	       return(err_code);


    }
    else
    {
        fnet_shell_println(desc, "Resolution is FAILED");
    }





}

#endif /* FAPP_CFG_MAIL_CMD */






