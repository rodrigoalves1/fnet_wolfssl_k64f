
/*!
*
* @file fapp_mail.h
*
* @author Rodrigo Alves
*
* @brief New FNET shell functionality (Mail).
*
***************************************************************************/

#ifndef _FAPP_MAIL_H_

#define _FAPP_MAIL_H_

#include "fapp_config.h"

#if FAPP_CFG_MAIL_CMD

/* Default parameters.*/


#if defined(__cplusplus)
extern "C" {
#endif

void fapp_mail( fnet_shell_desc_t desc, fnet_index_t argc, fnet_char_t **argv );
void fapp_server(fnet_shell_desc_t desc, fnet_index_t argc, fnet_char_t **argv );
void fapp_client(fnet_shell_desc_t desc, fnet_index_t argc, fnet_char_t **argv );
#if defined(__cplusplus)
}
#endif

#endif /* FAPP_CFG_MAIL_CMD */

#endif /* _FAPP_MAIL_H_ */
