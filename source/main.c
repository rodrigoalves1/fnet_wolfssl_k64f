/*
 * mai\zcx\cxn.c
 *
 *  Created on: 10/05/2016
 *      Author: RodrigoA
 */
#include "fapp.h" /* FNET API */
/* main entry point*/
int main(void)
{

    /* Init UART */
    fnet_cpu_serial_init(FNET_CFG_CPU_SERIAL_PORT_DEFAULT, 115200u);
    /* Enable interrupts */
    fnet_cpu_irq_enable(0u);

    /*Run app*/
    fapp_main();

    return(0);

    /* FNET Initialization
    if (fnet_init_static() != FNET_ERR)
    {
        fnet_printf(__TIME__);
        fnet_printf("\nTCP/IP stack initialization is done.\n");
    }
    else
    {
        fnet_printf("\nError:TCP/IP stack initialization is failed.\n");
    }

    for(;;)
    {
    }*/
}
