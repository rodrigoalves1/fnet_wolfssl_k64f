/*
 * mai\zcx\cxn.c
 *
 *  Created on: 10/05/2016
 *      Author: RodrigoA
 */
#ifndef BENCHMARK
#include "board.h"
#include "pin_mux.h"
#include "clock_config.h"
#include "fapp.h" /* FNET API */
#include "fsl_debug_console.h"
#include "fsl_device_registers.h"


/* main entry point*/
int main(void)
{
    /* Init hardware*/
    BOARD_InitPins();
    BOARD_BootClockRUN();
    BOARD_InitDebugConsole();

    /* Init time measurement. SysTick method deployed.
        if (time_config())
        {
            PRINTF("ERROR in SysTick Configuration\r\n");
        }
        else
        {
        	fnet_printf("Clock ok.\n");
        }*/

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
#endif
