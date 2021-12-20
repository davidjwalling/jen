## Configure the STM32 Device and Project
### Configure the Device

1. The "Clock Configuration" tab allows for clock timing configuration. Here we will set the HCLK (MHz) setting to the maximum supported for the device we are using. Click on the "Clock Configuration" tab. Set the HCLK to the maximum supported value of the device, which in this case is 216 MHz.

<hr><table><tr><td><img src="../images/STM32CubeIDE-1.8.0-Win10-Configure-001.png"></td></tr></table><hr>

2. The "Pinout & Configuration" tab is where most of the configuration of the device will me made. Here we will enable our Real Time Operating System (RTOS) and our Lightweight Internet Protocol (LWIP) stack. We will also define some memory and stack-size settings. Click the "Pinout & Configuration" tab. Select the "System Core" category and the "RCC" subcategory. Set the "High Speed Clock (HSE)" to the "Crystal/Ceramic Resonator" option.

<hr><table><tr><td><img src="../images/STM32CubeIDE-1.8.0-Win10-Configure-002.png"></td></tr></table><hr>

3. When using FreeRTOS, the Timebase Source should be other than the default "SysTick". Select the "SYS" subcategory and change "Timebase Source" to the "TIM6" option.

<hr><table><tr><td><img src="../images/STM32CubeIDE-1.8.0-Win10-Configure-003.png"></td></tr></table><hr>

4. We will not use any USART on the board. Select the "Connectivity" category and the "USART3" subcategory. Set the "Mode" to the "Disable" option.

<hr><table><tr><td><img src="../images/STM32CubeIDE-1.8.0-Win10-Configure-004.png"></td></tr></table><hr>

5. We will not use the USB "On-the-go" (OTG) full-speed feature. Select the "USB_OTG_FS" subcategory. Set the "Mode" to the "Disable" option.

<hr><table><tr><td><img src="../images/STM32CubeIDE-1.8.0-Win10-Configure-005.png"></td></tr></table><hr>

6. We'll use FreeRTOS as our operating system. Select the "Middleware" category and the "FREERTOS" subcategory. Set "Interface" to the "CMSIS_V2" option.

<hr><table><tr><td><img src="../images/STM32CubeIDE-1.8.0-Win10-Configure-006.png"></td></tr></table><hr>

7. We hve 512KB of RAM on our board. We're going to configure the device RAM at 256KB though. On the "Config parameters" tab, set "TOTAL_HEAP_SIZE" to "262144" bytes. This corresponds to 256KB.

<hr><table><tr><td><img src="../images/STM32CubeIDE-1.8.0-Win10-Configure-007.png"></td></tr></table><hr>

8. We want FreeRTOS to provide a handler for a stack overflow condition. On the "Config parameters" tab, in the "Hook function related defintions" section, set "CHECK_FOR_STACK_OVERFLOW" to "Option1".

<hr><table><tr><td><img src="../images/STM32CubeIDE-1.8.0-Win10-Configure-008.png"></td></tr></table><hr>

9. We will use both FreeRTOS and LWIP middleware. Each of them includes a distinct errno.h header. To avoid them having different values, on the "Config parameters" tab, in the "Added with 10.2.1 support" section, set "USE_POSIX_ERRNO" to "Enabled".

<hr><table><tr><td><img src="../images/STM32CubeIDE-1.8.0-Win10-Configure-009.png"></td></tr></table><hr>

10. We will perform calls to new/delete or malloc/free. On the "Advanced settings" tab, set "USE_NEWLIB_REENTRANT" to "Enabled".

<hr><table><tr><td><img src="../images/STM32CubeIDE-1.8.0-Win10-Configure-010.png"></td></tr></table><hr>

11. Our call stack will exceed the default size. On the "Tasks and Queues" tab, click on the "Stack Size (Words)" value for "defaultTask" and change the value from 128 to 256.

<hr><table><tr><td><img src="../images/STM32CubeIDE-1.8.0-Win10-Configure-011.png"></td></tr></table><hr>

12. On the "Mutexes" tab, add the "myMutex01" dynamic mutex.

<hr><table><tr><td><img src="../images/STM32CubeIDE-1.8.0-Win10-Configure-012.png"></td></tr></table><hr>

13. On the "Timers and Semaphores" tab, add the "myBinarySem01" binary semaphore.

<hr><table><tr><td><img src="../images/STM32CubeIDE-1.8.0-Win10-Configure-013.png"></td></tr></table><hr>

14. In th e "Middleware" section, select the "LWIP" category item. Check the "Enabled" check box.

<hr><table><tr><td><img src="../images/STM32CubeIDE-1.8.0-Win10-Configure-014.png"></td></tr></table><hr>

15. We'll expect file descriptors used for sockets to be non-zero. On the "Key Options" tab, set "LWIP_SOCKET_OFFSET" to 1.

<hr><table><tr><td><img src="../images/STM32CubeIDE-1.8.0-Win10-Configure-015.png"></td></tr></table><hr>

16. We'll test with a static network configuration first. On the "General Settings" tab, set "LWIP_DHCP" to "Disabled". Then, set "IP_ADDRESS", "NETMASK_ADDRESS" and "GATEWAY_ADDRESS" appropriately for your network. We can return and enable DHCP after testing a static configuration.

<hr><table><tr><td><img src="../images/STM32CubeIDE-1.8.0-Win10-Configure-016.png"></td></tr></table><hr>

17. Click on the save icon or use the File|Save menu option or press Ctrl+S to save the project IOC file. When the IOC file is saved, the Device Configuration Tool will automatically generate code for the project. If prompted whether to generate code, answer Yes. Close the .ioc file.

<hr><table><tr><td><img src="../images/STM32CubeIDE-1.8.0-Win10-Configure-017.png"></td></tr></table><hr>

18. If prompted to open the C/C++ perspective, answer Yes.

<hr><table><tr><td><img src="../images/STM32CubeIDE-1.8.0-Win10-Configure-018.png"></td></tr></table><hr>

### Configure the Project Files

19. Open the "Project Explorer" window. Locate the file "lwipopts.h" in the LWIP/Target folder. Open the lwipopts.h file and define the SO_REUSE symbol with a value of 1.

<hr><table><tr><td><img src="../images/STM32CubeIDE-1.8.0-Win10-Configure-019.png"></td></tr></table><hr>

20. Locate the file "ethernetif.c" in the LWIP/Target folder. Open the file "ethernetif.c". Change the value of "INTERFACE_THREAD_STACK_SIZE" to 512.

<hr><table><tr><td><img src="../images/STM32CubeIDE-1.8.0-Win10-Configure-020.png"></td></tr></table><hr>

21. Add sample logic to the infinite loop in the StartDefaultTask function to exercise development board LEDs. Save changes to all edited files.

<hr><table><tr><td><img src="../images/STM32CubeIDE-1.8.0-Win10-Configure-021.png"></td></tr></table><hr>

### Compile and Debug the Project

22. Select the "Project" | "Build Project" menu item to build the program.

<hr><table><tr><td><img src="../images/STM32CubeIDE-1.8.0-Win10-Configure-022.png"></td></tr></table><hr>

23. Select the "Run" | "Debug Configurations" menu option to open the "Debug Configurations" window. Right-click on the "STM32 Cortex-M C/C++ Application" category and select "New Configuration". A new debugging configuration is created.

<hr><table><tr><td><img src="../images/STM32CubeIDE-1.8.0-Win10-Configure-023.png"></td></tr></table><hr>

24. On the "main" tab of the "Debug Configurations" window, adjust the configuration name appropriately and select the C/C++ Application to be debugged. Here we select the .elf image created when the project was built.

<hr><table><tr><td><img src="../images/STM32CubeIDE-1.8.0-Win10-Configure-024.png"></td></tr></table><hr>

25. On the "Debugger" tab of the "Debug Configurations" window, make sure "Autostart local GDB sever" is selected. Make sure the Debug probe is set to "ST-LINK (ST-LINK GDB sever)". Make sure that Interface is set to "SWD". Check the "ST-LINK S/N" checkbox. Click the "Scan" button to locate the attached Nucleo Board and read its serial number. Click "Apply" and "Close" to save and close the debugging configuation.

<hr><table><tr><td><img src="../images/STM32CubeIDE-1.8.0-Win10-Configure-025.png"></td></tr></table><hr>

26. Select the "Run" | "Debug" menu item. If prompted to update the firmware of the attached ST-LINK, click Yes.  
  
If the STLinkUpgrade engine starts, click "Open in update mode" to enable firmware update. Confirm the existing and new firmware versions. Then click Upgade. Wait for the upgrade to complete and the window to report "Upgrade successful". Click the "X" at the upper-right corner of the "STLinkUpgrade" window to close it. Then select "Run" | "Debug" again to start the debugger.  
  
If Windows opens a Security Alert window and prompts you to allow the st-link_gdbserver.exe program to listen on incoming ports, check both the "Private networks" and "Public networks" checkboxes and click "Allow access".  
  
If prompted to open the "Debug" perspective, click "Switch".

<hr><table><tr><td><img src="../images/STM32CubeIDE-1.8.0-Win10-Configure-026.png"></td></tr></table><hr>

27. Confirm the program is at a breakpoint at the first instruction within the main routine.

<hr><table><tr><td><img src="../images/STM32CubeIDE-1.8.0-Win10-Configure-027.png"></td></tr></table><hr>

28. Place a breakpoint in StartDefaultTask. Step over instructions in main using the F6 key until osKernelStart is called, which should not return. Reach the breakpoint in StartDefaultTask. Step over instructions in StartDefaultTask and observe the HAL_GPIO_TogglePin calls enable/disable the green LED.

<hr><table><tr><td><img src="../images/STM32CubeIDE-1.8.0-Win10-Configure-028.png"></td></tr></table><hr>

29. Press F8 to allow the program to continue running within the debugger. When you are ready, use Ctrl+F2 to terminate the debugger. Before closing the project, use the "Window" | "Perspective" | "Open Perspective" | "Debug" menu option to open the "Debug" explorer. Be sure to "Remove All Terminated Launches" before debugging again.

<hr><table><tr><td><img src="../images/STM32CubeIDE-1.8.0-Win10-Configure-029.png"></td></tr></table><hr>

30. Use the "Project" | "Close Project" menu item to close the project. Archive your project folder to save your work. We are now ready to replace our sample code with logic to perform network I/O in the next part.
