## Create the STM32 Project
### Start the New STM32 Project Wizard

Launch STM32CubeIDE. Select the "File" | "New" | "STM32 Project" menu option. This will initiate the download of configuration data to support the STM32Cube tool.

<hr><table><tr><td><img src="../images/stm32cubeide-1.8.0-win10-010.png"></td></tr></table><hr>

When the STM32Cube tools is ready, it will launch the Target Selection window. Here, click on the Board Selector tab and enter the Commercial Part Number of the development board being used. Here we are using a NUCLEO-F767ZI. The value entered in the Commercial Part Number field will automatically filter the Boards List. Select the desired board in the Boards List and then click Next.

<hr><table><tr><td><img src="../images/stm32cubeide-1.8.0-win10-011.png"></td></tr></table><hr>

In the "STM32 Project" dialog, we enter the project name "ayriel" and will accept the default workplace location. We select "C++" as the targeted language. The Targted Binary Type is Executable. Th Targeted Project Type is STM32Cube. We'll accept the default options on the final page of this wizard, so we can click on Finish here.

<hr><table><tr><td><img src="../images/stm32cubeide-1.8.0-win10-012.png"></td></tr></table><hr>

If asked whether to initialize all peripherals with their default Mode, answer Yes.

<hr><table><tr><td><img src="../images/stm32cubeide-1.8.0-win10-013.png"></td></tr></table><hr>

If promptd to open the Device Configuration Tool prespective, answer Yes.

<hr><table><tr><td><img src="../images/stm32cubeide-1.8.0-win10-014.png"></td></tr></table><hr>

 The device configuration tool will now download packages specific to the development board we selected. This can take a few minutes.

<hr><table><tr><td><img src="../images/stm32cubeide-1.8.0-win10-015.png"></td></tr></table><hr>

When the download completes, the project will be initialized and its IOC file will be opened at the default "Pinout & Configuration" tab. Now we are ready to configure the device and project settings, which we will do in the next part.

<hr><table><tr><td><img src="../images/stm32cubeide-1.8.0-win10-016.png"></td></tr></table><hr>
