## Add Networking I/O

1. Jet uses a lightweight open-source JSON parser called "cJSON" by Dave Gamble. Download this from https://github.com/DaveGamble/cJSON.git. Copy the cJSON.h file into the STM32 Project's /Core/Inc file. Copy the cJSON.c file into the STM32 Project's /Core/Src file.

<hr><table><tr><td><img src="../images/stm32cubeide-045.png"></td></tr></table><hr>

<hr><table><tr><td><img src="../images/stm32cubeide-046.png"></td></tr></table><hr>

2. Add these header files from this repo's /src folder to the STM32 Project's /Core/Inc folder: jet.h, jetapi.h, jetbuffer.h, jetchannel.h, jetdriver.h, jetsocket.h, jetudpchannel.h.

<hr><table><tr><td><img src="../images/stm32cubeide-042.png"></td></tr></table><hr>

3. Add these source files from this repo's /src folder to the STM32 Project's /Core/Src folder: jetapi.cpp, jetbuffer.cpp, jetchannel.cpp, jetdriver.cpp, jetsocket.cpp, jetudpchannel.cpp.

<hr><table><tr><td><img src="../images/stm32cubeide-043.png"></td></tr></table><hr>

4. Open the file main.c. Add an include statement to include jet.h.

<hr><table><tr><td><img src="../images/stm32cubeide-044.png"></td></tr></table><hr>

5. Define a simple JSON device data model as a character string in main.c in the user code private variables section.

<hr><table><tr><td><img src="../images/stm32cubeide-047.png"></td></tr></table><hr>

6. Replace the user code in the StartDefaultTask function as shown below. After LWIP is initialized, we make two Jet API calls. The first call, to jetSetModel, tells Jet to use the JSON string we defined above as the device data model. The second call, to jetStart, tells Jet to listen on TCP and UDP on the INADDR_ANY address (0.0.0.0) on a reserved port. In the infinite loop, we call jetRun and a short osDelay. The jetRun API performs one iteration of the machine state. Also, we've set a breakpoint on the call to jetSetModel.

<hr><table><tr><td><img src="../images/stm32cubeide-048.png"></td></tr></table><hr>

7. Rebuild the project. Use the "Run" | "Debug" menu option or press the F11 key to debug the program. When control reaches the main routine, press F8 to continue debugging. When control reaches the breakpoint at jetSetModel, either step through the code to become familiar with it or press F8 to continue.

<hr><table><tr><td><img src="../images/stm32cubeide-049.png"></td></tr></table><hr>

8. When the jetStart API is called, a title message is output to the debug console.

<hr><table><tr><td><img src="../images/stm32cubeide-050.png"></td></tr></table><hr>

9. When LWIP initialized, the device became reachable by ICMP packets using the "ping" utility. We can confirm that by "ping'ing" the configured IP address.

<hr><table><tr><td><img src="../images/stm32cubeide-051.png"></td></tr></table><hr>

10. When Jet started, it begins listening on the configured port. Here, we used port 1143. We can use a telnet client in "raw" mode to connect to Jet over TCP, send it a message and receive a reply.

<hr><table><tr><td><img src="../images/stm32cubeide-052.png"></td></tr></table><hr>



Go back to [Configure the Device and Project](STM32Configure.md)  
Return to [README](../README.md)
