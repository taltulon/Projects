**BSOD - GSOD**

My goal is to change the windows Blue Screen of Death (BSOD) to a green color. The approach that will be taken is to debug ntoskrnl.exe find out and modify what's happening there with WINDBG.
Before we can start, we must learn some theory, what function is causing the BSOD? Where is our color parameter?
We start by reading from Windows Internals 6th Edition, 2nd and find the next thing:

![whatever](https://github.com/taltulon/Projects/blob/main/BSOD/BSOD-Images/Picture1.png)

Well, lets check what happens in ```KeBugCheckEx```:

![whatever](https://github.com/taltulon/Projects/blob/main/BSOD/BSOD-Images/Picture2.png)

Looks like our function ends in a call to KeBugCheck2 with different parameters, if we go over this function, we can find a call to ```KiDisplayBlueScreen```.
Oh well, what's in there?
We can’t really identify the function that executes the window creation (at least by name), or just sets its color, so now we have to start debugging!
Turn on our Windows 10 workstation, enable kernel debugging by using ```bcdedit /debug on```,
Running ```kdnet.exe <debugger_ip> <connection_port>``` and receiving a key, in our case it is *******************
Now we open WINDBG on the debugging computer and put a breakpoint on ```nt!KiDisplayBlueScreen```:
```
0: kd> bu nt!KiDisplayBlueScreen
0: kd> g
```
We have to download symbols of the ntoskrnl.exe so lets do it too:
```
0: kd> .reload /i ntoskrnl.exe
```
Lets cause a blue screen by using notmyfault.exe (sysinternals tool that creates BSOD by crushing its own driver) and get the following screen on WINDBG:

![whatever](https://github.com/taltulon/Projects/blob/main/BSOD/BSOD-Images/Picture3.png)

This message lets us analyze the BSOD, but we don't really care because we made it happen, lets press g to proceed to our breakpoint:

![whatever](https://github.com/taltulon/Projects/blob/main/BSOD/BSOD-Images/Picture4.png)

By going over the function we see the blue screen creation after this line:

![whatever](https://github.com/taltulon/Projects/blob/main/BSOD/BSOD-Images/Picture5.png)

Now we do it again and set the breakpoint to nt!BgpFwDisplayBugCheckScreen and run over it. We find out the ```nt!BgpClearScreen``` function called with a single parameter on ECX (IDA is backing us up, didn’t add screenshot):

![whatever](https://github.com/taltulon/Projects/blob/main/BSOD/BSOD-Images/Picture6.png)

This function does the color change, and its parameter is the color code of the BSOD, the value of it is ```ff0077d6``` and if we put it in a hex color calculator, we can see that:

![whatever](https://github.com/taltulon/Projects/blob/main/BSOD/BSOD-Images/Picture7.png))

Sadly enough, when I try to change this value from the struct here:

![whatever](https://github.com/taltulon/Projects/blob/main/BSOD/BSOD-Images/Picture8.png))

the BSOD will just turn black (?) I could not overcome this situation. My windows version is 21h2.
What I decided to do was use windows 7 to maybe succeed there.
I opened ntoskrnl.exe in IDA and found out ```nt!BgpFwDisplayBugCheckScreen``` doesn't exist, but ```nt!KiDisplayBlueScreen``` does.
I checked out where the change happens there and found out this function, which had little documentation online:

![whatever](https://github.com/taltulon/Projects/blob/main/BSOD/BSOD-Images/Picture9.png)

Easily we can understand that what is sent here are the window dimensions and the color of it, coded by a number. For example, blue equals 4.
I changed the number a couple of times and got some nice results.

![whatever](https://github.com/taltulon/Projects/blob/main/BSOD/BSOD-Images/Picture10.png)

Thats it for now, I learned how to debug a kernel and now I feel confident with it. Although I don’t know what was wrong with my Windows 10 BSOD change I can say for sure I was very much on track (or not? Black Screen of Death is still BSOD ;)
