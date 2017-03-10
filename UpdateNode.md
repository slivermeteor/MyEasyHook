###3-10-2017
The better method
Recently, I'm reviewing this project's remote hook.At that time, I find a better way to fixed the bug what I had fixed in the 'StealthStub_ASM_x64'.	
Last time, I didn't understand the calling convention and stack in the 64bit. Fortunately, I find a website to explain it.<a href="http://www.ntcore.com/Files/vista_x64.htm">x64 stack</a>.	
The old way I used is to save the old stack value to avoid the error.Now, I understand the reason that causes this bug.There is not much stack space to save parameters.	
This time, I only modify one line to fix it in the 'StealthStub_ASM_x64'.
The real stealth
The funtion 'RhCreateStealthRemoteThread' could inject the dll without any trail.The <a href="http://easyhook.github.io/tutorials/nativeremotehook.html">example</a> in the EasyHook is not the real stealth.	
Because, the EasyHookDll will be freed in the 'Injection_ASM_x64'.However, the real inject dll will not be free.	
In my InjectDll, I give a example that will free both EasyHookDll of RealInjectDll.	

###12-16-2016
At the before, I use 'EasyHook64.dll' to install a remote hook in a 64-bits target in the 64-bits System.I always think it's my code problem to cause the problem.
At some day before, I try to use the offical EasyHook64.dll to install.I find it failed same as my.So I commit the issuse to EasyHook.
Today, I have the fix the problem by myself.You can go to the issue the page to see the process.Meanwhile you can also discuss the problem with me.
<a href="https://github.com/EasyHook/EasyHook/issues/159">The issuse link</a>


###12-10-2016
I have complete the function 'RhCreateStealthRemoteThread' what is named 'RhCreateStealthRemoteThread' in the original easyhook.
But I find it can't work correctly when I use this function to install a remote hook.At the meantime, I use the Windbg to debug the function to 
find the possible bug.So I commit a new issuse in the https://github.com/EasyHook/EasyHook/issues. For more information about what I find, pleast
go to https://github.com/EasyHook/EasyHook/issues/159.