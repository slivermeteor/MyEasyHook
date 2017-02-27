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