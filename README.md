## MyEasyHook
I just write this project to learn the famous Win32 Hook "EasyHook".
I just copy EasyHoo to make me understand the EasyHook more better.
If you want to know more about EasyHook, pleast to visit it's home.
<a href="http://easyhook.github.io/" >EasyHook</a>

##Update note
###12-10-2016
I have complete the function 'RhCreateStealthRemoteThread' what is named 'RhCreateStealthRemoteThread' in the original easyhook.
But I find it can't work correctly when I use this function to install a remote hook.At the meantime, I use the Windbg to debug the function to 
find the possible bug.So I commit a new issuse in the https://github.com/EasyHook/EasyHook/issues. For more information about what I find, pleast
go to https://github.com/EasyHook/EasyHook/issues/159.