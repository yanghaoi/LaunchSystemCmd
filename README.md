# LaunchSystemCmd
launch a cmd.exe process with system permissions.

## launch cmd.exe in Session 0 
DuplicateTokenEx() / CreateProcessAsUser()

## Injetc session 7(gui system process)
ZwCreateThreadEx() / CreateRemoteThread()

## Set Parent
CreateProcessA()

## GIF Show
![](https://cdn.jsdelivr.net/gh/yanghaoi/LanchSystemCmd@latest/LaunchSystemCmd/Images/run.gif)

# LaunchSystemCmdDll
System Process Dll Hijack Test :).
Command line: rundll32 LaunchSystemCmdDll.dll,Run
