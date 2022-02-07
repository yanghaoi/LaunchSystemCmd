# LaunchSystemCmdExe
launch a cmd.exe process with system permissions.

### launch cmd.exe in Session 0 
WTSGetActiveConsoleSessionId() / ProcessIdToSessionId() / DuplicateTokenEx() / WTSEnumerateSessions() / CreateProcessAsUser()

### Injetc session>0(gui system process)
ZwCreateThreadEx() / CreateRemoteThread()

### Set Parent
CreateProcessA()

### GIF Show
![](https://cdn.jsdelivr.net/gh/yanghaoi/LaunchSystemCmd/LaunchSystemCmdExe/Images/run.gif)

# LaunchSystemCmdDll
System Process Dll Hijack Test :) , Command line:
  ```markdown
  rundll32 LaunchSystemCmdDll.dll,Run
  ```

