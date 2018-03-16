# PowerShell Security Notes

### 1. Windows PowerShell Architecture
![enter image description here](https://i-msdn.sec.s-msft.com/dynimg/IC13468.gif)
For example, Windows operating system includes also a graphical hosting application PowerShell_ISE.exe (Windows PowerShell Integrated Scripting Environment) that allows you to read, write, run, debug, and test scripts and modules in a graphic-assisted environment.
### 1.2 Runspaces
A runspace defines the context in which a PowerShell commands or scripts execute and contains state that is specific to the corresponding PowerShell session. This context represents the operating environment of the runspace, including such resources as startup scripts as well as commands, language elements, functions, and providers supported by the hosting application.
It is possible to create **constrained runspaces** by restricting scope of resources, such as providers, commands, language elements, or functions available from the within the corresponding Windows PowerShell session.
### 1.3 PowerShell commands
There are many varieties of commands, including cmdlets, functions, filters, scripts, applications, configurations, and workflows.
### 1.4 PowerShell modules
A module is a collection of related Windows PowerShell code, including scripts, scripting resources, and assemblies grouped together and residing typically in the same file system location.
**cmdlet**
>**Import-Module**
### 1.5 Windows PowerShell providers
Windows PowerShell relies on providers to facilitate access to different types of data and configuration stores.
Some of the more commonly used providers available in Windows PowerShell enable access to file system, registry, and environment variables.
For example, the Registry provider allows you to access hives and keys in a registry, and the HKLM and HKCU drives specify the corresponding hives within the registry.
![enter image description here](https://i-msdn.sec.s-msft.com/dynimg/IC54683.gif)

### 1.5 Windows PowerShell Workflow
A Windows PowerShell Workflow is a Windows PowerShell script that leverages Windows Workflow Foundation. Windows Workflow Foundation is a framework for development and management of complex processing tasks that provides such capabilities as asynchronous execution, parallelism, and checkpoint support.
Windows PowerShell Workflow dynamically converts Windows PowerShell cmdlets to workflow activities. Each activity constitutes an independent unit of execution.
### 1.6 PowerShell.exe syntax
PowerShell\[.exe\]
```
[-Command { - | <script-block> [-args <arg-array>]

| <string> [<CommandParameters>] } ]

[-EncodedCommand <Base64EncodedCommand>]

[-ExecutionPolicy <ExecutionPolicy>]

[-File <FilePath> [<Args>]]

[-InputFormat {Text | XML}] 

[-Mta]

[-NoExit]

[-NoLogo]

[-NonInteractive] 

[-NoProfile] 

[-OutputFormat {Text | XML}] 

[-PSConsoleFile <FilePath> | -Version <PowerShell version>]

[-Sta]

[-WindowStyle <style>]
```
### 1.6 PowerShell.exe syntax
- Command_ (or simply c)
The value of the parameter can be "-", a string, or a script block. If the value is "-", the command text is read from standard input.
You can use the call operator **(&)** to execute a command within the script block
	>**powershell.exe –c “& {Get-EventLog –LogName Security –Newest 10}”**

	**Invoke-Expression** cmdlet (frequently referenced via its **iex** alias)
	> **powershell.exe –c iex “’Get-EventLog –LogName Security –Newest 10’”**
- _EncodedCommand_ (or simply enc) - accepts a base-64-encoded string version of a command. This allows you to submit commands to PowerShell that require more complex combinations of quotation marks or curly braces. This parameter is also frequently used in obfuscation scenarios, in which an attacker wants to prevent detection of an actual Windows PowerShell script or command being executed.
- _File_ \- runs the specified script in the local scope, so that the functions and variables that the script creates are available in the current session.
- _NoExit_ \- does not exit after running commands specified by using the Command parameter.
- _NonInteractive_ (or simply noni) – runs Windows PowerShell session without an interactive shell.
- _NoProfile_ (or simply nop) - does not load the PowerShell profile. PowerShell profiles allow you to customize your Windows PowerShell sessions.
- _Version_ (or simply v) – allows starting Windows PowerShell 2.0, assuming that this version is present on the local computer. Specifying any version number higher than 2 will load the latest version of Windows PowerShell present on the local computer, regardless of the number specified.
- _WindowsStyle_ (or simply w) – sets the window style for the session. When set to Hidden, it allows running a Windows PowerShell session without displaying the console window (the window does actually appear for a brief moment when the session starts).
### 1.7 Windows PowerShell Execution Policy
he most basic protection mechanism against such exploit is a set of execution policies that is part of the Windows PowerShell runtime. The purpose of execution policies is to block unintended execution of Windows PowerShell scripts, rather than serve as the primary method of preventing intentional script-based exploits. The execution policy might provide some protection against less-sophisticated social engineering-based attacks, where unsuspecting users are deceived into launching a harmful Windows PowerShell script.

Windows PowerShell supports the following execution policy:
- Restricted. No scripts are allowed to run. The blocked scripts include formatting and configuration files (.ps1xml), module script files (.psm1), and Windows PowerShell profiles (.ps1). It is the default execution policy in Windows client operating systems and had been the default in Windows server operating systems until the release of Windows Server 2012.
- AllSigned. Only scripts that have been digitally signed by a trusted publisher are allowed to run. If a script has been signed by an untrusted publisher, you will be prompted to provide a confirmation before that script executes.
- RemoteSigned. You can run:
any local scripts
remote scripts that have been digitally signed by a trusted publisher

	The mechanism that detects whether a script is local or remote leverages alternate data streams (ADS), built into the file system (NTFS). ADS appends the ZoneIdentifer tag into the data ($DATA) attribute of files downloaded from the Internet. The value of the tag designates the zone from which the file originated. Scripts with the values of the ZoneIdentfier tag designating the Internet or restricted sites are considered to be remote by the RemoteSigned policy. To remove the tag, you can use the **Unblock-File** Windows PowerShell cmdlet.
- Unrestricted. You can run any local or remote script. However, when launching remote scripts that have not been signed by a trusted publisher, you will be prompted to provide a confirmation before that script executes.
- Bypass. You can run all scripts without any restrictions or prompts. The Bypass policy can be applied within an individual Windows PowerShell session, effectively eliminating impact of any computer or user-based policy.
- Undefined. This indicates that there is no execution policy set in the current scope. As the result, the effective policy depends on the operating system defaults (Restricted in Windows 10 and RemoteSigned in Windows Server 2016).
### 1.8 Execution Policy Scopes




