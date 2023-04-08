# :fire: Fast OpenSSH setup on Windows :fire:
OpenSSH is the open-source version of the Secure Shell (SSH), designed to provide a secure and straightforward approach to remote system administration.

# Prerequisites
To install OpenSSH on Windows check these minimum requirements by running PowerShell:
```
$PSVersionTable.PSVersion
```
Be sure to have at least the version ```5.1``` installed and 

```
(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
```
be sure to run the PowerShell as administrator.

# Install OpenSSH
OpenSSH is composed by a Client and a Server, usually you only need to install the Client for the client and the Server for the server. 
But first, check if you have already installed OpenSSH Client and/or Server:
```
Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH*'
```
If both are not installed continue the installation of:
* Client
```
Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
```
* Server
```
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
```
Usually, the Server contains all the services needed to create a secure connection (i.e., the ssh-keygen and ssh-agent).

Start the OpenSSH Server service:
```
Start-Service sshd
```

## Automatic startup and firewall rules
By running this lines the SSH Server will be started automatically at startup:
```
Set-Service -Name sshd -StartupType 'Automatic'
```
And be sure to add the following firewall rules:
```
if (!(Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue | Select-Object Name, Enabled)) {
    Write-Output "Firewall Rule 'OpenSSH-Server-In-TCP' does not exist, creating it..."
    New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
} else {
    Write-Output "Firewall rule 'OpenSSH-Server-In-TCP' has been created and exists."
}
```

## Key-based authentication
Enstabilish an SSH connection on Windows by typing the command ```ssh``` followed by the Username and the server's IP address:
```
ssh Username@IP
```
But this is considered insecure, especially if your server has a public IP and the Username account is a traditional ```user``` or ```root``` or ```admin``` coupled with a simple password. These will expose the server to be hacked by bots which scan the internet.

Instead, using a key-based authentication will raise the bar to exploit Windows Server, because without the right pair of private and public keys is not possible to access a Windows account via SSH.

For this reason OpenSSH provides a key generator, by default it creates a pair of public and private keys based on [Ed25519](https://en.wikipedia.org/wiki/EdDSA) algorithm by default (RSA, ECDSA, and so on must be specified):
```
ssh-keygen -t ed25519
```
During the generation of keys, will be prompted to use a passphrase or not. It is highly recommended to use a passphrase to generated the key pair.

With this command you created a pair of ```Ed25519``` keys: ```id_ed25519``` which is your **private key** and ```id_ed25519.pub``` which is your **public key**. Both will be saved in ```C:\Users\Username\.ssh``` for Standard user or in ```C:\ProgramData\ssh``` for Administrator User.

### Add the key to ssh-agent
Taking into consideration that your **private key** is stored in an User folder it must be stored securely. OpenSSH provides the so called ssh-agent which allows to use the private key related to your client without pointing to the private key path:
```
Get-Service ssh-agent | Set-Service -StartupType Automatic
Start-Service ssh-agent
Get-Service ssh-agent
ssh-add $env:USERPROFILE\.ssh\id_ed25519
```
Now, your private key can be moved to secure store instead of being left inside the User folder.

## Move the public key to the server
From PowerShell you can move the public key from the client to the server, the destination changes if the public key has to be applied to Standard or Administrator account:
* Standard user
```
$authorizedKey = Get-Content -Path $env:USERPROFILE\.ssh\id_ed25519.pub

$remotePowershell = "powershell New-Item -Force -ItemType Directory -Path $env:USERPROFILE\.ssh; Add-Content -Force -Path $env:USERPROFILE\.ssh\authorized_keys -Value '$authorizedKey'"
```

* Administrator user
```
$authorizedKey = Get-Content -Path $env:USERPROFILE\.ssh\id_ed25519.pub
$remotePowershell = "powershell Add-Content -Force -Path $env:ProgramData\ssh\administrators_authorized_keys -Value '$authorizedKey';icacls.exe ""$env:ProgramData\ssh\administrators_authorized_keys"" /inheritance:r /grant ""Administrators:F"" /grant ""SYSTEM:F"""
```
 
For both, run the ```ssh``` command by applying the previous ```$remotePowershell``` function, this will move the file via SSH to the server:
```
ssh Username@IP $remotePowershell
```

**Alternatively** use ```scp``` command to move the public key from the client to the server:
```
scp C:\Users\Username\.ssh\id_ed25519.pub Username@IP:C:\Users\Username\.ssh\authorized_keys
```
**Note**: Remember to change the source path of the public key, Username and server's IP address.

# Securing Remote Desktop with the SSH Tunnel
SSH tunnel provides a secure and encrypted connection between the client the server. In this case we want to secure RDP connection by using SSH, we redirect the ```8888``` port of our localhost to use the SSH Tunneling of the ```3389``` port (RDP port) of our server.
```
ssh -L 8888:IP:3389 Username@IP
```
or if the private key has not been set in ssh-agent just specify the source path for the private key:
```
ssh -L 8888:IP:3389 Username@IP -i "C:\Users\Username\.ssh\id_ed25519"
```

Now, open Microsoft Remote Desktop and use ```127.0.0.1:8888``` to connect to RDP, the password for access to the account will be prompted.

# Uninstall OpenSSH
To uninstall OpenSSH Client and/or Server just run these commands in PowerShell:
* Client
```
Remove-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
```
* Server
```
Remove-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
```
Remember to restart PC and/or Server and to delete the related SSH folders.

---

**Recommended read**
* [OpenSSH for Windows overview by Microsoft](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_overview)
* [Configuring SSH Public Key Authentication on Windows by Windows OS Hub](https://woshub.com/using-ssh-key-based-authentication-on-windows/)
* [Configure SSH Tunnel (Port Forwarding) on Windows by Windows OS Hub](https://woshub.com/ssh-tunnel-port-forward-windows/)
