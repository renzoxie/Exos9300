### Info
This script is used for helping dormakaba Exos 9300 installation<br>
The script helps install prerequesties for Exos 9300 silently <br>
or it could be used for checking if there are any missing IIS features or programs Exos 9300 requires.

### Details
The following parts will be installed by the scirpt unattached：
1. .net framework 4.7.2
2. all IIS features which Exos requires
3. OTP/Erlang
4. RabbitMQ Server
5. SQL Server Express 2019
6. SQL Server Management Studio

### How to

1.  Run Powershell as administrator
2.  Set-ExecutionPolicy RemoteSigned, and input Y, then enter to allow windows be able to run powershell script file
3.  load this InstallationHelper.ps1 to root of your installation directory
4.  change directory to the root folder in powershell, for example： cd C:\User\Administrator\Desktop\Exos9300_4.2.2\
5.  input this line to powershell windows: ./InstallationHelper.ps1 -Version '4.2.2', then hit Enter

### Attention

the version number input must be the same as the version you are going to install<br>
For instance, your instalation folder is Exos9300_<strong>4.2.3</strong>，then the command you have to input is: ./InstallationHelper.ps1 -Version <strong>'4.2.3'</strong>
