FROM mcr.microsoft.com/windows/servercore:ltsc2016

RUN powershell [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; \
 Invoke-WebRequest https://www.python.org/ftp/python/3.7.4/python-3.7.4-amd64.exe -OutFile python-374.exe
RUN python-374.exe /quiet InstallAllUsers=1 PrependPath=1 Include_test=0 TargetDir=C:\Python
RUN pip install -U oletools
RUN mkdir C:\olescan
RUN powershell [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; \
 Invoke-WebRequest https://github.com/Rices/olescan/raw/master/oletriage/bin/Debug/Debug.zip -OutFile C:\olescan\olescan.zip; \
 Expand-Archive -LiteralPath "C:\olescan\olescan.zip" -DestinationPath "C:\olescan" -Force
RUN powershell $oldpath = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).path; \
 $newpath = $oldpath + ';c:\olescan'; \
 Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH -Value $newPath