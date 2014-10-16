mkdir driver

sc stop protegeDados


sc delete protegeDados


copy ..\amd64\protegeDados.sys .\driver

copy ..\x64\Debug\protegeDados_exe.exe .\driver

copy ..\protegeDados.inf .\driver





"c:\Program Files (x86)\Windows Kits\8.0\bin\x64\Inf2Cat.exe"  /driver:.\driver /os:7_X64

signtool sign /v /s my /n "George Fleury" /t http://timestamp.verisign.com/scripts/timstamp.dll driver\protegeDados.sys

signtool sign /v /s my /n "George Fleury" /t http://timestamp.verisign.com/scripts/timstamp.dll driver\protegeDados.cat




copy .\driver\protegeDados.sys c:\windows\system32\drivers\protegeDados.sys