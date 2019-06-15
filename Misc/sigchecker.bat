REG ADD "HKCU\Software\Sysinternals\sigcheck" /v EulaAccepted /t REG_DWORD /d 1 /f
sigcheck64 -h -a -q -c -s -e %1