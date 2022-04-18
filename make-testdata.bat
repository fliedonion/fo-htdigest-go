@echo off

cd /d %~dp0

if exist htdigest.exe (

    setlocal enabledelayedexpansion
        set _u=abc
        set _p=efg
        set _r=rrr

        echo please enter !_p! for test data passowrd

        echo ^> .\htdigest.exe -c "!_r!_!_u!.digest" "!_r!" "!_u!"
        .\htdigest.exe -c "!_r!_!_u!.digest" "!_r!" "!_u!"
        @rem type "!_r!_!_u!.digest"
    endlocal

) else (

    echo "please put htdigest.exe to '%~dp0' "
)
