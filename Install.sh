#!/bin/sh

echo "----------"
echo "Skip Trace Instalation"
echo "----------"

echo "Checking for python3"
python3 -V > /dev/null 2>&1

if [$? != 0]; then
    read -p "Install python3? [Y/n] " -n 1 pyInstall
    if ["$pyInstall" == "n" || "$pyInstall" == "N"]; then
        echo "Error: Please install python then try installing again"
        exit -1

    else
        echo "Installing python3"
        sudo apt-get install python3 > /dev/null 2>&1
        echo "Installing pip3"
        sudo apt-get install python3-pip > /dev/null 2>&1
        echo "updating pip"
        sudo pip3 install --upgrade pip
    fi

fi

read -p "Is this a client install? [Y/n] " -n 1 clientInstall

if ["$clientInstall" == "n" || "$clientInstall" == "N"]; then
    echo "Creating Server Instalation"
    echo "Moving server script to /root"
    sudo cp server/server.py /root/.

    echo "Setting up server locationLog service."
    sudo cp server/locationLog.service /lib/systemd/system/.
    sudo systemctl daemon-reload
    sudo systemctl enable locationLog.service
else
    echo "Creating Server Instalation"
    echo "Moving server script to /root"
    sudo cp server/server.py /root/.
    
    echo "Creating client locationLog service."
    sudo cp client/locationLog.service /lib/systemd/system/.
    sudo systemctl daemon-reload
    sudo systemctl enable locationLog.service
fi

echo "Installing python libraries"



echo "exiting"
exit 0
