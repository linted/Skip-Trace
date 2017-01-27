#!/bin/sh

echo "----------"
echo "Skip Trace Instalation"
echo "----------"

echo "Is this a client install? [Y/n] "

echo "Creating locationLog service."
sudo cp client/locationLog.service /lib/systemd/system/.
sudo systemctl deamon-reload
sudo systemctl enable locationLog.service

echo "exiting"
exit 0