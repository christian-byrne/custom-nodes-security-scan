#!/bin/bash

./sandbox.sh &

sleep 10

echo "Firejail list:"
echo firejail --list

sudo firejail --join-network=comfyui-custom-nodes-sandbox tcpdump
