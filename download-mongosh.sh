#!/bin/bash
# Download mongosh.deb if it doesn't exist
if [ ! -f mongosh.deb ]; then
    wget https://downloads.mongodb.com/compass/mongosh_2.2.5_amd64.deb -O mongosh.deb
fi
