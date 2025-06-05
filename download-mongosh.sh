#!/bin/bash

# Download the Linux tarball
MONGOSH_VERSION="2.2.5"
MONGOSH_URL="https://downloads.mongodb.com/compass/mongosh-${MONGOSH_VERSION}-linux-x64.tgz"

echo "Downloading MongoDB shell..."
curl -L $MONGOSH_URL -o mongosh.tgz

# Extract the tarball
echo "Extracting MongoDB shell..."
tar -xvzf mongosh.tgz

# Add mongosh to PATH
export PATH=$PATH:$(pwd)/mongosh-${MONGOSH_VERSION}-linux-x64/bin

echo "MongoDB shell installed at $(pwd)/mongosh-${MONGOSH_VERSION}-linux-x64/bin/mongosh"
