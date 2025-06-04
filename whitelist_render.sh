#!/bin/bash
source .env

declare -A RENDER_IPS=(
  ["US-East-1"]="54.144.0.0/16"
  ["US-East-2"]="3.128.0.0/16"
  ["US-West-2"]="44.224.0.0/16"
  ["EU-West-1"]="52.51.0.0/16"
  ["US-East-1-Virginia"]="3.208.0.0/12"
)

for region in "${!RENDER_IPS[@]}"; do
  echo "Whitelisting ${RENDER_IPS[$region]} ($region)"
  curl -s -X POST \
    --user "cxcxnriy:00e2abb0-e5e1-4b16-91f9-76a99f75f0b3" \
    --digest \
    --header "Accept: application/json" \
    --header "Content-Type: application/json" \
    "https://cloud.mongodb.com/api/atlas/v1.0/groups/682ee28c64b0ed66f576f90b/accessList" \
    --data "[{
      \"ipAddress\": \"${RENDER_IPS[$region]}\",
      \"comment\": \"Render $region\"
    }]"
  echo ""
done
