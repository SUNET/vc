#!/usr/bin/env bash

files=("diploma" "eduid" "ehic" "elm" "basic_auth_users" "microcredential" "pda1" "pid-1-5" "pid-1-8")

remote_dir="../vc-ops/global/overlay/etc/puppet/modules/vc/templates/bootstrapping"

for file in "${files[@]}"; do
    printf "\nSyncing %s.json...\n" "$file"
    remote="$remote_dir/$file.json"
    local="bootstrapping/$file.json"

    rsync -avz --progress "$local" "$remote"

    localS256=$(sha256sum "$local")
    if [[ -f "$remote" ]]; then
        remoteS256=$(sha256sum "$remote")
    else
        remoteS256="file not found"
    fi
    printf "\nRemote SHA256: %s\nLocal SHA256: %s\n" "$remoteS256" "$localS256"
done
