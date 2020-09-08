#!/usr/bin/env bash
set -Ceuo pipefail

readonly TWITTER_ACCESS_KEY="twitter_access_key"
readonly TWITTER_ACCESS_SECRET="twitter_access_secret"
readonly TWITTER_CONSUMER_KEY="twitter_consumer_key"
readonly TWITTER_CONSUMER_SECRET="twitter_consumer_secret"

function encrypt() {
    local filename=$1
    local rawpath="static/raw/${filename}.txt"
    local encpath="static/${filename}"

    if [[ ! -f $(pwd)/$rawpath ]]; then
        echo "file: ${rawpath}.txt is not found"
    elif [[ -f $(pwd)/$encpath ]]; then
        echo "file: ${encpath} is already exists"
    else
        aws kms encrypt \
            --key-id "$KMS_KEY_ID" \
            --plaintext fileb://"$rawpath" \
            --output text \
            --query CiphertextBlob | base64 \
            --decode > "$encpath" && \
            echo "success encrypting: $filename"
    fi 

}

function require() {
    local command
    command=$1

    if ! type "$command" >/dev/null 2>&1; then
        echo "command: $command is not found"
        return 1
    fi
}

function main() {
    require "aws"
    require "base64"

    encrypt $TWITTER_ACCESS_KEY
    encrypt $TWITTER_ACCESS_SECRET
    encrypt $TWITTER_CONSUMER_KEY
    encrypt $TWITTER_CONSUMER_SECRET
}

main
