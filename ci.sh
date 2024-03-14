#!/bin/env bash

set -e


function test_dir() {
    if test -f Makefile; then
        echo -e "\033[33m=== start build $1  ===\033[0;39m"
        make clean && make
        echo -e "\033[32m=== finish build $1 ===\033[0;39m"
    fi
}

function test_multiple_dir() {
    local dir=$1

    for sub in $dir/*; do
        if test -d "$sub"; then
            ( cd "$sub" && test_multiple_dir "$sub" )
        elif test -f Makefile; then
            test_dir "$dir"
        fi
    done
}


function main() {
    for i in $(ls -d chapter*); do
        test_multiple_dir "$i"
    done
}

main
