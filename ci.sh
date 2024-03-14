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

    for sub in $(ls ./); do
        local subpath="$dir/$sub"
        if test -d "$sub"; then
            ( cd "$sub" && test_multiple_dir "$subpath" )
        elif test -f $sub; then
            if [[ "$sub" == *Makefile ]]; then
                test_dir "$dir"
            fi
        fi
    done
}


function main() {
    local dir="${1:-chapter*}"
    echo $dir
    for i in $(find $dir -maxdepth 0 -type d);  do
        ( cd $i && test_multiple_dir "$i")
    done
}

main "$@"
