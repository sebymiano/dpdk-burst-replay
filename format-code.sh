#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

set -x
find $DIR -name "*.c" -o -name "*.h" | xargs clang-format -i