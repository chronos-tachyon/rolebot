#!/bin/bash
set -eu

dir="$(dirname "$0")"
"$dir"/stop.sh
"$dir"/start.sh
