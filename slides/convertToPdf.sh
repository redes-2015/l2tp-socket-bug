#!/bin/bash
# Script que converte os slides para pdf

set -e

if (( $# < 1 )); then exit 1; fi
libreoffice --headless --convert-to pdf $1
