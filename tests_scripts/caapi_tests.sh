#!/bin/bash

set -e

set -a 
source .env
set +a

go test ./caapi -v