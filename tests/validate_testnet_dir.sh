#!/bin/bash

# Tool to validate a testnet_dir  

run_testnet_dir_test () {
   dir=$1
   docker_image=$2

   echo "testing $dir with $docker_image"
   docker pull $docker_image
   
   timeout --preserve-status 5 docker run --rm \
    -v $PWD/$dir:/data \
    $docker_image lighthouse --testnet-dir="/data" beacon_node 

    # Check the exit status of the command
    if [ $? -eq 0 ]; then
      # The command ran for more 10 seconds, assume lighthouse could decode state and consider it a success
      echo "OK: $dir"
    else
      # The command exited before the timeout, consider it a failure
      echo "ERROR: $dir"
      exit 1
    fi
}

run_testnet_dir_test tests/testnet_dir_mainnet sigp/lighthouse:v4.1.0
run_testnet_dir_test tests/testnet_dir_gnosis sigp/lighthouse:v4.1.0
run_testnet_dir_test tests/testnet_dir_minimal sigp/lighthouse:latest-amd64-unstable-dev

