#!/bin/bash
trap terminate SIGINT
terminate(){
    killall scope-reader
    killall scope-writer
    exit
}
#the rest of your code goes here
taskset -c $1 ./scope-reader &
taskset -c $1 ./scope-writer &
wait