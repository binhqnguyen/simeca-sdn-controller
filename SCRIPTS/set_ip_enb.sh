#!/bin/bash

sudo ip route | grep "10." | awk '{system("sudo ip route del " $1)}'
