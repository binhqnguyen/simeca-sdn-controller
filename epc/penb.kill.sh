#!/bin/bash

ps fax | grep "lte"| awk '{}{print $0; system("kill -9 " $1);}'
