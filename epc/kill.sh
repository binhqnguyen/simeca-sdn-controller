#!/bin/bash

ps fax|grep "wharf -f" | grep "$1.xml"| awk '{}{print $0; system("kill -9 " $1);}'
ps fax|grep wpa_supplicant | awk '{}{print $0; system("kill -9 " $1);}'
