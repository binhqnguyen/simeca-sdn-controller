#!/bin/bash

hn=$(hostname) ;
sudo sed -i "s/.*127.0.0.1.*/127.0.0.1       localhost loghost $hn/" /etc/hosts
