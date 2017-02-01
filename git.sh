#!/bin/bash

domain=$(hostname | awk -F'.' '{print $2"."$3"."$4"."$5}')

for i in client1 epc penb1 enb2 enb3 access1 access2 access3 tor hsw1 server1
do
        ssh -YA -t -t $i.$domain "cd /usr/local/src; sudo -E git clone git@gitlab.flux.utah.edu:binh/simeca-minimum.git simeca"
done

