@echo off
python .\fortiOS_API.py -i 8.8.8.8 -pp 9443 -u my.user -p password1234 -ip_out 9.9.9.9 -pp_out 5959 -c /api/v2/monitor/router/ipv4/select/
python .\fortiOS_API.py -i 8.8.8.8 -pp 9443 -u my.user -p password1234 -ip_out 9.9.9.9 -pp_out 5959 -c /api/v2/monitor/system/config/backup?scope=global
