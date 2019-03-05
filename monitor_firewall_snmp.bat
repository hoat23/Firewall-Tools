@echo off
echo Ejecutando .\monitor_firewall_snmp.py
python .\monitor_firewall_snmp.py -i 190.168.61.3 -pp 161 -m prueba -c "sys_info,bandwidth,cpu_mem,label-mac-alias-type-ip_mask-status" -ip_out 8.8.8.8 -pp_out 5959
python .\monitor_firewall_snmp.py -i 190.168.61.3 -pp 161 -m prueba -c "sys_info,cpu_mem" -ip_out 8.8.8.8 -pp_out 5959
python .\monitor_firewall_snmp.py -i 190.168.61.3 -pp 161 -m prueba -c "label-mac-alias-type-ip_mask-status" -ip_out 8.8.8.8 -pp_out 5959
python .\monitor_firewall_snmp.py -i 190.168.61.3 -pp 161 -m prueba -c "bandwidth" -ip_out 8.8.8.8 -pp_out 5959
python .\monitor_firewall_snmp.py -i 190.168.61.3 -pp 161 -m prueba -c "label" -ip_out 8.8.8.8 -pp_out 5959
echo Fin..
