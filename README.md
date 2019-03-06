# Firewall-Tools

## Programas Python:
La extracción de datos adicionales de los firewalls se clasifican según el protocolo utilizado:
#### Protocolo SNMP
+ monitor_firewall_snmp.py
  + Monitoreo del sistema e información adicional **“sys_info”**.
  + Monitoreo de ancho de banda **“bandwidth”**.
  + Monitoreo de cpu y memoria **“cpu_mem”**.
  + Monitoreo de interfaces **“label,mac,alias,type,ip_mask,status”**.
+ multiprocess_monitor_firewall_snmp.py
#### Protocol SSH
+ monitor_firewall_ssh.py
  + Monitoreo de estatus del sistema **“sys_status”**.
  + Monitoreo de estatus de hardware del shm **“sysinfo_shm”**.
  + Monitoreo del modo conservativo **“sysinfo_conserve”**.
  + Monitoreo de la memoria **“sysinfo_memory”**.
  + Monitoreo de los 25 procesos top **“check_process”**.
  + Descarga de backup **“down_config”**.
  + Test de conectividad a logstash **“test_logstash_conection”**.
+ multiprocess_monitor_firewall_ssh.py
#### Protocol HTTP
+ fortiOS_API.py: Aplicación que permite interactuar con el firewall a nivel de API, puedes configurar, cargar configuraciones, setear protocolos, etc.
  + Modificación adicional para descarga de backups **“/api/v2/monitor/system/config/backup?scope=global”**.
+ multiprocess_monitor_firewall_http.py
