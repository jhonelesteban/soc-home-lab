# soc-home-lab
Home lab de detección de amenazas con Wazuh, Kali y Ubuntu
# Caso 01: Detección de fuerza bruta SSH
## Objetivo
Simular un ataque de fuerza bruta contra un servicio SSH y verificar 
la capacidad de detección de Wazuh usando el ruleset por defecto (sshd).
## Entorno
- **Atacante:** Kali Linux — IP 192.168.20.129 — agente Wazuh instalado
- **Víctima:** Ubuntu Server (jhonelserver) — IP 192.168.20.132 — agente Wazuh instalado (agent.id 002)
- **Manager:** wazuh-server
## Ataque ejecutado
Comando usado desde Kali:
```bash
hydra -l usuario_invalido -P /tmp/pass_chicas.txt -t 4 ssh://192.168.20.132
```
Se probaron 8 passwords contra un usuario inexistente (`usuario_invalido`) 
para generar un patrón de intentos fallidos repetidos desde la misma IP 
en un periodo corto de tiempo.
## Flujo de detección
1. El daemon `sshd` en la Ubuntu registra cada intento fallido en el log 
   del sistema (visible vía `journald`), con líneas como:
   `Failed password for invalid user usuario_invalido from 192.168.20.129 port 43632 ssh2`
2. El agente Wazuh instalado en la Ubuntu lee ese log y lo envía al manager.
3. El **decoder `sshd`** parsea la línea y extrae los campos clave: 
   `data.srcip` (192.168.20.129), `data.srcuser` (usuario_invalido).
4. La **regla 5710** ("sshd: Attempt to login using a non-existent user", 
   nivel 5) se dispara por cada intento individual. En este caso, 
   se generaron 8 alertas de este tipo, correspondientes a los 8 intentos.
5. La **regla 5712** ("sshd: brute force trying to get access to the 
   system. Non existent user.", nivel 10) es una regla de correlación 
   configurada así (verificado en `0095-sshd_rules.xml`):
   - `if_matched_sid`: 5710 (depende de que la 5710 se dispare primero)
   - `frequency`: 8 (necesita 8 coincidencias)
   - `timeframe`: 120 (dentro de una ventana de 120 segundos)
   - `same_source_ip`: true (todas desde la misma IP)
   - `ignore`: 60 (luego de disparar, ignora nuevas coincidencias por 60s para evitar flood de alertas)
   Esta regla se disparó **una sola vez**, agrupando los 8 eventos 
   anteriores en una sola alerta de mayor severidad.
## Mapeo a MITRE ATT&CK
La alerta trae directamente el mapeo:
- **Técnica:** T1110 (Brute Force) / T1021.004 (Remote Services: SSH)
- **Táctica:** Credential Access, Lateral Movement
## Resultado
- 8 alertas nivel 5 (rule.id 5710) — una por cada intento fallido
- 1 alerta nivel 10 (rule.id 5712) — fuerza bruta confirmada por correlación
- Evidencia completa en `/capturas`
## Aprendizaje
Una alerta individual de "usuario inexistente" (nivel 5) no es crítica 
por sí sola — puede ser un simple error de tipeo. Pero Wazuh usa reglas 
de correlación (basadas en frecuencia, ventana de tiempo, y misma IP 
origen) para distinguir ruido de un patrón de ataque real. Esto reduce 
falsos positivos y es la lógica central detrás de cómo un SOC prioriza 
qué alertas investigar primero.
También aprendí a leer una regla en su definición XML directamente 
(`ruleset/rules/0095-sshd_rules.xml`), entendiendo qué significan 
parámetros como `frequency`, `timeframe`, `ignore` y `if_matched_sid` — 
no solo verla disparada en el dashboard.
