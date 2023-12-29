# README para Threat Intelligence Report Generator

Este repositorio contiene una herramienta para la generación automática de informe operacional de Threat Intelligence y reglas Sysmon, YARA, Suricata y Sigma.

## Requisitos previos

Antes de comenzar, asegúrate de tener Docker instalado en tu sistema. Puedes obtener Docker desde el sitio oficial: https://www.docker.com/get-started

## Construir la imagen Docker

Para construir la imagen Docker llamada "threatintel", ejecuta el siguiente comando en el directorio raíz del proyecto:

```bash
sudo docker build -t threatintel .
```
## Ejecutar la imagen Docker

Para ejecutar la imagen Docker llamada "threatintel", ejecuta el siguiente comando en el directorio raíz del proyecto:

```bash
sudo docker run -p 80:80 -p 8000:8000 threatintel
```

## Uso de la herramienta

Simplemente, acceder con el navegador a localhost:80
