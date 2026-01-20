# MQTT no Defense (README breve, “falado”)

Este projeto é um **cliente** (Go e Python) que se conecta no **MQTT do Defense** para receber eventos em tempo real (alarmes, notificações, etc.).  
A ideia é simples: **antes de acessar o broker**, você precisa passar pelo **BRMS** para pegar as credenciais corretas.

## Como funciona:
1. Você informa **host/porta/usuário/senha** do Defense (BRMS).
2. O programa autentica no BRMS e recebe um **token** + duas chaves (**secretKey** e **secretVector**).
3. Com esse token, ele chama o endpoint **GetMqConfig**, que devolve:
   - o endereço do broker (`host:port`)
   - o **usuário MQTT**
   - a **senha MQTT criptografada** (em HEX)
   - se o broker usa **TLS** (`enableTls`)
4. O programa **descriptografa a senha MQTT** usando AES (com `secretKey` e `secretVector`).
5. Aí sim ele conecta no broker MQTT (`ssl://` se TLS, senão `tcp://`) e faz o **subscribe** no tópico (por padrão `mq/event/msg/topic/#`).
6. Quando chega mensagem, ele imprime o payload e (no Go) converte o JSON numa struct (`payloadDefense`) para você processar campos como `alarmType`, `deviceName`, `alarmDate`, etc.

## O que você ganha com isso
- Cliente que faz o **fluxo certo de credenciais** do Defense (**BRMS → GetMqConfig → MQTT**)
- Recebimento contínuo de eventos via **subscribe**
- Base pronta para automação/log/integração

---

# Como rodar (Go)

## Exemplo via flags

` go run main.go \
  --host 10.100.61.138 \
  --port 443 \
  --user system \
  --pass SUA_SENHA \
  --topic "mq/event/msg/topic/#" \
  --clientid "mqtt-client-01" `

# Como rodar (Python)

Arquivo sugerido: mqtt_defense.py (ou o nome que você salvou o script)

1) Instalar dependências
`pip install paho-mqtt requests cryptography`

2) Rodar via flags
`python mqtt_defense.py \
  --host 10.100.61.175 \
  --port 443 \
  --user system \
  --pass SUA_SENHA \
  --topic "mq/event/msg/topic/#" \
  --clientid "mqtt-client-01"`
