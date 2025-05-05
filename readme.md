Проект является PoC технологии аттестации ключей. Реализована аттестация rsa ключевой пары. Проект запускается на windows и linux. Состоит из двух компонент:
1. KeyAttestation.Client - клиент, имитирующий работу агента автоенролмента сертификатов.
2. KeyAttestation.Server - сервер, имитирующий проверяющую сторону(УЦ/РЦ).

Взаимодействие между клиентом и сервером реализовано через протокол gRPC.

Порядок запуска:
1. Запускаем сервер, предварительно указав нужный порт и ssl в конфиге, при необходимости.
2. Запускаем клиент.
Пример запуска клиента под windows:
 KeyAttestation.Client.exe attest --tpmDevice windows --endpoint "https://localhost:8085"
   Пример запуска клиента под linux:
   KeyAttestation.Client.exe attest --tpmDevice linux --endpoint "https://localhost:8085"