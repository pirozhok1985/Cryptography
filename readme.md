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

Для успешной сборки требуется пакет MSR.TSS версии 2.2.0
https://github.com/microsoft/TSS.MSR/tree/main/NuGet/2.2

-----------------------------------------------------------------------------------------------------------------------------------------

This is the key attestation PoC project with RSA only key pair support. Works on windows and linux platforms. Consists of two components:
1. KeyAttestation.Client - the client, which is used to generate certificate signing request with attestation statement attribute.
2. KeyAttestation.Server - the server, which processes client requests with attestation.

Communication between client and server is implemented using gRPC.

Launch hints:
1. Launch server using apropriate web configuration - hostname, port, ssl/tls, etc...
2. Launch client with required parameters.
   
Example:

 windows:
 
  KeyAttestation.Client.exe attest --tpmDevice windows --endpoint "https://localhost:8085
  
 linux:
 
  KeyAttestation.Client.exe attest --tpmDevice linux --endpoint "https://localhost:8085"

MSR.TSS nuget 2.2.0 is required. This package is not published in nuget repository(the old version only). Consider downloding it from MSR.TSS repository before building the project.
https://github.com/microsoft/TSS.MSR/tree/main/NuGet/2.2
