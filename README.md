# API de Manejo de Secretos y Manejo de Mensajes

API REST Spring Boot con separación hexagonal y dos casos de uso: **Manejo de Secretos** para sembrar, cifrar, descifrar y rotar credenciales o tokens; y **Manejo de Mensajes** para cifrar, almacenar y recuperar mensajes. El dominio y los casos de uso no dependen de Spring ni del proveedor criptográfico.

## Requisitos

- Java 21
- Maven 3.8+

## Seguridad y configuración

La API emite JWT para autorizar el acceso a los casos de uso. Solicita el token con `POST /api/v1/auth/token`, enviando las credenciales de cliente configuradas:

```json
{
  "username": "cliente-api",
  "password": "contraseña-configurada"
}
```

La respuesta contiene `accessToken`, `tokenType: "Bearer"` y el tiempo de expiración. Usa el token en los demás endpoints mediante `Authorization: Bearer <accessToken>`. El token dura 900 segundos (15 minutos) de forma predeterminada. No se entrega token de actualización; cuando expira, se solicita uno nuevo con las credenciales de cliente.

El JWT está firmado con HS256. Configura `CREDENTIALS_JWT_SECRET_BASE64` con una clave aleatoria de al menos 32 bytes codificada en Base64; la aplicación falla al iniciar si falta o no tiene longitud suficiente. Opcionalmente, configura `CREDENTIALS_JWT_EXPIRATION_SECONDS` y `CREDENTIALS_JWT_ISSUER`. No uses la clave de pruebas en producción y rota la clave de firma de manera controlada, considerando que invalidará los tokens vigentes.

Usa TLS para el endpoint de emisión y para todas las solicitudes. No registrar contraseñas, JWT, tokens de servicio ni respuestas de descifrado. Entrega las claves mediante un gestor de secretos o plataforma de gestión de claves; no guardarlas en el repositorio ni enviarlas en solicitudes de negocio.

La configuración actual consume las claves inyectadas por variables de entorno; no implementa integración directa con un KMS o HSM. La gestión, rotación y respaldo de claves deben resolverse fuera de la aplicación.

Variables de entorno:

| Variable | Uso |
|---|---|
| `CREDENTIALS_API_USERNAME` / `CREDENTIALS_API_PASSWORD` | Credenciales del cliente API |
| `CREDENTIALS_JWT_SECRET_BASE64` | Clave aleatoria de firma JWT HS256 (mínimo 32 bytes antes de codificar) |
| `CREDENTIALS_JWT_EXPIRATION_SECONDS` | Duración del JWT en segundos (predeterminado: 900) |
| `CREDENTIALS_JWT_ISSUER` | Emisor declarado y validado en los JWT |
| `CREDENTIALS_AES_KEY_BASE64` | Clave AES de 256 bits, codificada en Base64 |
| `CREDENTIALS_MLKEM_PUBLIC_KEY_BASE64` | Clave pública ML-KEM-768 en DER X.509, codificada en Base64 |
| `CREDENTIALS_MLKEM_PRIVATE_KEY_BASE64` | Clave privada ML-KEM-768 en DER PKCS#8, codificada en Base64 |

Configurar solo las claves de los algoritmos que se vayan a utilizar. El endpoint de cifrado genera un nonce nuevo en cada operación. La opción híbrida encapsula una clave con ML-KEM-768 y deriva una clave AES-256 con HKDF-SHA-256; ambas opciones usan AES-GCM para confidencialidad e integridad.

## Caso de uso: Manejo de Secretos

`POST /api/v1/secrets/seed` recibe el tipo de identidad y el secreto inicial. Para credenciales:

```json
{
  "identityType": "CONNECTION_CREDENTIALS",
  "username": "app-user",
  "password": "secret",
  "algorithm": "AES_256_GCM"
}
```

Para un token, usa `identityType: "SERVICE_TOKEN"`, proporciona `token` y `algorithm`, y omite `username` y `password`. El sembrado admite `AES_256_GCM` o `ML_KEM_768_AES_256_GCM`; devuelve `operation: "SEEDED"`, el serial generado, el estado y el sobre cifrado.

`POST /api/v1/secrets/rotate` recibe solo el serial:

```json
{
  "serial": "serial-devuelto-al-sembrar"
}
```

La API identifica el tipo de secreto por el serial. La rotación cifra el nuevo valor obligatoriamente con `ML_KEM_768_AES_256_GCM`, genera un serial nuevo y elimina el anterior transaccionalmente. Un serial desconocido responde `404`.

Para credenciales, la API conserva el usuario, genera una contraseña aleatoria fuerte y devuelve la contraseña nueva una sola vez en la respuesta `operation: "ROTATED"`. Esta aplicación no cambia por sí misma la contraseña en el servidor de base de datos: el consumidor debe aplicar el valor devuelto al sistema destino y protegerlo como secreto.

Para tokens, la rotación debe solicitar un token nuevo al emisor. El puerto `ServiceTokenIssuerPort` define esa integración, pero el proveedor y protocolo aún no se especificaron; hasta configurar su adaptador, una solicitud de rotación de token falla con `503` y conserva el token anterior. No se genera un token falso ni se reutiliza el anterior como si fuera nuevo.

Los endpoints existentes `POST /api/v1/connections` y `POST /api/v1/connections/service-tokens` siguen disponibles para siembra especializada; sus rutas de descifrado permanecen disponibles para consultar registros por serial. Las rutas especializadas `/api/v1/connections/{serial}/rotate` y `/api/v1/connections/service-tokens/{serial}/rotate` también aceptan solo el serial en la ruta y usan el mismo flujo postcuántico.

La base se crea como `./credentials.db` en el directorio de ejecución. Para cambiar su ubicación, configura `CREDENTIALS_DB_PATH`. Protege el archivo y sus copias de seguridad: aunque contiene ciphertext, el descifrado requiere conservar las claves correctas fuera de la base de datos.

## Caso de uso: Manejo de Mensajes

`POST /api/v1/messages` acepta un mensaje y el algoritmo, lo cifra y almacena en SQLite solo el serial, el estado, el sobre cifrado (ciphertext, nonce y, para el modo híbrido, clave encapsulada y sal), la versión del formato y la fecha. El texto original no se persiste.

```json
{
  "message": "Mensaje confidencial",
  "algorithm": "ML_KEM_768_AES_256_GCM"
}
```

La respuesta `201` contiene el serial y los datos del sobre cifrado para permitir su transporte. Para recuperar el texto original, utiliza `POST /api/v1/messages/{serial}/decrypt`; esta respuesta sí contiene el mensaje en claro, por lo que debe tratarse como sensible. Los sobres de mensaje tienen separación criptográfica de dominio y no se descifran como credenciales o tokens.

## Cifrado directo (sin persistencia)

`POST /api/v1/connections/encrypt`

```json
{
  "username": "app-user",
  "password": "secret",
  "algorithm": "ML_KEM_768_AES_256_GCM"
}
```

Algoritmos admitidos: `AES_256_GCM` y `ML_KEM_768_AES_256_GCM`. La respuesta contiene el sobre cifrado y una evaluación cualitativa del algoritmo seleccionado. Para AES directo, `encapsulatedKey` y `kdfSalt` son `null`.

`POST /api/v1/connections/decrypt` recibe los campos del sobre devuelto por el endpoint de cifrado y responde con usuario y contraseña. La respuesta de descifrado contiene información sensible; proteger el acceso y evitar registrar cuerpos de solicitud/respuesta.

La evaluación no es una garantía de seguridad integral: AES-256-GCM se considera fuerte, pero no resistente a ataques cuánticos; ML-KEM-768 corresponde a la categoría NIST 3. El resultado depende también de la gestión de claves, el entorno y la implementación.

## Ejecución y pruebas

```bash
mvn test
mvn spring-boot:run
```
