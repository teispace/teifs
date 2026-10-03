# Command line

Every `teifs` command and its arguments. `teifs <command> --help` says the same on a
terminal. This page is generated from the command line's definition (`UPDATE_DOCS=1
cargo test -p teifs --bin teifs reference`); a test fails when it falls behind.

Global options (`--json`, `--quiet`, `--yes`, `--color`) work with every command; they're
listed once, under `teifs`.

<!-- generated: commands -->

## teifs

Your folders as a drive and as S3.

```
teifs [OPTIONS] <COMMAND>
```

| Argument | |
|---|---|
| `--json` | Print results as JSON Lines (one object per line, each with a `type`). |
| `-q, --quiet` | Print only results, warnings and errors. |
| `-y, --yes` | Answer yes to questions (like confirming a deletion). |
| `--color <COLOR>` | When to use colors. One of `auto`, `always`, `never`. Default: `auto`. |

## teifs init

Set up a drive: its folder, keys, keyring and settings, and an alias to reach it. Asks on a terminal; flags answer instead.

```
teifs init [OPTIONS] [DIR]
```

| Argument | |
|---|---|
| `<DIR>` | The drive's folder (created if missing). Default: the current folder. |
| `--listen <LISTEN>` | The address `teifs serve` listens on. Default: 127.0.0.1:9000. |
| `--default-layout <DEFAULT_LAYOUT>` | How new buckets store objects: `object` (any key S3 allows, encrypted at rest, as on AWS) or `folder` (plain files you can open anywhere). Default: object. One of `object`, `folder`. |
| `--kms-keyring <KMS_KEYRING>` | The KMS keyring. Default: `<config dir>/teifs/keys/<drive id>.json`, off the drive. |
| `--alias <ALIAS>` | The alias to add for the drive (`teifs ls NAME`). Default: local. |
| `--no-alias` | Don't add an alias. |
| `--force` | Replace the drive's settings file and the alias if they exist. |

## teifs serve

Serve a drive over the S3 API. Every folder in it is a bucket.

```
teifs serve [OPTIONS] [DIR]
```

| Argument | |
|---|---|
| `--config <CONFIG>` | A TOML file of settings, under the flags' names (`listen = "0.0.0.0:9000"`). Environment: `TEIFS_CONFIG`. |
| `<DIR>` | The drive's folder (created if missing). Default: `.`. Environment: `TEIFS_DIR`. |
| `--listen <LISTEN>` | Address to listen on. Default: `127.0.0.1:9000`. Environment: `TEIFS_LISTEN`. |
| `--certs-dir <CERTS_DIR>` | Serve HTTPS with the certificates in this folder: `public.crt` and `private.key` (or `tls.crt` and `tls.key`), and a subfolder with the same files for each further certificate, chosen by the name clients ask for. They're reloaded when they change, and on SIGHUP. Environment: `TEIFS_CERTS_DIR`. |
| `--tls-cert <TLS_CERT>` | Serve HTTPS with this certificate (PEM, its chain after it), reloaded when it changes; needs `--tls-key`. Environment: `TEIFS_TLS_CERT`. |
| `--tls-key <TLS_KEY>` | The private key (PEM) of `--tls-cert`. Environment: `TEIFS_TLS_KEY`. |
| `--trusted-proxy <CIDR>` | Trust the reverse proxy at this address or network (`10.0.0.5`, `10.0.0.0/8`; repeatable) to say who its clients are, in `--proxy-header`, and whether they came over HTTPS, in `X-Forwarded-Proto`. Nobody else can. Environment: `TEIFS_TRUSTED_PROXIES`. |
| `--proxy-header <PROXY_HEADER>` | The header trusted proxies name clients in: `x-forwarded-for` (nginx, HAProxy, Traefik, Caddy, Envoy, AWS load balancers), `forwarded` (RFC 7239) or `x-real-ip`. Choose one the proxy adds to or sets, never one it passes on. Default: `x-forwarded-for`. Environment: `TEIFS_PROXY_HEADER`. |
| `--domain <DOMAINS>` | A domain for virtual-hosted-style requests (bucket.domain); repeatable. Environment: `TEIFS_DOMAINS`. |
| `--website-domain <WEBSITE_DOMAINS>` | A domain for buckets' static websites (`bucket.domain`), as S3's website endpoint; repeatable. Buckets with a website configuration answer there. Environment: `TEIFS_WEBSITE_DOMAINS`. |
| `--access-key <ACCESS_KEY>` | The access key (else one is generated and kept in the drive). Environment: `TEIFS_ACCESS_KEY`. |
| `--default-layout <DEFAULT_LAYOUT>` | How buckets created over S3 store objects, unless the request says: `object` (any key S3 allows, encrypted at rest by default, as on AWS) or `folder` (plain files you can open anywhere). One of `object`, `folder`. Default: `object`. Environment: `TEIFS_DEFAULT_LAYOUT`. |
| `--kms-keyring <KMS_KEYRING>` | The KMS keyring (default: `<config dir>/teifs/keys/<drive id>.json`). Keep it off the drive and back it up: encrypted objects can't be read without it. Environment: `TEIFS_KMS_KEYRING`. |
| `--kms-transit <KMS_TRANSIT>` | Use a Vault or OpenBao transit engine as the KMS (e.g. `https://vault:8200`); its token comes from `VAULT_TOKEN` or `BAO_TOKEN`. Environment: `TEIFS_KMS_TRANSIT`. |
| `--kms-transit-mount <KMS_TRANSIT_MOUNT>` | Where the transit engine is mounted. Default: `transit`. Environment: `TEIFS_KMS_TRANSIT_MOUNT`. |
| `--kms-transit-namespace <KMS_TRANSIT_NAMESPACE>` | The transit engine's namespace (Vault Enterprise, OpenBao). Environment: `TEIFS_KMS_TRANSIT_NAMESPACE`. |
| `--kms-kes <KMS_KES>` | Use KES as the KMS: one or more servers, comma-separated (e.g. `https://kes:7373`). TeiFS signs in with the API key in `TEIFS_KMS_KES_API_KEY`, or with --kms-kes-cert and --kms-kes-key. Environment: `TEIFS_KMS_KES`. |
| `--kms-kes-cert <KMS_KES_CERT>` | A client certificate (PEM) to sign in to KES with, instead of an API key. Environment: `TEIFS_KMS_KES_CERT`. |
| `--kms-kes-key <KMS_KES_KEY>` | The client certificate's private key (PEM). Environment: `TEIFS_KMS_KES_KEY`. |
| `--kms-kes-ca <KMS_KES_CA>` | The certificate authorities KES's certificate is checked against (PEM; default: the system's). Environment: `TEIFS_KMS_KES_CA`. |
| `--kms-aws` | Use AWS KMS: credentials come from AWS's usual places (environment, shared config and SSO, instance and container roles). Environment: `TEIFS_KMS_AWS`. |
| `--kms-aws-region <KMS_AWS_REGION>` | AWS KMS's region (default: AWS's configuration's). Environment: `TEIFS_KMS_AWS_REGION`. |
| `--kms-aws-endpoint <KMS_AWS_ENDPOINT>` | Another AWS KMS endpoint, such as a VPC endpoint or a local emulator. Environment: `TEIFS_KMS_AWS_ENDPOINT`. |
| `--kms-default-key <KMS_DEFAULT_KEY>` | The key to use where TeiFS would use `teifs-default`: SSE-S3, SSE-KMS without a key, and the drive's own secrets. Keys sealed before keep opening. Environment: `TEIFS_KMS_DEFAULT_KEY`. |
| `--ldap-server <ADDRESS>` | Sign users in with this LDAP server (`host` or `host:port`; port 636 when none), as MinIO's `AssumeRoleWithLDAPIdentity`. Its lookup account's password comes from `TEIFS_LDAP_LOOKUP_BIND_PASSWORD`. Environment: `TEIFS_LDAP_SERVER`. |
| `--ldap-srv-record <LDAP_SRV_RECORD>` | Find the servers in DNS SRV records instead: `on` (the address is the record's whole name), `ldap` or `ldaps` (the address is a domain). One of `on`, `ldap`, `ldaps`. Environment: `TEIFS_LDAP_SRV_RECORD`. |
| `--ldap-starttls` | Reach it with plain LDAP upgraded by `StartTLS`, not LDAP over TLS. Environment: `TEIFS_LDAP_STARTTLS`. |
| `--ldap-insecure` | Reach it with plain, unencrypted LDAP: passwords cross the network as they are. Environment: `TEIFS_LDAP_INSECURE`. |
| `--ldap-ca <FILE>` | The certificate authorities (PEM) its certificate is checked against (default: the system's). Environment: `TEIFS_LDAP_CA`. |
| `--ldap-tls-skip-verify` | Accept any certificate from it: for a test directory only. Environment: `TEIFS_LDAP_TLS_SKIP_VERIFY`. |
| `--ldap-lookup-bind-dn <DN>` | The DN of the account users are looked up with. Environment: `TEIFS_LDAP_LOOKUP_BIND_DN`. |
| `--ldap-user-base-dn <DN>` | Where users are searched for (repeatable, or separated by `;`). Environment: `TEIFS_LDAP_USER_BASE_DN`. |
| `--ldap-user-filter <FILTER>` | The filter that finds a user: `%s` is the name it signs in with, like `(uid=%s)`. Environment: `TEIFS_LDAP_USER_FILTER`. |
| `--ldap-user-attributes <NAMES>` | The user's attributes its sessions carry, comma-separated. Environment: `TEIFS_LDAP_USER_ATTRIBUTES`. |
| `--ldap-group-base-dn <DN>` | Where groups are searched for (repeatable, or separated by `;`). Environment: `TEIFS_LDAP_GROUP_BASE_DN`. |
| `--ldap-group-filter <FILTER>` | The filter that finds a user's groups: `%d` is its DN and `%s` the name it signs in with, like `(&(objectclass=groupOfNames)(member=%d))`. Environment: `TEIFS_LDAP_GROUP_FILTER`. |
| `--identity-plugin-url <URL>` | Check custom tokens with this identity plugin (an `http(s)` URL), as MinIO's `AssumeRoleWithCustomToken`: it's sent each token and answers whom it's for. The `Authorization` header it's sent comes from `TEIFS_IDENTITY_PLUGIN_AUTH_TOKEN`. Environment: `TEIFS_IDENTITY_PLUGIN_URL`. |
| `--identity-plugin-role-policy <NAMES>` | The managed policies its users' sessions get (repeatable, or comma-separated). Environment: `TEIFS_IDENTITY_PLUGIN_ROLE_POLICY`. |
| `--identity-plugin-role-id <ID>` | The id in the role ARN clients name, `arn:minio:iam:::role/idmp-<ID>` (default: derived from the URL, as MinIO derives it). Environment: `TEIFS_IDENTITY_PLUGIN_ROLE_ID`. |
| `--identity-plugin-ca <PATH>` | Certificate authorities (PEM: a file, or a folder of them) its certificate may be issued by, besides the system's. Environment: `TEIFS_IDENTITY_PLUGIN_CA`. |
| `--openid-config-url <URL>` | Make an OpenID Connect provider, or keep it in line with these settings, when the server starts: its discovery URL (`https://…/.well-known/openid-configuration`) or its issuer, as MinIO's `config_url`. Environment: `TEIFS_OPENID_CONFIG_URL`. |
| `--openid-client-id <ID>` | The client its tokens are for (their `aud` or `azp`). Environment: `TEIFS_OPENID_CLIENT_ID`. |
| `--openid-role-policy <NAMES>` | Give every token for the client these managed policies when it names the client's role (`arn:minio:iam:::role/…`), as MinIO's `role_policy` (repeatable, or comma-separated). Environment: `TEIFS_OPENID_ROLE_POLICY`. |
| `--openid-claim-name <CLAIM>` | Without role policies, the claim that names a token's managed policies (default: `policy`), as MinIO's `claim_name`. Environment: `TEIFS_OPENID_CLAIM_NAME`. |
| `--openid-claim-userinfo` | Complete tokens' claims from the provider's userinfo endpoint, with the access token a request gives, as MinIO's `claim_userinfo`. Environment: `TEIFS_OPENID_CLAIM_USERINFO`. |
| `--identity-tls` | Sign in clients that connect with a certificate (MinIO's `AssumeRoleWithCertificate`): the session has the policy the certificate's subject common name names. Needs HTTPS. MinIO's `MINIO_IDENTITY_TLS_ENABLE=on` works too. Environment: `TEIFS_IDENTITY_TLS`. |
| `--identity-tls-ca <PATH>` | The CA certificates (PEM: a file, or a folder of them) that must have issued client certificates (default: the certificates folder's `CAs`, as MinIO has it). Environment: `TEIFS_IDENTITY_TLS_CA`. |
| `--identity-tls-skip-verify` | Take any client certificate, whoever issued it: for testing only. MinIO's `MINIO_IDENTITY_TLS_SKIP_VERIFY=on` works too. Environment: `TEIFS_IDENTITY_TLS_SKIP_VERIFY`. |
| `--allow-sse-c` | Allow SSE-C (customer-provided keys) on buckets that don't set it themselves; AWS blocks it by default since April 2026. Environment: `TEIFS_ALLOW_SSE_C`. |
| `--no-root-access` | Refuse the root key, the service accounts it made and the sessions it started, as `MinIO`'s `root_access=off`: only IAM's users sign in. Make an admin user first. Environment: `TEIFS_NO_ROOT_ACCESS`. |
| `--allow-sigv2` | Accept Signature Version 2 (HMAC-SHA1) requests and links, for old clients and boto3's default presigned links. AWS deprecated it and refuses it for newer buckets; prefer configuring clients for Signature Version 4. Environment: `TEIFS_ALLOW_SIGV2`. |
| `--legacy-bucket-defaults` | Make new buckets as S3 did before April 2023: ACLs enabled and no Block Public Access, for applications that upload with public ACLs such as `public-read`. Without it, new buckets start as AWS's do now: ACLs disabled, public access blocked. Either way each bucket's settings can be changed. Environment: `TEIFS_LEGACY_BUCKET_DEFAULTS`. |
| `--public-metrics` | Serve Prometheus metrics (`/.teifs/metrics`) to anyone who can reach the server. Without it, a scrape needs a bearer token from `teifs admin prometheus generate`. Metrics name operations and the drive's size: only on a network you trust. Environment: `TEIFS_PUBLIC_METRICS`. |
| `--audit-log <FILE>` | Keep an audit log: one JSON line per request (who asked what, the answer, bytes and time; never secrets), appended to this file (created owner-only, reopened on SIGHUP for logrotate), or `-` for standard output. Environment: `TEIFS_AUDIT_LOG`. |
| `--audit-webhook <URL>` | Also POST the audit log's entries to this URL, in batches of JSON lines (`application/x-ndjson`), each retried until it's taken; for an https URL, `,ca=PATH` verifies the server with a CA's PEM file, and `,client_cert=PATH` and `,client_key=PATH` are shown to a server that asks. The webhook's token, sent as `Authorization: Bearer TOKEN` (or as given when it names a scheme), is read only from the environment: `TEIFS_AUDIT_WEBHOOK_TOKEN`. Environment: `TEIFS_AUDIT_WEBHOOK`. |
| `--notify-webhook <ID=URL>` | A webhook buckets' notification rules can send events to, as ID=URL, with `ca=PATH`, `client_cert=PATH` and `client_key=PATH` for an https URL, as the audit webhook's (repeat for more; in the environment, separated by spaces). Rules name it by its ARN, `arn:teifs:sqs::ID:webhook`; each event is sent as JSON, retried until it's taken, and waits on the drive meanwhile. Its token, sent as `Authorization: Bearer TOKEN` (or as given when it names a scheme), is read only from the environment: `TEIFS_NOTIFY_WEBHOOK_TOKEN_ID` (the ID in capitals, `-` as `_`). Environment: `TEIFS_NOTIFY_WEBHOOK`. |
| `--notify-elasticsearch <ID=URL,index=NAME>` | An Elasticsearch index buckets' notification rules can send events to, as ID=URL,index=NAME, with format=namespace (a document per object, replaced by each event and removed with it: the default) or format=access (a document per event), user=NAME, and for an https URL `ca=PATH`, `client_cert=PATH` and `client_key=PATH` (repeat for more; in the environment, separated by spaces). Rules name it `arn:teifs:sqs::ID:elasticsearch`; the index is created when missing. Its password, `TEIFS_NOTIFY_ELASTICSEARCH_PASSWORD_ID`, or API key, `TEIFS_NOTIFY_ELASTICSEARCH_API_KEY_ID`, is read only from the environment. Environment: `TEIFS_NOTIFY_ELASTICSEARCH`. |
| `--notify-redis <ID=HOST:PORT,key=NAME>` | A Redis key buckets' notification rules can send events to, as ID=HOST:PORT,key=NAME, with format=namespace (a hash, a field per object, set by each event and removed with it: the default) or format=access (a list, an entry per event), db=N, user=NAME, and tls=true (the server verified with the system's certificates) or ca=PATH (with a CA's PEM file), with `client_cert=PATH` and `client_key=PATH` for a server that wants a client certificate (repeat for more; in the environment, separated by spaces). Rules name it `arn:teifs:sqs::ID:redis`. Its password, `TEIFS_NOTIFY_REDIS_PASSWORD_ID`, is read only from the environment. Environment: `TEIFS_NOTIFY_REDIS`. |
| `--notify-nsq <ID=HOST:PORT,topic=NAME>` | An NSQ topic buckets' notification rules can send events to, as ID=HOST:PORT,topic=NAME, the nsqd's TCP address, with `tls=true` or `ca=PATH` (and `client_cert=PATH` and `client_key=PATH`) for TLS (repeat for more; in the environment, separated by spaces). Rules name it `arn:teifs:sqs::ID:nsq`; each event is published as a webhook is sent it. The secret for an nsqd that wants `AUTH`, `TEIFS_NOTIFY_NSQ_SECRET_ID`, is read only from the environment and sent only over TLS. Environment: `TEIFS_NOTIFY_NSQ`. |
| `--notify-nats <ID=HOST:PORT,subject=NAME>` | A NATS subject buckets' notification rules can send events to, as ID=HOST:PORT,subject=NAME, with jetstream=true (a `JetStream` stream that takes the subject acknowledges each event), user=NAME, creds=PATH (a `.creds` file's user JWT and key) or nkey=PATH (a file holding a user seed), and tls=true or ca=PATH, `client_cert=PATH` and `client_key=PATH`, with `tls_first=true` for a server that starts TLS first (repeat for more; in the environment, separated by spaces). Rules name it `arn:teifs:sqs::ID:nats`. Its password or token, `TEIFS_NOTIFY_NATS_PASSWORD_ID` or `TEIFS_NOTIFY_NATS_TOKEN_ID`, is read only from the environment. Environment: `TEIFS_NOTIFY_NATS`. |
| `--notify-mqtt <ID=HOST:PORT,topic=NAME>` | An MQTT topic buckets' notification rules can send events to, as ID=HOST:PORT,topic=NAME, the broker's address (or its URL: tcp://, ssl:// for TLS, ws:// or wss:// with the WebSocket's path), with qos=0, 1 (the default) or 2, user=NAME, keepalive=SECONDS, and tls=true or ca=PATH with `client_cert=PATH` and `client_key=PATH` (repeat for more; in the environment, separated by spaces). Rules name it `arn:teifs:sqs::ID:mqtt`. Its password, `TEIFS_NOTIFY_MQTT_PASSWORD_ID`, is read only from the environment. Environment: `TEIFS_NOTIFY_MQTT`. |
| `--notify-kafka <ID=BROKER,topic=NAME>` | A Kafka topic buckets' notification rules can send events to, as ID=BROKER[;BROKER…],topic=NAME, the brokers first asked about the topic (`HOST:PORT`), with acks=all (the default: every in-sync replica has each event) or acks=1, compression=gzip, snappy, lz4 or zstd (Kafka 2.1 or later), sasl=plain, scram-sha-256 or scram-sha-512 with user=NAME, and tls=true or ca=PATH with `client_cert=PATH` and `client_key=PATH` (repeat for more; in the environment, separated by spaces). Rules name it `arn:teifs:sqs::ID:kafka`; each event is produced as a webhook is sent it, keyed `bucket/object`. Its SASL password, `TEIFS_NOTIFY_KAFKA_PASSWORD_ID`, is read only from the environment. Environment: `TEIFS_NOTIFY_KAFKA`. |
| `--notify-amqp <ID=URL,exchange=NAME,routing_key=KEY>` | An AMQP 0-9-1 exchange (`RabbitMQ`) buckets' notification rules can send events to, as `ID=amqp[s]://HOST[:PORT][/VHOST],exchange=NAME,routing_key=KEY`, with `exchange_type=direct` (the default), fanout, topic or headers, `durable=false`, `auto_delete=true`, `internal=true`, `declare=false` (only check that the exchange exists), `mandatory=true` (a message no queue takes fails and is tried again), `persistent=false`, `user=NAME`, and for `amqps://` `ca=PATH`, `client_cert=PATH` and `client_key=PATH` (repeat for more; in the environment, separated by spaces). Rules name it `arn:teifs:sqs::ID:amqp`; each event is published as a webhook is sent it and confirmed by the broker. Its password, `TEIFS_NOTIFY_AMQP_PASSWORD_ID`, is read only from the environment. Environment: `TEIFS_NOTIFY_AMQP`. |
| `--notify-postgresql <ID=HOST:PORT,database=NAME,table=NAME,user=NAME>` | A PostgreSQL table buckets' notification rules can send events to, as `ID=HOST:PORT,database=NAME,table=NAME,user=NAME` (a table's name in double quotes keeps its capitals, as `table="S3Events"`), with `format=namespace` (a row per object, set by each event and deleted with it: the default) or `format=access` (a row per event), and `tls=true` (the server verified with the system's certificates) or `ca=PATH`, with `client_cert=PATH` and `client_key=PATH` (repeat for more; in the environment, separated by spaces). The table is made if it's missing. Rules name it `arn:teifs:sqs::ID:postgresql`. Its password, `TEIFS_NOTIFY_POSTGRESQL_PASSWORD_ID`, is read only from the environment. Environment: `TEIFS_NOTIFY_POSTGRESQL`. |
| `--notify-mysql <ID=HOST:PORT,database=NAME,table=NAME,user=NAME>` | A MySQL (5.7 or later) or `MariaDB` table buckets' notification rules can send events to, as `ID=HOST:PORT,database=NAME,table=NAME,user=NAME` (a table's name in backquotes keeps its capitals), with `format=namespace` (a row per object: the default) or `format=access` (a row per event), `tls=true` or `ca=PATH` with `client_cert=PATH` and `client_key=PATH`, and, for a server that wants the whole password without TLS, `server_public_key=PATH` (its RSA key, `public_key.pem`) or `get_server_public_key=true` (asked for, which a machine in between could swap). The table is made if it's missing. Rules name it `arn:teifs:sqs::ID:mysql`. Its password, `TEIFS_NOTIFY_MYSQL_PASSWORD_ID`, is read only from the environment. Environment: `TEIFS_NOTIFY_MYSQL`. |
| `--notify-sqs <ID=QUEUE_URL>` | An SQS queue buckets' notification rules can send events to, as S3 sends them, as `ID=QUEUE_URL` (`https://sqs.REGION.amazonaws.com/ACCOUNT/NAME`, or any service that speaks SQS's API), with region=NAME when its host doesn't name it (repeat for more; in the environment, separated by spaces). Rules name it `arn:teifs:sqs::ID:sqs`. Requests are signed with `TEIFS_NOTIFY_SQS_ACCESS_KEY_ID`, `TEIFS_NOTIFY_SQS_SECRET_KEY_ID` and `TEIFS_NOTIFY_SQS_SESSION_TOKEN_ID`, else `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN`, read only from the environment. Environment: `TEIFS_NOTIFY_SQS`. |
| `--notify-sns <ID=TOPIC_ARN>` | An SNS topic buckets' notification rules can publish events to, as S3 publishes them, as `ID=TOPIC_ARN` (`arn:aws:sns:REGION:ACCOUNT:NAME`), with endpoint=URL for a service other than AWS's (repeat for more; in the environment, separated by spaces). Rules name it by the topic's ARN, as on S3, or `arn:teifs:sqs::ID:sns`. Requests are signed with `TEIFS_NOTIFY_SNS_ACCESS_KEY_ID`, `TEIFS_NOTIFY_SNS_SECRET_KEY_ID` and `TEIFS_NOTIFY_SNS_SESSION_TOKEN_ID`, else `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN`, read only from the environment. Environment: `TEIFS_NOTIFY_SNS`. |
| `--notify-lambda <ID=FUNCTION_ARN>` | A Lambda function buckets' notification rules can invoke with events, as S3 invokes it, as `ID=FUNCTION_ARN` (`arn:aws:lambda:REGION:ACCOUNT:function:NAME`, with `:VERSION` or `:ALIAS` if one is meant), with endpoint=URL for a service other than AWS's (repeat for more; in the environment, separated by spaces). Rules name it by the function's ARN, as on S3, or `arn:teifs:sqs::ID:lambda`. Requests are signed with `TEIFS_NOTIFY_LAMBDA_ACCESS_KEY_ID`, `TEIFS_NOTIFY_LAMBDA_SECRET_KEY_ID` and `TEIFS_NOTIFY_LAMBDA_SESSION_TOKEN_ID`, else `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN`, read only from the environment. Environment: `TEIFS_NOTIFY_LAMBDA`. |
| `--notify-eventbridge <ID=BUS_ARN>` | The EventBridge event bus buckets send every event to once EventBridge is turned on for them (`EventBridgeConfiguration`), as S3 does, as `ID=BUS_ARN` (`arn:aws:events:REGION:ACCOUNT:event-bus/default`), with source=NAME (`teifs.s3` by default: EventBridge keeps `aws.` sources for AWS's services) and endpoint=URL for a service other than AWS's. Requests are signed with `TEIFS_NOTIFY_EVENTBRIDGE_ACCESS_KEY_ID`, `TEIFS_NOTIFY_EVENTBRIDGE_SECRET_KEY_ID` and `TEIFS_NOTIFY_EVENTBRIDGE_SESSION_TOKEN_ID`, else `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN`, read only from the environment. Environment: `TEIFS_NOTIFY_EVENTBRIDGE`. |
| `--sse-c-over-http` | Accept SSE-C keys over plain HTTP. Only behind a proxy that terminates TLS; a server listening on this machine only accepts them anyway. Environment: `TEIFS_SSE_C_OVER_HTTP`. |
| `--upload-expiry <UPLOAD_EXPIRY>` | Abort multipart uploads left unfinished this long (`30m`, `12h`, `7d`), or `never`. Default: `7d`. Environment: `TEIFS_UPLOAD_EXPIRY`. |
| `--scrub-every <SCRUB_EVERY>` | Read every stored version back this often (`7d`, `30d`), checking it against its checksums and ETag so damage on the disk is found early, or `never`. Passes go at the background jobs' pace and carry on after a restart. Default: `30d`. Environment: `TEIFS_SCRUB_EVERY`. |
| `--snapshots <SNAPSHOTS>` | How many daily snapshots of the drive's metadata (its buckets, settings, IAM and object index) to keep in `.teifs/backups/auto/`; 0 takes none. Default: `3`. Environment: `TEIFS_SNAPSHOTS`. |
| `--durability <DURABILITY>` | How hard writes are made to survive a power cut: `strict` (nothing acknowledged is lost), `relaxed` (file data synced; the last moments' writes may be lost) or `none` (scratch data). None of them can corrupt the drive. One of `strict`, `relaxed`, `none`. Default: `strict`. Environment: `TEIFS_DURABILITY`. |
| `--key-names <KEY_NAMES>` | Which names folder buckets may create: `portable` (names Windows, macOS and Linux can all hold, so the drive can move between them) or `host` (whatever this system can hold). Object buckets take any S3 key either way. One of `portable`, `host`. Default: `portable`. Environment: `TEIFS_KEY_NAMES`. |
| `--access-log-interval <ACCESS_LOG_INTERVAL>` | How often each bucket's server access log is delivered into its target bucket as a log object (AWS delivers within hours; sooner here). A log object is also delivered at 1 MiB, and when the day changes. Default: `5m`. Environment: `TEIFS_ACCESS_LOG_INTERVAL`. |
| `--header-timeout <HEADER_TIMEOUT>` | How long a client has to send a request's headers; idle connections close after it too. Default: `30s`. Environment: `TEIFS_HEADER_TIMEOUT`. |
| `--body-timeout <BODY_TIMEOUT>` | How long an upload's body may stop arriving before the request fails with `RequestTimeout`. Default: `60s`. Environment: `TEIFS_BODY_TIMEOUT`. |
| `--max-connections <MAX_CONNECTIONS>` | The most connections served at once; more wait until one closes. Default: `4096`. Environment: `TEIFS_MAX_CONNECTIONS`. |
| `--secret-key-file <SECRET_KEY_FILE>` | A file holding the secret key, for use with the access key (Docker and systemd secrets). Or set `TEIFS_SECRET_KEY`; never on the command line. Environment: `TEIFS_SECRET_KEY_FILE`. |

## teifs config

Show the settings `teifs serve` would use, and where each comes from.

```
teifs config [OPTIONS] <COMMAND>
```

## teifs config show

Print the effective settings as TOML, with where each comes from. Secrets are never printed.

```
teifs config show [OPTIONS] [DIR]
```

| Argument | |
|---|---|
| `--config <CONFIG>` | A TOML file of settings, under the flags' names (`listen = "0.0.0.0:9000"`). Environment: `TEIFS_CONFIG`. |
| `<DIR>` | The drive's folder (created if missing). Default: `.`. Environment: `TEIFS_DIR`. |
| `--listen <LISTEN>` | Address to listen on. Default: `127.0.0.1:9000`. Environment: `TEIFS_LISTEN`. |
| `--certs-dir <CERTS_DIR>` | Serve HTTPS with the certificates in this folder: `public.crt` and `private.key` (or `tls.crt` and `tls.key`), and a subfolder with the same files for each further certificate, chosen by the name clients ask for. They're reloaded when they change, and on SIGHUP. Environment: `TEIFS_CERTS_DIR`. |
| `--tls-cert <TLS_CERT>` | Serve HTTPS with this certificate (PEM, its chain after it), reloaded when it changes; needs `--tls-key`. Environment: `TEIFS_TLS_CERT`. |
| `--tls-key <TLS_KEY>` | The private key (PEM) of `--tls-cert`. Environment: `TEIFS_TLS_KEY`. |
| `--trusted-proxy <CIDR>` | Trust the reverse proxy at this address or network (`10.0.0.5`, `10.0.0.0/8`; repeatable) to say who its clients are, in `--proxy-header`, and whether they came over HTTPS, in `X-Forwarded-Proto`. Nobody else can. Environment: `TEIFS_TRUSTED_PROXIES`. |
| `--proxy-header <PROXY_HEADER>` | The header trusted proxies name clients in: `x-forwarded-for` (nginx, HAProxy, Traefik, Caddy, Envoy, AWS load balancers), `forwarded` (RFC 7239) or `x-real-ip`. Choose one the proxy adds to or sets, never one it passes on. Default: `x-forwarded-for`. Environment: `TEIFS_PROXY_HEADER`. |
| `--domain <DOMAINS>` | A domain for virtual-hosted-style requests (bucket.domain); repeatable. Environment: `TEIFS_DOMAINS`. |
| `--website-domain <WEBSITE_DOMAINS>` | A domain for buckets' static websites (`bucket.domain`), as S3's website endpoint; repeatable. Buckets with a website configuration answer there. Environment: `TEIFS_WEBSITE_DOMAINS`. |
| `--access-key <ACCESS_KEY>` | The access key (else one is generated and kept in the drive). Environment: `TEIFS_ACCESS_KEY`. |
| `--default-layout <DEFAULT_LAYOUT>` | How buckets created over S3 store objects, unless the request says: `object` (any key S3 allows, encrypted at rest by default, as on AWS) or `folder` (plain files you can open anywhere). One of `object`, `folder`. Default: `object`. Environment: `TEIFS_DEFAULT_LAYOUT`. |
| `--kms-keyring <KMS_KEYRING>` | The KMS keyring (default: `<config dir>/teifs/keys/<drive id>.json`). Keep it off the drive and back it up: encrypted objects can't be read without it. Environment: `TEIFS_KMS_KEYRING`. |
| `--kms-transit <KMS_TRANSIT>` | Use a Vault or OpenBao transit engine as the KMS (e.g. `https://vault:8200`); its token comes from `VAULT_TOKEN` or `BAO_TOKEN`. Environment: `TEIFS_KMS_TRANSIT`. |
| `--kms-transit-mount <KMS_TRANSIT_MOUNT>` | Where the transit engine is mounted. Default: `transit`. Environment: `TEIFS_KMS_TRANSIT_MOUNT`. |
| `--kms-transit-namespace <KMS_TRANSIT_NAMESPACE>` | The transit engine's namespace (Vault Enterprise, OpenBao). Environment: `TEIFS_KMS_TRANSIT_NAMESPACE`. |
| `--kms-kes <KMS_KES>` | Use KES as the KMS: one or more servers, comma-separated (e.g. `https://kes:7373`). TeiFS signs in with the API key in `TEIFS_KMS_KES_API_KEY`, or with --kms-kes-cert and --kms-kes-key. Environment: `TEIFS_KMS_KES`. |
| `--kms-kes-cert <KMS_KES_CERT>` | A client certificate (PEM) to sign in to KES with, instead of an API key. Environment: `TEIFS_KMS_KES_CERT`. |
| `--kms-kes-key <KMS_KES_KEY>` | The client certificate's private key (PEM). Environment: `TEIFS_KMS_KES_KEY`. |
| `--kms-kes-ca <KMS_KES_CA>` | The certificate authorities KES's certificate is checked against (PEM; default: the system's). Environment: `TEIFS_KMS_KES_CA`. |
| `--kms-aws` | Use AWS KMS: credentials come from AWS's usual places (environment, shared config and SSO, instance and container roles). Environment: `TEIFS_KMS_AWS`. |
| `--kms-aws-region <KMS_AWS_REGION>` | AWS KMS's region (default: AWS's configuration's). Environment: `TEIFS_KMS_AWS_REGION`. |
| `--kms-aws-endpoint <KMS_AWS_ENDPOINT>` | Another AWS KMS endpoint, such as a VPC endpoint or a local emulator. Environment: `TEIFS_KMS_AWS_ENDPOINT`. |
| `--kms-default-key <KMS_DEFAULT_KEY>` | The key to use where TeiFS would use `teifs-default`: SSE-S3, SSE-KMS without a key, and the drive's own secrets. Keys sealed before keep opening. Environment: `TEIFS_KMS_DEFAULT_KEY`. |
| `--ldap-server <ADDRESS>` | Sign users in with this LDAP server (`host` or `host:port`; port 636 when none), as MinIO's `AssumeRoleWithLDAPIdentity`. Its lookup account's password comes from `TEIFS_LDAP_LOOKUP_BIND_PASSWORD`. Environment: `TEIFS_LDAP_SERVER`. |
| `--ldap-srv-record <LDAP_SRV_RECORD>` | Find the servers in DNS SRV records instead: `on` (the address is the record's whole name), `ldap` or `ldaps` (the address is a domain). One of `on`, `ldap`, `ldaps`. Environment: `TEIFS_LDAP_SRV_RECORD`. |
| `--ldap-starttls` | Reach it with plain LDAP upgraded by `StartTLS`, not LDAP over TLS. Environment: `TEIFS_LDAP_STARTTLS`. |
| `--ldap-insecure` | Reach it with plain, unencrypted LDAP: passwords cross the network as they are. Environment: `TEIFS_LDAP_INSECURE`. |
| `--ldap-ca <FILE>` | The certificate authorities (PEM) its certificate is checked against (default: the system's). Environment: `TEIFS_LDAP_CA`. |
| `--ldap-tls-skip-verify` | Accept any certificate from it: for a test directory only. Environment: `TEIFS_LDAP_TLS_SKIP_VERIFY`. |
| `--ldap-lookup-bind-dn <DN>` | The DN of the account users are looked up with. Environment: `TEIFS_LDAP_LOOKUP_BIND_DN`. |
| `--ldap-user-base-dn <DN>` | Where users are searched for (repeatable, or separated by `;`). Environment: `TEIFS_LDAP_USER_BASE_DN`. |
| `--ldap-user-filter <FILTER>` | The filter that finds a user: `%s` is the name it signs in with, like `(uid=%s)`. Environment: `TEIFS_LDAP_USER_FILTER`. |
| `--ldap-user-attributes <NAMES>` | The user's attributes its sessions carry, comma-separated. Environment: `TEIFS_LDAP_USER_ATTRIBUTES`. |
| `--ldap-group-base-dn <DN>` | Where groups are searched for (repeatable, or separated by `;`). Environment: `TEIFS_LDAP_GROUP_BASE_DN`. |
| `--ldap-group-filter <FILTER>` | The filter that finds a user's groups: `%d` is its DN and `%s` the name it signs in with, like `(&(objectclass=groupOfNames)(member=%d))`. Environment: `TEIFS_LDAP_GROUP_FILTER`. |
| `--identity-plugin-url <URL>` | Check custom tokens with this identity plugin (an `http(s)` URL), as MinIO's `AssumeRoleWithCustomToken`: it's sent each token and answers whom it's for. The `Authorization` header it's sent comes from `TEIFS_IDENTITY_PLUGIN_AUTH_TOKEN`. Environment: `TEIFS_IDENTITY_PLUGIN_URL`. |
| `--identity-plugin-role-policy <NAMES>` | The managed policies its users' sessions get (repeatable, or comma-separated). Environment: `TEIFS_IDENTITY_PLUGIN_ROLE_POLICY`. |
| `--identity-plugin-role-id <ID>` | The id in the role ARN clients name, `arn:minio:iam:::role/idmp-<ID>` (default: derived from the URL, as MinIO derives it). Environment: `TEIFS_IDENTITY_PLUGIN_ROLE_ID`. |
| `--identity-plugin-ca <PATH>` | Certificate authorities (PEM: a file, or a folder of them) its certificate may be issued by, besides the system's. Environment: `TEIFS_IDENTITY_PLUGIN_CA`. |
| `--openid-config-url <URL>` | Make an OpenID Connect provider, or keep it in line with these settings, when the server starts: its discovery URL (`https://…/.well-known/openid-configuration`) or its issuer, as MinIO's `config_url`. Environment: `TEIFS_OPENID_CONFIG_URL`. |
| `--openid-client-id <ID>` | The client its tokens are for (their `aud` or `azp`). Environment: `TEIFS_OPENID_CLIENT_ID`. |
| `--openid-role-policy <NAMES>` | Give every token for the client these managed policies when it names the client's role (`arn:minio:iam:::role/…`), as MinIO's `role_policy` (repeatable, or comma-separated). Environment: `TEIFS_OPENID_ROLE_POLICY`. |
| `--openid-claim-name <CLAIM>` | Without role policies, the claim that names a token's managed policies (default: `policy`), as MinIO's `claim_name`. Environment: `TEIFS_OPENID_CLAIM_NAME`. |
| `--openid-claim-userinfo` | Complete tokens' claims from the provider's userinfo endpoint, with the access token a request gives, as MinIO's `claim_userinfo`. Environment: `TEIFS_OPENID_CLAIM_USERINFO`. |
| `--identity-tls` | Sign in clients that connect with a certificate (MinIO's `AssumeRoleWithCertificate`): the session has the policy the certificate's subject common name names. Needs HTTPS. MinIO's `MINIO_IDENTITY_TLS_ENABLE=on` works too. Environment: `TEIFS_IDENTITY_TLS`. |
| `--identity-tls-ca <PATH>` | The CA certificates (PEM: a file, or a folder of them) that must have issued client certificates (default: the certificates folder's `CAs`, as MinIO has it). Environment: `TEIFS_IDENTITY_TLS_CA`. |
| `--identity-tls-skip-verify` | Take any client certificate, whoever issued it: for testing only. MinIO's `MINIO_IDENTITY_TLS_SKIP_VERIFY=on` works too. Environment: `TEIFS_IDENTITY_TLS_SKIP_VERIFY`. |
| `--allow-sse-c` | Allow SSE-C (customer-provided keys) on buckets that don't set it themselves; AWS blocks it by default since April 2026. Environment: `TEIFS_ALLOW_SSE_C`. |
| `--no-root-access` | Refuse the root key, the service accounts it made and the sessions it started, as `MinIO`'s `root_access=off`: only IAM's users sign in. Make an admin user first. Environment: `TEIFS_NO_ROOT_ACCESS`. |
| `--allow-sigv2` | Accept Signature Version 2 (HMAC-SHA1) requests and links, for old clients and boto3's default presigned links. AWS deprecated it and refuses it for newer buckets; prefer configuring clients for Signature Version 4. Environment: `TEIFS_ALLOW_SIGV2`. |
| `--legacy-bucket-defaults` | Make new buckets as S3 did before April 2023: ACLs enabled and no Block Public Access, for applications that upload with public ACLs such as `public-read`. Without it, new buckets start as AWS's do now: ACLs disabled, public access blocked. Either way each bucket's settings can be changed. Environment: `TEIFS_LEGACY_BUCKET_DEFAULTS`. |
| `--public-metrics` | Serve Prometheus metrics (`/.teifs/metrics`) to anyone who can reach the server. Without it, a scrape needs a bearer token from `teifs admin prometheus generate`. Metrics name operations and the drive's size: only on a network you trust. Environment: `TEIFS_PUBLIC_METRICS`. |
| `--audit-log <FILE>` | Keep an audit log: one JSON line per request (who asked what, the answer, bytes and time; never secrets), appended to this file (created owner-only, reopened on SIGHUP for logrotate), or `-` for standard output. Environment: `TEIFS_AUDIT_LOG`. |
| `--audit-webhook <URL>` | Also POST the audit log's entries to this URL, in batches of JSON lines (`application/x-ndjson`), each retried until it's taken; for an https URL, `,ca=PATH` verifies the server with a CA's PEM file, and `,client_cert=PATH` and `,client_key=PATH` are shown to a server that asks. The webhook's token, sent as `Authorization: Bearer TOKEN` (or as given when it names a scheme), is read only from the environment: `TEIFS_AUDIT_WEBHOOK_TOKEN`. Environment: `TEIFS_AUDIT_WEBHOOK`. |
| `--notify-webhook <ID=URL>` | A webhook buckets' notification rules can send events to, as ID=URL, with `ca=PATH`, `client_cert=PATH` and `client_key=PATH` for an https URL, as the audit webhook's (repeat for more; in the environment, separated by spaces). Rules name it by its ARN, `arn:teifs:sqs::ID:webhook`; each event is sent as JSON, retried until it's taken, and waits on the drive meanwhile. Its token, sent as `Authorization: Bearer TOKEN` (or as given when it names a scheme), is read only from the environment: `TEIFS_NOTIFY_WEBHOOK_TOKEN_ID` (the ID in capitals, `-` as `_`). Environment: `TEIFS_NOTIFY_WEBHOOK`. |
| `--notify-elasticsearch <ID=URL,index=NAME>` | An Elasticsearch index buckets' notification rules can send events to, as ID=URL,index=NAME, with format=namespace (a document per object, replaced by each event and removed with it: the default) or format=access (a document per event), user=NAME, and for an https URL `ca=PATH`, `client_cert=PATH` and `client_key=PATH` (repeat for more; in the environment, separated by spaces). Rules name it `arn:teifs:sqs::ID:elasticsearch`; the index is created when missing. Its password, `TEIFS_NOTIFY_ELASTICSEARCH_PASSWORD_ID`, or API key, `TEIFS_NOTIFY_ELASTICSEARCH_API_KEY_ID`, is read only from the environment. Environment: `TEIFS_NOTIFY_ELASTICSEARCH`. |
| `--notify-redis <ID=HOST:PORT,key=NAME>` | A Redis key buckets' notification rules can send events to, as ID=HOST:PORT,key=NAME, with format=namespace (a hash, a field per object, set by each event and removed with it: the default) or format=access (a list, an entry per event), db=N, user=NAME, and tls=true (the server verified with the system's certificates) or ca=PATH (with a CA's PEM file), with `client_cert=PATH` and `client_key=PATH` for a server that wants a client certificate (repeat for more; in the environment, separated by spaces). Rules name it `arn:teifs:sqs::ID:redis`. Its password, `TEIFS_NOTIFY_REDIS_PASSWORD_ID`, is read only from the environment. Environment: `TEIFS_NOTIFY_REDIS`. |
| `--notify-nsq <ID=HOST:PORT,topic=NAME>` | An NSQ topic buckets' notification rules can send events to, as ID=HOST:PORT,topic=NAME, the nsqd's TCP address, with `tls=true` or `ca=PATH` (and `client_cert=PATH` and `client_key=PATH`) for TLS (repeat for more; in the environment, separated by spaces). Rules name it `arn:teifs:sqs::ID:nsq`; each event is published as a webhook is sent it. The secret for an nsqd that wants `AUTH`, `TEIFS_NOTIFY_NSQ_SECRET_ID`, is read only from the environment and sent only over TLS. Environment: `TEIFS_NOTIFY_NSQ`. |
| `--notify-nats <ID=HOST:PORT,subject=NAME>` | A NATS subject buckets' notification rules can send events to, as ID=HOST:PORT,subject=NAME, with jetstream=true (a `JetStream` stream that takes the subject acknowledges each event), user=NAME, creds=PATH (a `.creds` file's user JWT and key) or nkey=PATH (a file holding a user seed), and tls=true or ca=PATH, `client_cert=PATH` and `client_key=PATH`, with `tls_first=true` for a server that starts TLS first (repeat for more; in the environment, separated by spaces). Rules name it `arn:teifs:sqs::ID:nats`. Its password or token, `TEIFS_NOTIFY_NATS_PASSWORD_ID` or `TEIFS_NOTIFY_NATS_TOKEN_ID`, is read only from the environment. Environment: `TEIFS_NOTIFY_NATS`. |
| `--notify-mqtt <ID=HOST:PORT,topic=NAME>` | An MQTT topic buckets' notification rules can send events to, as ID=HOST:PORT,topic=NAME, the broker's address (or its URL: tcp://, ssl:// for TLS, ws:// or wss:// with the WebSocket's path), with qos=0, 1 (the default) or 2, user=NAME, keepalive=SECONDS, and tls=true or ca=PATH with `client_cert=PATH` and `client_key=PATH` (repeat for more; in the environment, separated by spaces). Rules name it `arn:teifs:sqs::ID:mqtt`. Its password, `TEIFS_NOTIFY_MQTT_PASSWORD_ID`, is read only from the environment. Environment: `TEIFS_NOTIFY_MQTT`. |
| `--notify-kafka <ID=BROKER,topic=NAME>` | A Kafka topic buckets' notification rules can send events to, as ID=BROKER[;BROKER…],topic=NAME, the brokers first asked about the topic (`HOST:PORT`), with acks=all (the default: every in-sync replica has each event) or acks=1, compression=gzip, snappy, lz4 or zstd (Kafka 2.1 or later), sasl=plain, scram-sha-256 or scram-sha-512 with user=NAME, and tls=true or ca=PATH with `client_cert=PATH` and `client_key=PATH` (repeat for more; in the environment, separated by spaces). Rules name it `arn:teifs:sqs::ID:kafka`; each event is produced as a webhook is sent it, keyed `bucket/object`. Its SASL password, `TEIFS_NOTIFY_KAFKA_PASSWORD_ID`, is read only from the environment. Environment: `TEIFS_NOTIFY_KAFKA`. |
| `--notify-amqp <ID=URL,exchange=NAME,routing_key=KEY>` | An AMQP 0-9-1 exchange (`RabbitMQ`) buckets' notification rules can send events to, as `ID=amqp[s]://HOST[:PORT][/VHOST],exchange=NAME,routing_key=KEY`, with `exchange_type=direct` (the default), fanout, topic or headers, `durable=false`, `auto_delete=true`, `internal=true`, `declare=false` (only check that the exchange exists), `mandatory=true` (a message no queue takes fails and is tried again), `persistent=false`, `user=NAME`, and for `amqps://` `ca=PATH`, `client_cert=PATH` and `client_key=PATH` (repeat for more; in the environment, separated by spaces). Rules name it `arn:teifs:sqs::ID:amqp`; each event is published as a webhook is sent it and confirmed by the broker. Its password, `TEIFS_NOTIFY_AMQP_PASSWORD_ID`, is read only from the environment. Environment: `TEIFS_NOTIFY_AMQP`. |
| `--notify-postgresql <ID=HOST:PORT,database=NAME,table=NAME,user=NAME>` | A PostgreSQL table buckets' notification rules can send events to, as `ID=HOST:PORT,database=NAME,table=NAME,user=NAME` (a table's name in double quotes keeps its capitals, as `table="S3Events"`), with `format=namespace` (a row per object, set by each event and deleted with it: the default) or `format=access` (a row per event), and `tls=true` (the server verified with the system's certificates) or `ca=PATH`, with `client_cert=PATH` and `client_key=PATH` (repeat for more; in the environment, separated by spaces). The table is made if it's missing. Rules name it `arn:teifs:sqs::ID:postgresql`. Its password, `TEIFS_NOTIFY_POSTGRESQL_PASSWORD_ID`, is read only from the environment. Environment: `TEIFS_NOTIFY_POSTGRESQL`. |
| `--notify-mysql <ID=HOST:PORT,database=NAME,table=NAME,user=NAME>` | A MySQL (5.7 or later) or `MariaDB` table buckets' notification rules can send events to, as `ID=HOST:PORT,database=NAME,table=NAME,user=NAME` (a table's name in backquotes keeps its capitals), with `format=namespace` (a row per object: the default) or `format=access` (a row per event), `tls=true` or `ca=PATH` with `client_cert=PATH` and `client_key=PATH`, and, for a server that wants the whole password without TLS, `server_public_key=PATH` (its RSA key, `public_key.pem`) or `get_server_public_key=true` (asked for, which a machine in between could swap). The table is made if it's missing. Rules name it `arn:teifs:sqs::ID:mysql`. Its password, `TEIFS_NOTIFY_MYSQL_PASSWORD_ID`, is read only from the environment. Environment: `TEIFS_NOTIFY_MYSQL`. |
| `--notify-sqs <ID=QUEUE_URL>` | An SQS queue buckets' notification rules can send events to, as S3 sends them, as `ID=QUEUE_URL` (`https://sqs.REGION.amazonaws.com/ACCOUNT/NAME`, or any service that speaks SQS's API), with region=NAME when its host doesn't name it (repeat for more; in the environment, separated by spaces). Rules name it `arn:teifs:sqs::ID:sqs`. Requests are signed with `TEIFS_NOTIFY_SQS_ACCESS_KEY_ID`, `TEIFS_NOTIFY_SQS_SECRET_KEY_ID` and `TEIFS_NOTIFY_SQS_SESSION_TOKEN_ID`, else `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN`, read only from the environment. Environment: `TEIFS_NOTIFY_SQS`. |
| `--notify-sns <ID=TOPIC_ARN>` | An SNS topic buckets' notification rules can publish events to, as S3 publishes them, as `ID=TOPIC_ARN` (`arn:aws:sns:REGION:ACCOUNT:NAME`), with endpoint=URL for a service other than AWS's (repeat for more; in the environment, separated by spaces). Rules name it by the topic's ARN, as on S3, or `arn:teifs:sqs::ID:sns`. Requests are signed with `TEIFS_NOTIFY_SNS_ACCESS_KEY_ID`, `TEIFS_NOTIFY_SNS_SECRET_KEY_ID` and `TEIFS_NOTIFY_SNS_SESSION_TOKEN_ID`, else `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN`, read only from the environment. Environment: `TEIFS_NOTIFY_SNS`. |
| `--notify-lambda <ID=FUNCTION_ARN>` | A Lambda function buckets' notification rules can invoke with events, as S3 invokes it, as `ID=FUNCTION_ARN` (`arn:aws:lambda:REGION:ACCOUNT:function:NAME`, with `:VERSION` or `:ALIAS` if one is meant), with endpoint=URL for a service other than AWS's (repeat for more; in the environment, separated by spaces). Rules name it by the function's ARN, as on S3, or `arn:teifs:sqs::ID:lambda`. Requests are signed with `TEIFS_NOTIFY_LAMBDA_ACCESS_KEY_ID`, `TEIFS_NOTIFY_LAMBDA_SECRET_KEY_ID` and `TEIFS_NOTIFY_LAMBDA_SESSION_TOKEN_ID`, else `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN`, read only from the environment. Environment: `TEIFS_NOTIFY_LAMBDA`. |
| `--notify-eventbridge <ID=BUS_ARN>` | The EventBridge event bus buckets send every event to once EventBridge is turned on for them (`EventBridgeConfiguration`), as S3 does, as `ID=BUS_ARN` (`arn:aws:events:REGION:ACCOUNT:event-bus/default`), with source=NAME (`teifs.s3` by default: EventBridge keeps `aws.` sources for AWS's services) and endpoint=URL for a service other than AWS's. Requests are signed with `TEIFS_NOTIFY_EVENTBRIDGE_ACCESS_KEY_ID`, `TEIFS_NOTIFY_EVENTBRIDGE_SECRET_KEY_ID` and `TEIFS_NOTIFY_EVENTBRIDGE_SESSION_TOKEN_ID`, else `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN`, read only from the environment. Environment: `TEIFS_NOTIFY_EVENTBRIDGE`. |
| `--sse-c-over-http` | Accept SSE-C keys over plain HTTP. Only behind a proxy that terminates TLS; a server listening on this machine only accepts them anyway. Environment: `TEIFS_SSE_C_OVER_HTTP`. |
| `--upload-expiry <UPLOAD_EXPIRY>` | Abort multipart uploads left unfinished this long (`30m`, `12h`, `7d`), or `never`. Default: `7d`. Environment: `TEIFS_UPLOAD_EXPIRY`. |
| `--scrub-every <SCRUB_EVERY>` | Read every stored version back this often (`7d`, `30d`), checking it against its checksums and ETag so damage on the disk is found early, or `never`. Passes go at the background jobs' pace and carry on after a restart. Default: `30d`. Environment: `TEIFS_SCRUB_EVERY`. |
| `--snapshots <SNAPSHOTS>` | How many daily snapshots of the drive's metadata (its buckets, settings, IAM and object index) to keep in `.teifs/backups/auto/`; 0 takes none. Default: `3`. Environment: `TEIFS_SNAPSHOTS`. |
| `--durability <DURABILITY>` | How hard writes are made to survive a power cut: `strict` (nothing acknowledged is lost), `relaxed` (file data synced; the last moments' writes may be lost) or `none` (scratch data). None of them can corrupt the drive. One of `strict`, `relaxed`, `none`. Default: `strict`. Environment: `TEIFS_DURABILITY`. |
| `--key-names <KEY_NAMES>` | Which names folder buckets may create: `portable` (names Windows, macOS and Linux can all hold, so the drive can move between them) or `host` (whatever this system can hold). Object buckets take any S3 key either way. One of `portable`, `host`. Default: `portable`. Environment: `TEIFS_KEY_NAMES`. |
| `--access-log-interval <ACCESS_LOG_INTERVAL>` | How often each bucket's server access log is delivered into its target bucket as a log object (AWS delivers within hours; sooner here). A log object is also delivered at 1 MiB, and when the day changes. Default: `5m`. Environment: `TEIFS_ACCESS_LOG_INTERVAL`. |
| `--header-timeout <HEADER_TIMEOUT>` | How long a client has to send a request's headers; idle connections close after it too. Default: `30s`. Environment: `TEIFS_HEADER_TIMEOUT`. |
| `--body-timeout <BODY_TIMEOUT>` | How long an upload's body may stop arriving before the request fails with `RequestTimeout`. Default: `60s`. Environment: `TEIFS_BODY_TIMEOUT`. |
| `--max-connections <MAX_CONNECTIONS>` | The most connections served at once; more wait until one closes. Default: `4096`. Environment: `TEIFS_MAX_CONNECTIONS`. |
| `--secret-key-file <SECRET_KEY_FILE>` | A file holding the secret key, for use with the access key (Docker and systemd secrets). Or set `TEIFS_SECRET_KEY`; never on the command line. Environment: `TEIFS_SECRET_KEY_FILE`. |

## teifs credentials

Show the drive's access key and where its secret is kept.

```
teifs credentials [OPTIONS] [DIR]
```

| Argument | |
|---|---|
| `<DIR>` | The drive's folder. Default: `.`. Environment: `TEIFS_DIR`. |

## teifs bucket

List, create or remove buckets.

```
teifs bucket [OPTIONS] <COMMAND>
```

## teifs bucket list

List buckets.

```
teifs bucket list [OPTIONS]
```

| Argument | |
|---|---|
| `--dir <DIR>` | The drive's folder (while `teifs serve` isn't using it). Default: `.`. Environment: `TEIFS_DIR`. |

## teifs bucket create

Create a bucket.

```
teifs bucket create [OPTIONS] <NAME>
```

| Argument | |
|---|---|
| `<NAME>` | The bucket's name. |
| `--layout <LAYOUT>` | How it stores objects: `object` (any key S3 allows) or `folder` (plain files). One of `object`, `folder`. Default: `object`. |
| `--dir <DIR>` | The drive's folder (while `teifs serve` isn't using it). Default: `.`. Environment: `TEIFS_DIR`. |

## teifs bucket remove

Remove an empty bucket.

```
teifs bucket remove [OPTIONS] <NAME>
```

| Argument | |
|---|---|
| `<NAME>` | The bucket's name. |
| `--dir <DIR>` | The drive's folder (while `teifs serve` isn't using it). Default: `.`. Environment: `TEIFS_DIR`. |

## teifs key

Manage the KMS keys that encrypt objects (SSE-S3 uses `teifs-default`).

```
teifs key [OPTIONS] <COMMAND>
```

## teifs key list

List the keys and their newest versions.

```
teifs key list [OPTIONS]
```

| Argument | |
|---|---|
| `--kms-keyring <KMS_KEYRING>` | The keyring (default: the drive's, in `<config dir>/teifs/keys/`). Environment: `TEIFS_KMS_KEYRING`. |
| `--dir <DIR>` | The drive whose default keyring to use. Default: `.`. Environment: `TEIFS_DIR`. |
| `--kms-transit <KMS_TRANSIT>` | Use a Vault or OpenBao transit engine as the KMS (e.g. `https://vault:8200`); its token comes from `VAULT_TOKEN` or `BAO_TOKEN`. Environment: `TEIFS_KMS_TRANSIT`. |
| `--kms-transit-mount <KMS_TRANSIT_MOUNT>` | Where the transit engine is mounted. Default: `transit`. Environment: `TEIFS_KMS_TRANSIT_MOUNT`. |
| `--kms-transit-namespace <KMS_TRANSIT_NAMESPACE>` | The transit engine's namespace (Vault Enterprise, OpenBao). Environment: `TEIFS_KMS_TRANSIT_NAMESPACE`. |
| `--kms-kes <KMS_KES>` | Use KES as the KMS: one or more servers, comma-separated (e.g. `https://kes:7373`). TeiFS signs in with the API key in `TEIFS_KMS_KES_API_KEY`, or with --kms-kes-cert and --kms-kes-key. Environment: `TEIFS_KMS_KES`. |
| `--kms-kes-cert <KMS_KES_CERT>` | A client certificate (PEM) to sign in to KES with, instead of an API key. Environment: `TEIFS_KMS_KES_CERT`. |
| `--kms-kes-key <KMS_KES_KEY>` | The client certificate's private key (PEM). Environment: `TEIFS_KMS_KES_KEY`. |
| `--kms-kes-ca <KMS_KES_CA>` | The certificate authorities KES's certificate is checked against (PEM; default: the system's). Environment: `TEIFS_KMS_KES_CA`. |
| `--kms-aws` | Use AWS KMS: credentials come from AWS's usual places (environment, shared config and SSO, instance and container roles). Environment: `TEIFS_KMS_AWS`. |
| `--kms-aws-region <KMS_AWS_REGION>` | AWS KMS's region (default: AWS's configuration's). Environment: `TEIFS_KMS_AWS_REGION`. |
| `--kms-aws-endpoint <KMS_AWS_ENDPOINT>` | Another AWS KMS endpoint, such as a VPC endpoint or a local emulator. Environment: `TEIFS_KMS_AWS_ENDPOINT`. |
| `--kms-default-key <KMS_DEFAULT_KEY>` | The key to use where TeiFS would use `teifs-default`: SSE-S3, SSE-KMS without a key, and the drive's own secrets. Keys sealed before keep opening. Environment: `TEIFS_KMS_DEFAULT_KEY`. |

## teifs key create

Create a key (for SSE-KMS: `x-amz-server-side-encryption-aws-kms-key-id`).

```
teifs key create [OPTIONS] <NAME>
```

| Argument | |
|---|---|
| `<NAME>` | Its name: letters, digits, `-`, `_` and `.`. |
| `--kms-keyring <KMS_KEYRING>` | The keyring (default: the drive's, in `<config dir>/teifs/keys/`). Environment: `TEIFS_KMS_KEYRING`. |
| `--dir <DIR>` | The drive whose default keyring to use. Default: `.`. Environment: `TEIFS_DIR`. |
| `--kms-transit <KMS_TRANSIT>` | Use a Vault or OpenBao transit engine as the KMS (e.g. `https://vault:8200`); its token comes from `VAULT_TOKEN` or `BAO_TOKEN`. Environment: `TEIFS_KMS_TRANSIT`. |
| `--kms-transit-mount <KMS_TRANSIT_MOUNT>` | Where the transit engine is mounted. Default: `transit`. Environment: `TEIFS_KMS_TRANSIT_MOUNT`. |
| `--kms-transit-namespace <KMS_TRANSIT_NAMESPACE>` | The transit engine's namespace (Vault Enterprise, OpenBao). Environment: `TEIFS_KMS_TRANSIT_NAMESPACE`. |
| `--kms-kes <KMS_KES>` | Use KES as the KMS: one or more servers, comma-separated (e.g. `https://kes:7373`). TeiFS signs in with the API key in `TEIFS_KMS_KES_API_KEY`, or with --kms-kes-cert and --kms-kes-key. Environment: `TEIFS_KMS_KES`. |
| `--kms-kes-cert <KMS_KES_CERT>` | A client certificate (PEM) to sign in to KES with, instead of an API key. Environment: `TEIFS_KMS_KES_CERT`. |
| `--kms-kes-key <KMS_KES_KEY>` | The client certificate's private key (PEM). Environment: `TEIFS_KMS_KES_KEY`. |
| `--kms-kes-ca <KMS_KES_CA>` | The certificate authorities KES's certificate is checked against (PEM; default: the system's). Environment: `TEIFS_KMS_KES_CA`. |
| `--kms-aws` | Use AWS KMS: credentials come from AWS's usual places (environment, shared config and SSO, instance and container roles). Environment: `TEIFS_KMS_AWS`. |
| `--kms-aws-region <KMS_AWS_REGION>` | AWS KMS's region (default: AWS's configuration's). Environment: `TEIFS_KMS_AWS_REGION`. |
| `--kms-aws-endpoint <KMS_AWS_ENDPOINT>` | Another AWS KMS endpoint, such as a VPC endpoint or a local emulator. Environment: `TEIFS_KMS_AWS_ENDPOINT`. |
| `--kms-default-key <KMS_DEFAULT_KEY>` | The key to use where TeiFS would use `teifs-default`: SSE-S3, SSE-KMS without a key, and the drive's own secrets. Keys sealed before keep opening. Environment: `TEIFS_KMS_DEFAULT_KEY`. |

## teifs key rotate

Add a new version to a key; objects sealed by older versions stay readable.

```
teifs key rotate [OPTIONS] <NAME>
```

| Argument | |
|---|---|
| `<NAME>` | The key's name. |
| `--kms-keyring <KMS_KEYRING>` | The keyring (default: the drive's, in `<config dir>/teifs/keys/`). Environment: `TEIFS_KMS_KEYRING`. |
| `--dir <DIR>` | The drive whose default keyring to use. Default: `.`. Environment: `TEIFS_DIR`. |
| `--kms-transit <KMS_TRANSIT>` | Use a Vault or OpenBao transit engine as the KMS (e.g. `https://vault:8200`); its token comes from `VAULT_TOKEN` or `BAO_TOKEN`. Environment: `TEIFS_KMS_TRANSIT`. |
| `--kms-transit-mount <KMS_TRANSIT_MOUNT>` | Where the transit engine is mounted. Default: `transit`. Environment: `TEIFS_KMS_TRANSIT_MOUNT`. |
| `--kms-transit-namespace <KMS_TRANSIT_NAMESPACE>` | The transit engine's namespace (Vault Enterprise, OpenBao). Environment: `TEIFS_KMS_TRANSIT_NAMESPACE`. |
| `--kms-kes <KMS_KES>` | Use KES as the KMS: one or more servers, comma-separated (e.g. `https://kes:7373`). TeiFS signs in with the API key in `TEIFS_KMS_KES_API_KEY`, or with --kms-kes-cert and --kms-kes-key. Environment: `TEIFS_KMS_KES`. |
| `--kms-kes-cert <KMS_KES_CERT>` | A client certificate (PEM) to sign in to KES with, instead of an API key. Environment: `TEIFS_KMS_KES_CERT`. |
| `--kms-kes-key <KMS_KES_KEY>` | The client certificate's private key (PEM). Environment: `TEIFS_KMS_KES_KEY`. |
| `--kms-kes-ca <KMS_KES_CA>` | The certificate authorities KES's certificate is checked against (PEM; default: the system's). Environment: `TEIFS_KMS_KES_CA`. |
| `--kms-aws` | Use AWS KMS: credentials come from AWS's usual places (environment, shared config and SSO, instance and container roles). Environment: `TEIFS_KMS_AWS`. |
| `--kms-aws-region <KMS_AWS_REGION>` | AWS KMS's region (default: AWS's configuration's). Environment: `TEIFS_KMS_AWS_REGION`. |
| `--kms-aws-endpoint <KMS_AWS_ENDPOINT>` | Another AWS KMS endpoint, such as a VPC endpoint or a local emulator. Environment: `TEIFS_KMS_AWS_ENDPOINT`. |
| `--kms-default-key <KMS_DEFAULT_KEY>` | The key to use where TeiFS would use `teifs-default`: SSE-S3, SSE-KMS without a key, and the drive's own secrets. Keys sealed before keep opening. Environment: `TEIFS_KMS_DEFAULT_KEY`. |

## teifs key rewrap

Seal again, under a key's newest version, the objects' keys its older versions sealed (the drive, while `teifs serve` isn't using it). Their data stays as it is.

```
teifs key rewrap [OPTIONS] <NAME>
```

| Argument | |
|---|---|
| `<NAME>` | The key's name. |
| `--dry-run` | Only count what would be sealed again. |
| `--kms-keyring <KMS_KEYRING>` | The keyring (default: the drive's, in `<config dir>/teifs/keys/`). Environment: `TEIFS_KMS_KEYRING`. |
| `--dir <DIR>` | The drive whose default keyring to use. Default: `.`. Environment: `TEIFS_DIR`. |
| `--kms-transit <KMS_TRANSIT>` | Use a Vault or OpenBao transit engine as the KMS (e.g. `https://vault:8200`); its token comes from `VAULT_TOKEN` or `BAO_TOKEN`. Environment: `TEIFS_KMS_TRANSIT`. |
| `--kms-transit-mount <KMS_TRANSIT_MOUNT>` | Where the transit engine is mounted. Default: `transit`. Environment: `TEIFS_KMS_TRANSIT_MOUNT`. |
| `--kms-transit-namespace <KMS_TRANSIT_NAMESPACE>` | The transit engine's namespace (Vault Enterprise, OpenBao). Environment: `TEIFS_KMS_TRANSIT_NAMESPACE`. |
| `--kms-kes <KMS_KES>` | Use KES as the KMS: one or more servers, comma-separated (e.g. `https://kes:7373`). TeiFS signs in with the API key in `TEIFS_KMS_KES_API_KEY`, or with --kms-kes-cert and --kms-kes-key. Environment: `TEIFS_KMS_KES`. |
| `--kms-kes-cert <KMS_KES_CERT>` | A client certificate (PEM) to sign in to KES with, instead of an API key. Environment: `TEIFS_KMS_KES_CERT`. |
| `--kms-kes-key <KMS_KES_KEY>` | The client certificate's private key (PEM). Environment: `TEIFS_KMS_KES_KEY`. |
| `--kms-kes-ca <KMS_KES_CA>` | The certificate authorities KES's certificate is checked against (PEM; default: the system's). Environment: `TEIFS_KMS_KES_CA`. |
| `--kms-aws` | Use AWS KMS: credentials come from AWS's usual places (environment, shared config and SSO, instance and container roles). Environment: `TEIFS_KMS_AWS`. |
| `--kms-aws-region <KMS_AWS_REGION>` | AWS KMS's region (default: AWS's configuration's). Environment: `TEIFS_KMS_AWS_REGION`. |
| `--kms-aws-endpoint <KMS_AWS_ENDPOINT>` | Another AWS KMS endpoint, such as a VPC endpoint or a local emulator. Environment: `TEIFS_KMS_AWS_ENDPOINT`. |
| `--kms-default-key <KMS_DEFAULT_KEY>` | The key to use where TeiFS would use `teifs-default`: SSE-S3, SSE-KMS without a key, and the drive's own secrets. Keys sealed before keep opening. Environment: `TEIFS_KMS_DEFAULT_KEY`. |

## teifs backup

Copy the drive's metadata (buckets, settings, IAM and the object index) into a folder, while `teifs serve` isn't using the drive. Objects' bytes stay where they are.

```
teifs backup [OPTIONS] --to <TO> [DIR]
```

| Argument | |
|---|---|
| `<DIR>` | The drive's folder. Default: `.`. Environment: `TEIFS_DIR`. |
| `--to <TO>` | The folder to write the backup into (made if missing); each backup is a folder of its own in it, named for when it was taken. |

## teifs restore

Put a backup or one of the drive's daily snapshots back as its metadata, while `teifs serve` isn't using the drive; what it replaces is kept.

```
teifs restore [OPTIONS] --from <FROM> [DIR]
```

| Argument | |
|---|---|
| `<DIR>` | The drive's folder. Default: `.`. Environment: `TEIFS_DIR`. |
| `--from <FROM>` | A backup's folder, or the name of one of the drive's own snapshots (`teifs admin snapshot ls`). |

## teifs verify

Check that the drive's objects are still the bytes written: every version against its checksums and ETag, encrypted ones as they decrypt (the drive, while `teifs serve` isn't using it). Exit code 1 when something is damaged.

```
teifs verify [OPTIONS]
```

| Argument | |
|---|---|
| `--bucket <BUCKET>` | Only this bucket. |
| `--kms-keyring <KMS_KEYRING>` | The keyring (default: the drive's, in `<config dir>/teifs/keys/`). Environment: `TEIFS_KMS_KEYRING`. |
| `--dir <DIR>` | The drive whose default keyring to use. Default: `.`. Environment: `TEIFS_DIR`. |
| `--kms-transit <KMS_TRANSIT>` | Use a Vault or OpenBao transit engine as the KMS (e.g. `https://vault:8200`); its token comes from `VAULT_TOKEN` or `BAO_TOKEN`. Environment: `TEIFS_KMS_TRANSIT`. |
| `--kms-transit-mount <KMS_TRANSIT_MOUNT>` | Where the transit engine is mounted. Default: `transit`. Environment: `TEIFS_KMS_TRANSIT_MOUNT`. |
| `--kms-transit-namespace <KMS_TRANSIT_NAMESPACE>` | The transit engine's namespace (Vault Enterprise, OpenBao). Environment: `TEIFS_KMS_TRANSIT_NAMESPACE`. |
| `--kms-kes <KMS_KES>` | Use KES as the KMS: one or more servers, comma-separated (e.g. `https://kes:7373`). TeiFS signs in with the API key in `TEIFS_KMS_KES_API_KEY`, or with --kms-kes-cert and --kms-kes-key. Environment: `TEIFS_KMS_KES`. |
| `--kms-kes-cert <KMS_KES_CERT>` | A client certificate (PEM) to sign in to KES with, instead of an API key. Environment: `TEIFS_KMS_KES_CERT`. |
| `--kms-kes-key <KMS_KES_KEY>` | The client certificate's private key (PEM). Environment: `TEIFS_KMS_KES_KEY`. |
| `--kms-kes-ca <KMS_KES_CA>` | The certificate authorities KES's certificate is checked against (PEM; default: the system's). Environment: `TEIFS_KMS_KES_CA`. |
| `--kms-aws` | Use AWS KMS: credentials come from AWS's usual places (environment, shared config and SSO, instance and container roles). Environment: `TEIFS_KMS_AWS`. |
| `--kms-aws-region <KMS_AWS_REGION>` | AWS KMS's region (default: AWS's configuration's). Environment: `TEIFS_KMS_AWS_REGION`. |
| `--kms-aws-endpoint <KMS_AWS_ENDPOINT>` | Another AWS KMS endpoint, such as a VPC endpoint or a local emulator. Environment: `TEIFS_KMS_AWS_ENDPOINT`. |
| `--kms-default-key <KMS_DEFAULT_KEY>` | The key to use where TeiFS would use `teifs-default`: SSE-S3, SSE-KMS without a key, and the drive's own secrets. Keys sealed before keep opening. Environment: `TEIFS_KMS_DEFAULT_KEY`. |

## teifs repair

Find where the drive's metadata and its files disagree (after restoring an older snapshot, say) and, with --apply, set right what's safe to (the drive, while `teifs serve` isn't using it). Exit code 1 when problems are left.

```
teifs repair [OPTIONS] [DIR]
```

| Argument | |
|---|---|
| `<DIR>` | The drive's folder. Default: `.`. Environment: `TEIFS_DIR`. |
| `--apply` | Set right what can be: give data files back their versions, remove what was replaced since and upload folders of no upload. Without it, only report. |
| `--forget-missing` | Also forget versions whose data file is missing (their bytes are lost). |

## teifs alias

Name an S3 endpoint and its keys, to use as `NAME/BUCKET/KEY`.

```
teifs alias [OPTIONS] <COMMAND>
```

## teifs alias set

Add or replace an alias. The secret key is asked for (hidden) on a terminal, or read from standard input (`--secret-key-stdin`) or `TEIFS_SECRET_KEY`; never from the command line.

```
teifs alias set [OPTIONS] <NAME> <URL>
```

| Argument | |
|---|---|
| `<NAME>` | A short name: lowercase letters, digits, `-` and `_`. |
| `<URL>` | The endpoint, like `http://127.0.0.1:9000` or `https://s3.example.com`. |
| `--access-key <ACCESS_KEY>` | The access key (or `TEIFS_ACCESS_KEY`; asked for on a terminal). Environment: `TEIFS_ACCESS_KEY`. |
| `--secret-key-stdin` | Read the secret key from the first line of standard input. |
| `--drive <DRIVE>` | Use the keys of the TeiFS drive in this folder (from `.teifs/credentials.json`), whatever else sets keys. |
| `--region <REGION>` | The region to sign for. Default: `us-east-1`. |
| `--virtual-hosted` | Address buckets as host names (`bucket.host`), as AWS prefers, instead of as the first part of the path. |
| `--ca-cert <FILE>` | Trust this certificate authority (PEM) for the server besides the system's: for a certificate a private CA signed, or a self-signed one. |
| `--no-check` | Save it without checking that the endpoint and keys work. |

## teifs alias ls

List aliases (never their secret keys).

```
teifs alias ls [OPTIONS]
```

## teifs alias rm

Remove an alias.

```
teifs alias rm [OPTIONS] <NAME>
```

| Argument | |
|---|---|
| `<NAME>` | The alias's name. |

## teifs ls

List buckets (`ALIAS`) or objects (`ALIAS/BUCKET[/PREFIX]`).

```
teifs ls [OPTIONS] <TARGET>
```

| Argument | |
|---|---|
| `<TARGET>` | What to list. |
| `-r, --recursive` | Everything under the prefix, not just one level. |
| `--versions` | Every version and delete marker too, each key's newest first. |

## teifs mb

Make a bucket.

```
teifs mb [OPTIONS] <TARGET>
```

| Argument | |
|---|---|
| `<TARGET>` | `ALIAS/BUCKET`. |
| `--layout <LAYOUT>` | On TeiFS, how it stores objects: `object` (any key S3 allows) or `folder` (plain files). Other servers ignore it. One of `object`, `folder`. |
| `--ignore-existing` | Succeed if the bucket is already there and yours. |
| `--with-lock` | With Object Lock, so objects can be kept from deletion for a time or until released (this turns versioning on for good). |

## teifs rb

Remove a bucket.

```
teifs rb [OPTIONS] <TARGET>
```

| Argument | |
|---|---|
| `<TARGET>` | `ALIAS/BUCKET`. |
| `--force` | Delete every object in it first. |

## teifs cp

Copy files and objects: local to S3, S3 to local, or S3 to S3.

A destination ending in `/` (or a bucket, or a local folder) takes each source's name. With `-r`, a folder's contents go under the destination, as `aws s3 cp --recursive` does. Large files go in parallel parts, and an interrupted upload resumes when the same copy runs again.

```
teifs cp [OPTIONS] <PATHS> <PATHS>...
```

| Argument | |
|---|---|
| `<PATHS>` | What to copy, then where to (the last one). `-` is standard input (`tar c dir \| teifs cp - home/b/dir.tar`) or output (`teifs cp home/b/dir.tar - \| tar x`). |
| `-r, --recursive` | Copy folders and key prefixes with everything in them. |
| `--version-id <VERSION_ID>` | Copy this version of the source (one object) instead of its current one. |
| `--parallel <PARALLEL>` | Requests at once, across files and their parts. Default: `8`. |
| `--part-size <PART_SIZE>` | Files larger than this go in parts of this size (at least 5 MiB; larger when a file needs more than 10,000 parts). A size in bytes or with KiB, MiB or GiB. Default: `8MiB`. |
| `--enc-s3 <PREFIX>` | Encrypt what's written under `ALIAS/BUCKET[/PREFIX]` with SSE-S3 (repeatable). |
| `--enc-kms <PREFIX=KEY>` | Encrypt what's written under a prefix with a KMS key (repeatable). |
| `--enc-dsse <PREFIX=KEY>` | Encrypt what's written under a prefix twice (DSSE-KMS), with a KMS key and a key the server keeps (repeatable). |
| `--enc-c <PREFIX=FILE>` | Read and write objects under a prefix with a customer key (SSE-C) from a file: 32 bytes, or base64 or hex (repeatable). `TEIFS_ENC_C` takes `PREFIX=KEY,…`. |

## teifs mv

Move files and objects: copy, then delete each source once it's copied.

```
teifs mv [OPTIONS] <PATHS> <PATHS>...
```

| Argument | |
|---|---|
| `<PATHS>` | What to copy, then where to (the last one). `-` is standard input (`tar c dir \| teifs cp - home/b/dir.tar`) or output (`teifs cp home/b/dir.tar - \| tar x`). |
| `-r, --recursive` | Copy folders and key prefixes with everything in them. |
| `--version-id <VERSION_ID>` | Copy this version of the source (one object) instead of its current one. |
| `--parallel <PARALLEL>` | Requests at once, across files and their parts. Default: `8`. |
| `--part-size <PART_SIZE>` | Files larger than this go in parts of this size (at least 5 MiB; larger when a file needs more than 10,000 parts). A size in bytes or with KiB, MiB or GiB. Default: `8MiB`. |
| `--enc-s3 <PREFIX>` | Encrypt what's written under `ALIAS/BUCKET[/PREFIX]` with SSE-S3 (repeatable). |
| `--enc-kms <PREFIX=KEY>` | Encrypt what's written under a prefix with a KMS key (repeatable). |
| `--enc-dsse <PREFIX=KEY>` | Encrypt what's written under a prefix twice (DSSE-KMS), with a KMS key and a key the server keeps (repeatable). |
| `--enc-c <PREFIX=FILE>` | Read and write objects under a prefix with a customer key (SSE-C) from a file: 32 bytes, or base64 or hex (repeatable). `TEIFS_ENC_C` takes `PREFIX=KEY,…`. |

## teifs rm

Delete objects.

```
teifs rm [OPTIONS] <TARGETS>...
```

| Argument | |
|---|---|
| `<TARGETS>` | `ALIAS/BUCKET/KEY`, one or more. |
| `-r, --recursive` | Everything under each key prefix. |
| `--force` | With `--recursive` or `--versions`, delete without asking (as `--yes` does). |
| `--version-id <VERSION_ID>` | Remove this version of the key for good, instead of deleting the key (which, in a bucket with versioning, only adds a delete marker). |
| `--versions` | Remove every version and delete marker of the key for good (with `--recursive`, of every key under it). Asks first, unless `--force`. |
| `--bypass` | With `--version-id` or `--versions`: remove versions that a governance-mode retention keeps (needs `s3:BypassGovernanceRetention`). |

## teifs cat

Print objects to standard output.

```
teifs cat [OPTIONS] <TARGETS>...
```

| Argument | |
|---|---|
| `<TARGETS>` | `ALIAS/BUCKET/KEY`, one or more. |
| `--version-id <VERSION_ID>` | Print this version of the object instead of the current one. |
| `--enc-c <PREFIX=FILE>` | Read objects under `ALIAS/BUCKET[/PREFIX]` with a customer key (SSE-C) from a file: 32 bytes, or base64 or hex (repeatable). `TEIFS_ENC_C` takes `PREFIX=KEY,…`. |

## teifs stat

Show an object's or a bucket's details.

```
teifs stat [OPTIONS] <TARGET>
```

| Argument | |
|---|---|
| `<TARGET>` | `ALIAS/BUCKET[/KEY]`. |
| `--version-id <VERSION_ID>` | Show this version of the object instead of the current one. |
| `--enc-c <PREFIX=FILE>` | Read objects under `ALIAS/BUCKET[/PREFIX]` with a customer key (SSE-C) from a file: 32 bytes, or base64 or hex (repeatable). `TEIFS_ENC_C` takes `PREFIX=KEY,…`. |

## teifs version

Turn a bucket's versioning on, suspend it, or show it.

```
teifs version [OPTIONS] <COMMAND>
```

## teifs version enable

Keep every version: writes add one, deletes add a delete marker.

```
teifs version enable [OPTIONS] <TARGET>
```

| Argument | |
|---|---|
| `<TARGET>` | `ALIAS/BUCKET`. |

## teifs version suspend

Stop adding versions: writes and deletes replace the `null` version, and the versions kept so far stay. Versioning never goes back to off.

```
teifs version suspend [OPTIONS] <TARGET>
```

| Argument | |
|---|---|
| `<TARGET>` | `ALIAS/BUCKET`. |

## teifs version info

Show whether versioning is on, suspended, or was never turned on.

```
teifs version info [OPTIONS] <TARGET>
```

| Argument | |
|---|---|
| `<TARGET>` | `ALIAS/BUCKET`. |

## teifs retention

Keep objects from deletion until a date (Object Lock retention), or set a bucket's default retention.

```
teifs retention [OPTIONS] <COMMAND>
```

## teifs retention set

Keep objects for a time: governance (only those allowed to bypass it may remove them early) or compliance (nobody may). With `--default`, what new objects in the bucket get.

```
teifs retention set [OPTIONS] <MODE> <VALIDITY> <TARGET>
```

| Argument | |
|---|---|
| `<MODE>` | `governance` or `compliance`. One of `governance`, `compliance`. |
| `<VALIDITY>` | For how long, from now: days or years, like `30d` or `1y`. |
| `<TARGET>` | `ALIAS/BUCKET/KEY` (with `-r`, a prefix). |
| `--version-id <VERSION_ID>` | A version of the object instead of the current one. |
| `-r, --recursive` | Every object under the prefix (their current versions). |
| `--default` | The bucket's default retention instead (give `ALIAS/BUCKET`). |
| `--bypass` | Shorten or remove a governance-mode retention, or make it compliance (needs `s3:BypassGovernanceRetention`). |

## teifs retention clear

Remove objects' retention (a governance one needs `--bypass`; a compliance one can't be removed), or with `--default`, the bucket's default.

```
teifs retention clear [OPTIONS] <TARGET>
```

| Argument | |
|---|---|
| `<TARGET>` | `ALIAS/BUCKET/KEY` (with `-r`, a prefix). |
| `--version-id <VERSION_ID>` | A version of the object instead of the current one. |
| `-r, --recursive` | Every object under the prefix (their current versions). |
| `--default` | The bucket's default retention instead (give `ALIAS/BUCKET`). |
| `--bypass` | Shorten or remove a governance-mode retention, or make it compliance (needs `s3:BypassGovernanceRetention`). |

## teifs retention info

Show an object's retention, or with `--default`, the bucket's Object Lock.

```
teifs retention info [OPTIONS] <TARGET>
```

| Argument | |
|---|---|
| `<TARGET>` | `ALIAS/BUCKET/KEY` (`ALIAS/BUCKET` with `--default`). |
| `--default` | The bucket's default retention instead. |
| `--version-id <VERSION_ID>` | A version of the object instead of the current one. |

## teifs legalhold

Keep objects from deletion until released (an Object Lock legal hold).

```
teifs legalhold [OPTIONS] <COMMAND>
```

## teifs legalhold set

Place a legal hold: nobody may remove the object until it's lifted.

```
teifs legalhold set [OPTIONS] <TARGET>
```

| Argument | |
|---|---|
| `<TARGET>` | `ALIAS/BUCKET/KEY` (with `-r`, a prefix). |
| `--version-id <VERSION_ID>` | A version of the object instead of the current one. |
| `-r, --recursive` | Every object under the prefix (their current versions). |

## teifs legalhold clear

Lift a legal hold.

```
teifs legalhold clear [OPTIONS] <TARGET>
```

| Argument | |
|---|---|
| `<TARGET>` | `ALIAS/BUCKET/KEY` (with `-r`, a prefix). |
| `--version-id <VERSION_ID>` | A version of the object instead of the current one. |
| `-r, --recursive` | Every object under the prefix (their current versions). |

## teifs legalhold info

Show whether an object is under a legal hold.

```
teifs legalhold info [OPTIONS] <TARGET>
```

| Argument | |
|---|---|
| `<TARGET>` | `ALIAS/BUCKET/KEY`. |
| `--version-id <VERSION_ID>` | A version of the object instead of the current one. |

## teifs ilm

Expire objects and old versions, and abort old uploads, by a bucket's lifecycle rules.

```
teifs ilm [OPTIONS] <COMMAND>
```

## teifs ilm rule

Add, change, list, remove, export or import a bucket's lifecycle rules.

```
teifs ilm rule [OPTIONS] <COMMAND>
```

## teifs ilm rule add

Add a rule.

```
teifs ilm rule add [OPTIONS] <TARGET>
```

| Argument | |
|---|---|
| `<TARGET>` | `ALIAS/BUCKET`. |
| `--id <ID>` | The rule's name (made up when not given). |
| `--prefix <PREFIX>` | Only keys starting with this. |
| `--tags <TAGS>` | Only objects with these tags: `key=value&key2=value2`. |
| `--size-gt <SIZE_GT>` | Only objects larger than this (bytes, or with KiB, MiB or GiB). |
| `--size-lt <SIZE_LT>` | Only objects smaller than this. |
| `--expire-days <EXPIRE_DAYS>` | Expire objects this many days after they're written. |
| `--expire-date <EXPIRE_DATE>` | Expire objects from this day on (`YYYY-MM-DD`, UTC). |
| `--expire-delete-marker` | Remove delete markers left with no versions behind them. |
| `--noncurrent-expire-days <NONCURRENT_EXPIRE_DAYS>` | Remove versions this many days after they stop being current. |
| `--noncurrent-expire-newer <NONCURRENT_EXPIRE_NEWER>` | Keep this many of the newest noncurrent versions of each object (1 to 100). |
| `--abort-uploads-days <ABORT_UPLOADS_DAYS>` | Abort uploads this many days after they start. |
| `--transition-days <TRANSITION_DAYS>` | Move objects to `--transition-tier` this many days after they're written. |
| `--transition-date <TRANSITION_DATE>` | Move objects to `--transition-tier` from this day on. |
| `--transition-tier <TRANSITION_TIER>` | The storage class objects move to. |
| `--noncurrent-transition-days <NONCURRENT_TRANSITION_DAYS>` | Move versions to `--noncurrent-transition-tier` this many days after they stop being current. |
| `--noncurrent-transition-newer <NONCURRENT_TRANSITION_NEWER>` | Leave this many of the newest noncurrent versions where they are. |
| `--noncurrent-transition-tier <NONCURRENT_TRANSITION_TIER>` | The storage class noncurrent versions move to. |
| `--disable` | Add it turned off. |

## teifs ilm rule edit

Change a rule: what's given replaces what it had, the rest stays.

```
teifs ilm rule edit [OPTIONS] --id <ID> <TARGET>
```

| Argument | |
|---|---|
| `<TARGET>` | `ALIAS/BUCKET`. |
| `--id <ID>` | The rule to change. |
| `--prefix <PREFIX>` | Only keys starting with this. |
| `--tags <TAGS>` | Only objects with these tags: `key=value&key2=value2`. |
| `--size-gt <SIZE_GT>` | Only objects larger than this (bytes, or with KiB, MiB or GiB). |
| `--size-lt <SIZE_LT>` | Only objects smaller than this. |
| `--expire-days <EXPIRE_DAYS>` | Expire objects this many days after they're written. |
| `--expire-date <EXPIRE_DATE>` | Expire objects from this day on (`YYYY-MM-DD`, UTC). |
| `--expire-delete-marker` | Remove delete markers left with no versions behind them. |
| `--noncurrent-expire-days <NONCURRENT_EXPIRE_DAYS>` | Remove versions this many days after they stop being current. |
| `--noncurrent-expire-newer <NONCURRENT_EXPIRE_NEWER>` | Keep this many of the newest noncurrent versions of each object (1 to 100). |
| `--abort-uploads-days <ABORT_UPLOADS_DAYS>` | Abort uploads this many days after they start. |
| `--transition-days <TRANSITION_DAYS>` | Move objects to `--transition-tier` this many days after they're written. |
| `--transition-date <TRANSITION_DATE>` | Move objects to `--transition-tier` from this day on. |
| `--transition-tier <TRANSITION_TIER>` | The storage class objects move to. |
| `--noncurrent-transition-days <NONCURRENT_TRANSITION_DAYS>` | Move versions to `--noncurrent-transition-tier` this many days after they stop being current. |
| `--noncurrent-transition-newer <NONCURRENT_TRANSITION_NEWER>` | Leave this many of the newest noncurrent versions where they are. |
| `--noncurrent-transition-tier <NONCURRENT_TRANSITION_TIER>` | The storage class noncurrent versions move to. |
| `--enable` | Turn it on. |
| `--disable` | Turn it off. |

## teifs ilm rule ls

List a bucket's rules.

```
teifs ilm rule ls [OPTIONS] <TARGET>
```

| Argument | |
|---|---|
| `<TARGET>` | `ALIAS/BUCKET`. |

## teifs ilm rule rm

Remove a rule, or all of them.

```
teifs ilm rule rm [OPTIONS] <TARGET>
```

| Argument | |
|---|---|
| `<TARGET>` | `ALIAS/BUCKET`. |
| `--id <ID>` | The rule to remove. |
| `--all` | Every rule of the bucket. |
| `--force` | Remove them all without asking. |

## teifs ilm rule export

Print a bucket's rules as JSON, as AWS gives them.

```
teifs ilm rule export [OPTIONS] <TARGET>
```

| Argument | |
|---|---|
| `<TARGET>` | `ALIAS/BUCKET`. |

## teifs ilm rule import

Replace a bucket's rules with JSON read from standard input (as `export` prints it).

```
teifs ilm rule import [OPTIONS] <TARGET>
```

| Argument | |
|---|---|
| `<TARGET>` | `ALIAS/BUCKET`. |

## teifs encrypt

Choose how a bucket encrypts new objects (SSE-S3 or SSE-KMS) and whether it takes customer keys (SSE-C), or move objects to a KMS key in place.

```
teifs encrypt [OPTIONS] <COMMAND>
```

## teifs encrypt set

Set how a bucket encrypts new objects: `sse-s3 ALIAS/BUCKET`, or `sse-kms KEY ALIAS/BUCKET` for a KMS key (`dsse-kms` for two layers).

```
teifs encrypt set [OPTIONS] <MODE> <[KEY] ALIAS/BUCKET>...
```

| Argument | |
|---|---|
| `<MODE>` | `sse-s3` (keys the server keeps), `sse-kms` (a KMS key) or `dsse-kms` (two layers: a KMS key's and the server's). One of `sse-s3`, `sse-kms`, `dsse-kms`. |
| `<[KEY] ALIAS/BUCKET>` | The KMS key (for `sse-kms` and `dsse-kms` only), then `ALIAS/BUCKET`. |
| `--bucket-key` | Seal SSE-KMS objects' keys with an S3 Bucket Key. |
| `--block-sse-c` | Refuse writes with customer-provided keys (SSE-C). |
| `--allow-sse-c` | Take writes with customer-provided keys (SSE-C) again. |

## teifs encrypt clear

Go back to the default: SSE-S3.

```
teifs encrypt clear [OPTIONS] <TARGET>
```

| Argument | |
|---|---|
| `<TARGET>` | `ALIAS/BUCKET`. |

## teifs encrypt info

Show how a bucket encrypts new objects.

```
teifs encrypt info [OPTIONS] <TARGET>
```

| Argument | |
|---|---|
| `<TARGET>` | `ALIAS/BUCKET`. |

## teifs encrypt update

Move objects the server encrypts (SSE-S3 or SSE-KMS) to a KMS key, in place: their data, `ETag` and dates stay as they are.

```
teifs encrypt update [OPTIONS] --kms-key <KEY> <TARGET>
```

| Argument | |
|---|---|
| `<TARGET>` | `ALIAS/BUCKET/KEY` (with `-r`, a prefix). |
| `--version-id <VERSION_ID>` | A version of the object instead of the current one. |
| `-r, --recursive` | Every object under the prefix (their current versions). |
| `--kms-key <KEY>` | The KMS key: its name, or its ARN. |
| `--bucket-key` | Seal the objects' keys with an S3 Bucket Key. |

## teifs logging

Deliver a record of every request on a bucket, in S3's server access log format, into another bucket (or itself), or show where they go.

```
teifs logging [OPTIONS] <COMMAND>
```

## teifs logging set

Log `ALIAS/BUCKET`'s requests into `ALIAS/TARGET[/PREFIX]`, letting the logging service into the target with a statement in its bucket policy (as the S3 console does).

```
teifs logging set [OPTIONS] <SOURCE> <TARGET>
```

| Argument | |
|---|---|
| `<SOURCE>` | `ALIAS/BUCKET`: the bucket whose requests are logged. |
| `<TARGET>` | `ALIAS/TARGET[/PREFIX]`: where log objects go, their keys starting with PREFIX (end it with `/` for a folder). |
| `--format <FORMAT>` | How log objects are named: `simple` (`PREFIX` + date and time), or partitioned by account, region, bucket and the records' day (`event-time`) or the delivery's (`delivery-time`). One of `simple`, `event-time`, `delivery-time`. Default: `simple`. |
| `--no-policy` | Leave the target's bucket policy alone (it lets the service in already, or its ACL grants the log delivery group WRITE). |

## teifs logging info

Show where a bucket's access log goes.

```
teifs logging info [OPTIONS] <BUCKET>
```

| Argument | |
|---|---|
| `<BUCKET>` | `ALIAS/BUCKET`. |

## teifs logging rm

Stop logging a bucket's requests.

```
teifs logging rm [OPTIONS] <BUCKET>
```

| Argument | |
|---|---|
| `<BUCKET>` | `ALIAS/BUCKET`. |

## teifs inventory

Report a bucket's objects daily or weekly into another bucket (or itself), as S3 Inventory does: add, list, show or remove its inventory configurations.

```
teifs inventory [OPTIONS] <COMMAND>
```

## teifs inventory add

Report `ALIAS/BUCKET`'s objects daily (or weekly) into `ALIAS/DESTINATION[/PREFIX]` as S3 Inventory does: gzipped CSV files with a manifest. Replaces the bucket's configuration of the same id.

```
teifs inventory add [OPTIONS] <SOURCE> <ID> <DESTINATION>
```

| Argument | |
|---|---|
| `<SOURCE>` | `ALIAS/BUCKET`: the bucket whose objects are reported. |
| `<ID>` | The configuration's id. |
| `<DESTINATION>` | `ALIAS/DESTINATION[/PREFIX]`: where reports go, their keys starting with `PREFIX/BUCKET/ID/`. |
| `--prefix <PREFIX>` | Only objects whose keys start with this. |
| `--all-versions` | Every version and delete marker, not only current objects. |
| `--weekly` | Once a week (on Sundays, UTC) instead of every day. |
| `--format <FORMAT>` | The files' format: gzipped `csv`, `orc` or `parquet`. One of `csv`, `orc`, `parquet`. Default: `csv`. |
| `--fields <FIELDS>` | The optional fields, comma-separated, as S3 names them (`Size`, `ETag`, `LastModifiedDate`, `StorageClass`, `EncryptionStatus`…), or `all`. |
| `--encrypt <ENCRYPT>` | Encrypt reports with SSE-S3, or with SSE-KMS and this key (`sse-s3` or a KMS key); otherwise the destination's default. |
| `--disabled` | Keep the configuration without making reports. |
| `--no-policy` | Leave the destination's bucket policy alone (it lets S3 Inventory in already). |

## teifs inventory ls

List a bucket's inventory configurations.

```
teifs inventory ls [OPTIONS] <BUCKET>
```

| Argument | |
|---|---|
| `<BUCKET>` | `ALIAS/BUCKET`. |

## teifs inventory info

Show one of a bucket's inventory configurations.

```
teifs inventory info [OPTIONS] <BUCKET> <ID>
```

| Argument | |
|---|---|
| `<BUCKET>` | `ALIAS/BUCKET`. |
| `<ID>` | The configuration's id. |

## teifs inventory run

Make one of a bucket's inventory reports now, whatever its schedule (even when disabled), and say where it went. The schedule doesn't move.

```
teifs inventory run [OPTIONS] <BUCKET> <ID>
```

| Argument | |
|---|---|
| `<BUCKET>` | `ALIAS/BUCKET`. |
| `<ID>` | The configuration's id. |

## teifs inventory rm

Remove one of a bucket's inventory configurations.

```
teifs inventory rm [OPTIONS] <BUCKET> <ID>
```

| Argument | |
|---|---|
| `<BUCKET>` | `ALIAS/BUCKET`. |
| `<ID>` | The configuration's id. |

## teifs metrics

Count a bucket's requests as S3's request metrics do (`CloudWatch`'s names, served as Prometheus metrics): add, list, show or remove its metrics configurations.

```
teifs metrics [OPTIONS] <COMMAND>
```

## teifs metrics add

Count `ALIAS/BUCKET`'s requests (only those on objects matching `--prefix` and `--tag`, when given) under `ID`. Replaces the bucket's configuration of the same id.

```
teifs metrics add [OPTIONS] <BUCKET> <ID>
```

| Argument | |
|---|---|
| `<BUCKET>` | `ALIAS/BUCKET`. |
| `<ID>` | The configuration's id: the `filter_id` its metrics are labeled with. |
| `--prefix <PREFIX>` | Only requests on objects whose keys start with this. |
| `--tag <TAGS>` | Only requests on objects with this tag, as `KEY=VALUE`; repeat for several. |

## teifs metrics ls

List a bucket's metrics configurations.

```
teifs metrics ls [OPTIONS] <BUCKET>
```

| Argument | |
|---|---|
| `<BUCKET>` | `ALIAS/BUCKET`. |

## teifs metrics info

Show one of a bucket's metrics configurations.

```
teifs metrics info [OPTIONS] <BUCKET> <ID>
```

| Argument | |
|---|---|
| `<BUCKET>` | `ALIAS/BUCKET`. |
| `<ID>` | The configuration's id. |

## teifs metrics rm

Remove one of a bucket's metrics configurations.

```
teifs metrics rm [OPTIONS] <BUCKET> <ID>
```

| Argument | |
|---|---|
| `<BUCKET>` | `ALIAS/BUCKET`. |
| `<ID>` | The configuration's id. |

## teifs analytics

Analyse how a bucket's objects are read by age, as S3's storage class analysis does, exporting each day's figures as CSV into another bucket (or itself): add, list, show or remove its analytics configurations.

```
teifs analytics [OPTIONS] <COMMAND>
```

## teifs analytics add

Analyse `ALIAS/BUCKET`'s objects (only those matching `--prefix` and `--tag`, when given) under `ID`, exporting each day's figures with `--export`. Replaces the bucket's configuration of the same id.

```
teifs analytics add [OPTIONS] <BUCKET> <ID>
```

| Argument | |
|---|---|
| `<BUCKET>` | `ALIAS/BUCKET`. |
| `<ID>` | The configuration's id: the `ConfigId` of its rows. |
| `--prefix <PREFIX>` | Only objects whose keys start with this. |
| `--tag <TAGS>` | Only objects with this tag, as `KEY=VALUE`; repeat for several. |
| `--export <EXPORT>` | `ALIAS/DESTINATION[/PREFIX]`: where the daily CSV goes, as `PREFIX/BUCKET/ID.csv`. |
| `--no-policy` | Leave the destination's bucket policy alone (it lets S3 in already). |

## teifs analytics ls

List a bucket's analytics configurations.

```
teifs analytics ls [OPTIONS] <BUCKET>
```

| Argument | |
|---|---|
| `<BUCKET>` | `ALIAS/BUCKET`. |

## teifs analytics info

Show one of a bucket's analytics configurations.

```
teifs analytics info [OPTIONS] <BUCKET> <ID>
```

| Argument | |
|---|---|
| `<BUCKET>` | `ALIAS/BUCKET`. |
| `<ID>` | The configuration's id. |

## teifs analytics rm

Remove one of a bucket's analytics configurations.

```
teifs analytics rm [OPTIONS] <BUCKET> <ID>
```

| Argument | |
|---|---|
| `<BUCKET>` | `ALIAS/BUCKET`. |
| `<ID>` | The configuration's id. |

## teifs tiering

Keep S3 Intelligent-Tiering's archive settings for a bucket's objects: add, list, show or remove its Intelligent-Tiering configurations (every object stays `STANDARD`).

```
teifs tiering [OPTIONS] <COMMAND>
```

## teifs tiering add

Archive `ALIAS/BUCKET`'s objects (only those matching `--prefix` and `--tag`, when given) after days without access, as S3 Intelligent-Tiering's archive tiers do. Replaces the bucket's configuration of the same id.

```
teifs tiering add [OPTIONS] <--archive-days <ARCHIVE_DAYS>|--deep-archive-days <DEEP_ARCHIVE_DAYS>> <BUCKET> <ID>
```

| Argument | |
|---|---|
| `<BUCKET>` | `ALIAS/BUCKET`. |
| `<ID>` | The configuration's id. |
| `--prefix <PREFIX>` | Only objects whose keys start with this. |
| `--tag <TAGS>` | Only objects with this tag, as `KEY=VALUE`; repeat for several. |
| `--archive-days <ARCHIVE_DAYS>` | Days without access before the Archive Access tier (90 to 730). |
| `--deep-archive-days <DEEP_ARCHIVE_DAYS>` | Days without access before the Deep Archive Access tier (180 to 730). |
| `--disabled` | Keep the configuration without it applying. |

## teifs tiering ls

List a bucket's Intelligent-Tiering configurations.

```
teifs tiering ls [OPTIONS] <BUCKET>
```

| Argument | |
|---|---|
| `<BUCKET>` | `ALIAS/BUCKET`. |

## teifs tiering info

Show one of a bucket's Intelligent-Tiering configurations.

```
teifs tiering info [OPTIONS] <BUCKET> <ID>
```

| Argument | |
|---|---|
| `<BUCKET>` | `ALIAS/BUCKET`. |
| `<ID>` | The configuration's id. |

## teifs tiering rm

Remove one of a bucket's Intelligent-Tiering configurations.

```
teifs tiering rm [OPTIONS] <BUCKET> <ID>
```

| Argument | |
|---|---|
| `<BUCKET>` | `ALIAS/BUCKET`. |
| `<ID>` | The configuration's id. |

## teifs requester-pays

Make requesters pay for a bucket (S3's Requester Pays): anonymous requests are refused; or show who pays.

```
teifs requester-pays [OPTIONS] <COMMAND>
```

## teifs requester-pays enable

Make requesters pay: anonymous requests are refused.

```
teifs requester-pays enable [OPTIONS] <BUCKET>
```

| Argument | |
|---|---|
| `<BUCKET>` | `ALIAS/BUCKET`. |

## teifs requester-pays disable

Make the bucket's owner pay again.

```
teifs requester-pays disable [OPTIONS] <BUCKET>
```

| Argument | |
|---|---|
| `<BUCKET>` | `ALIAS/BUCKET`. |

## teifs requester-pays info

Show who pays.

```
teifs requester-pays info [OPTIONS] <BUCKET>
```

| Argument | |
|---|---|
| `<BUCKET>` | `ALIAS/BUCKET`. |

## teifs website

Serve a bucket as a static website (its index and error documents and redirects, as S3's website hosting), or show or remove its configuration.

```
teifs website [OPTIONS] <COMMAND>
```

## teifs website set

Make `ALIAS/BUCKET` a website: requests for a folder get its index document, errors the error document; or, with `--redirect-all`, send every request elsewhere.

```
teifs website set [OPTIONS] <BUCKET>
```

| Argument | |
|---|---|
| `<BUCKET>` | `ALIAS/BUCKET`. |
| `--index <INDEX>` | What a request for a folder (`/`, `docs/`) is answered with: the folder's object of this name. Default: `index.html`. |
| `--error <ERROR>` | The object answered, with the error's status, when a request fails. |
| `--rules <RULES>` | A JSON file of redirection rules, as the S3 console takes them (`[{"Condition": {"KeyPrefixEquals": "docs/"}, "Redirect": {"ReplaceKeyPrefixWith": "documents/"}}]`). |
| `--redirect-all <REDIRECT_ALL>` | Send every request to this host (`example.com`, or `https://example.com` for a protocol). |

## teifs website info

Show a bucket's website configuration.

```
teifs website info [OPTIONS] <BUCKET>
```

| Argument | |
|---|---|
| `<BUCKET>` | `ALIAS/BUCKET`. |

## teifs website rm

Stop serving a bucket as a website.

```
teifs website rm [OPTIONS] <BUCKET>
```

| Argument | |
|---|---|
| `<BUCKET>` | `ALIAS/BUCKET`. |

## teifs quota

Limit how much a bucket may hold (`MinIO`'s hard quota, as `mc quota` sets it): writes that would reach it are refused.

```
teifs quota [OPTIONS] <COMMAND>
```

## teifs quota set

Let `ALIAS/BUCKET` hold at most `--size`: a write that would reach it is refused.

```
teifs quota set [OPTIONS] --size <SIZE> <BUCKET>
```

| Argument | |
|---|---|
| `<BUCKET>` | `ALIAS/BUCKET`. |
| `--size <SIZE>` | The most it may hold: bytes, or with KiB, MiB, GiB or TiB. |

## teifs quota info

Show a bucket's quota.

```
teifs quota info [OPTIONS] <BUCKET>
```

| Argument | |
|---|---|
| `<BUCKET>` | `ALIAS/BUCKET`. |

## teifs quota clear

Remove a bucket's quota.

```
teifs quota clear [OPTIONS] <BUCKET>
```

| Argument | |
|---|---|
| `<BUCKET>` | `ALIAS/BUCKET`. |

## teifs presign

Make a link that gets (or, with `--put`, uploads) an object without keys.

```
teifs presign [OPTIONS] <TARGET>
```

| Argument | |
|---|---|
| `<TARGET>` | `ALIAS/BUCKET/KEY`. |
| `--expires <EXPIRES>` | How long the link works: up to 7d. Default: `1h`. |
| `--put` | A link for uploading the object instead. |
| `--max-size <MAX_SIZE>` | The most the upload may be (with `--put`): bytes, or with KiB, MiB or GiB. The limit is part of the link's signature, so it can't be raised or removed. |

## teifs mirror

Make a folder or a key prefix the same as another: copy what's new or changed, and (with `--remove`) delete what's gone.

```
teifs mirror [OPTIONS] <SOURCE> <DESTINATION>
```

| Argument | |
|---|---|
| `<SOURCE>` | A local folder or `ALIAS/BUCKET[/PREFIX]`. |
| `<DESTINATION>` | A local folder or `ALIAS/BUCKET[/PREFIX]`. |
| `--remove` | Delete what's in the destination but not the source. |
| `--dry-run` | Show what would change, and change nothing. |
| `--parallel <PARALLEL>` | Requests at once, across files and their parts. Default: `8`. |
| `--part-size <PART_SIZE>` | Files larger than this go in parts of this size (at least 5 MiB; larger when a file needs more than 10,000 parts). A size in bytes or with KiB, MiB or GiB. Default: `8MiB`. |
| `--enc-s3 <PREFIX>` | Encrypt what's written under `ALIAS/BUCKET[/PREFIX]` with SSE-S3 (repeatable). |
| `--enc-kms <PREFIX=KEY>` | Encrypt what's written under a prefix with a KMS key (repeatable). |
| `--enc-dsse <PREFIX=KEY>` | Encrypt what's written under a prefix twice (DSSE-KMS), with a KMS key and a key the server keeps (repeatable). |
| `--enc-c <PREFIX=FILE>` | Read and write objects under a prefix with a customer key (SSE-C) from a file: 32 bytes, or base64 or hex (repeatable). `TEIFS_ENC_C` takes `PREFIX=KEY,…`. |

## teifs migrate

Move buckets from any S3 service to another (MinIO, AWS or RustFS to TeiFS, say): every version and delete marker in order, each object's headers, metadata, tags, retention and legal hold with the same ETag, and the buckets' settings. Only what the destination lacks is copied, so running it again carries on where it stopped.

```
teifs migrate [OPTIONS] <SOURCE> <DESTINATION>
```

| Argument | |
|---|---|
| `<SOURCE>` | `ALIAS` (every bucket) or `ALIAS/BUCKET[/PREFIX]`. |
| `<DESTINATION>` | `ALIAS` (the same bucket names) or `ALIAS/BUCKET[/PREFIX]`. |
| `--latest` | Copy only the current objects, not every version. |
| `--dry-run` | Show what would be copied, and change nothing. |
| `--size-only` | Tell objects apart by size alone, not by ETag as well (for services whose ETags aren't MD5s, such as for objects encrypted with KMS keys). |
| `--no-configs` | Don't copy the buckets' settings (versioning, policy, lifecycle…). |
| `--parallel <PARALLEL>` | Requests at once, across files and their parts. Default: `8`. |
| `--part-size <PART_SIZE>` | Files larger than this go in parts of this size (at least 5 MiB; larger when a file needs more than 10,000 parts). A size in bytes or with KiB, MiB or GiB. Default: `8MiB`. |

## teifs event

Send a bucket's events (objects written, read, deleted…) to the server's targets: add, list or remove its notification rules.

```
teifs event [OPTIONS] <COMMAND>
```

## teifs event add

Send a bucket's events to one of the server's targets (`teifs admin config` lists them).

```
teifs event add [OPTIONS] <TARGET> <ARN>
```

| Argument | |
|---|---|
| `<TARGET>` | `ALIAS/BUCKET`. |
| `<ARN>` | The target's ARN: `arn:teifs:sqs::ID:webhook` (or MinIO's `arn:minio:…`), or an AWS queue's, topic's or function's own ARN, as on S3. |
| `--event <EVENT>` | The events: `put`, `delete`, `get`, `ilm` (lifecycle expirations), or S3's names (`s3:ObjectCreated:Copy`), comma-separated. Default: `put,delete,get`. |
| `--prefix <PREFIX>` | Only keys starting with this. |
| `--suffix <SUFFIX>` | Only keys ending with this. |
| `--id <ID>` | The rule's id (the server makes one up when not given). |
| `--ignore-existing` | Succeed if the bucket already has this rule. |

## teifs event ls

List a bucket's rules, or those sending to one target.

```
teifs event ls [OPTIONS] <TARGET> [ARN]
```

| Argument | |
|---|---|
| `<TARGET>` | `ALIAS/BUCKET`. |
| `<ARN>` | Only the rules sending to this ARN. |

## teifs event rm

Remove a bucket's rules: one (`--id`), those sending to a target (its ARN), or all of them (`--all`).

```
teifs event rm [OPTIONS] <TARGET> [ARN]
```

| Argument | |
|---|---|
| `<TARGET>` | `ALIAS/BUCKET`. |
| `<ARN>` | Remove the rules sending to this ARN. |
| `--id <ID>` | The rule to remove. |
| `--all` | Every rule of the bucket. |
| `--force` | Remove them all without asking. |

## teifs event eventbridge

Send every event of a bucket to the server's EventBridge bus, as S3 does, or stop.

```
teifs event eventbridge [OPTIONS] <TARGET> <STATE>
```

| Argument | |
|---|---|
| `<TARGET>` | `ALIAS/BUCKET`. |
| `<STATE>` | `on` or `off`. One of `on`, `off`. |

## teifs watch

Show a bucket's events (or, for an alias, every bucket's) as they happen: objects written, read and deleted, until Ctrl-C.

```
teifs watch [OPTIONS] <TARGET>
```

| Argument | |
|---|---|
| `<TARGET>` | `ALIAS` for every bucket's events, or `ALIAS/BUCKET[/PREFIX]`. |
| `--events <EVENTS>` | The events: `put`, `delete`, `get`, `ilm` (lifecycle expirations), `bucket` (buckets created and removed), or S3's names (`s3:ObjectCreated:Copy`), comma-separated. Default: `put,delete,get`. |
| `--suffix <SUFFIX>` | Only keys ending with this. Default: ``. |

## teifs admin

Manage a TeiFS server through its admin API: its info and configuration, its IAM (export and import) and its root key.

```
teifs admin [OPTIONS] <COMMAND>
```

## teifs admin info

Show what a TeiFS server is and how it's doing: its version, drive, account, uptime, background jobs and what its scrubs found.

```
teifs admin info [OPTIONS] <ALIAS>
```

| Argument | |
|---|---|
| `<ALIAS>` | The server's alias. |

## teifs admin config

Show how a TeiFS server was started (never its secrets), or get and set the settings it keeps on its drive (as `mc admin config`).

```
teifs admin config [OPTIONS] <ALIAS>
       teifs admin config <COMMAND>
```

| Argument | |
|---|---|
| `<ALIAS>` | The server's alias. |

## teifs admin config get

Show a sub-system's settings (`identity_ldap`, `identity_openid[:NAME]`, `notify_webhook[:NAME]`…; every one without it), never their secrets.

```
teifs admin config get [OPTIONS] <ALIAS> [KEY]
```

| Argument | |
|---|---|
| `<ALIAS>` | The server's alias. |
| `<KEY>` | The sub-system, and its target after a colon. Default: ``. |

## teifs admin config set

Set a sub-system's keys: `identity_ldap server_addr=ldap.example.com:636 …`. Takes effect when the server starts again; a setting it wouldn't start with is refused.

```
teifs admin config set [OPTIONS] <ALIAS> <TARGET> <KEY=VALUE>...
```

| Argument | |
|---|---|
| `<ALIAS>` | The server's alias. |
| `<TARGET>` | The sub-system, and its target after a colon. |
| `<KEY=VALUE>` | The keys, as KEY=VALUE. |

## teifs admin config reset

Reset a sub-system's keys to their defaults, or all of a target's.

```
teifs admin config reset [OPTIONS] <ALIAS> <TARGET> [KEYS]...
```

| Argument | |
|---|---|
| `<ALIAS>` | The server's alias. |
| `<TARGET>` | The sub-system, and its target after a colon. |
| `<KEYS>` | The keys to reset; all of them without any. |

## teifs admin config keys

List the keys a sub-system takes (the sub-systems, without one).

```
teifs admin config keys [OPTIONS] <ALIAS> [SUBSYSTEM] [KEY]
```

| Argument | |
|---|---|
| `<ALIAS>` | The server's alias. |
| `<SUBSYSTEM>` | The sub-system. Default: ``. |
| `<KEY>` | Only this key. Default: ``. |
| `--env` | Name the keys by their environment variables. |

## teifs admin config history

List the newest changes, which `restore` puts back.

```
teifs admin config history [OPTIONS] <ALIAS>
```

| Argument | |
|---|---|
| `<ALIAS>` | The server's alias. |
| `--count <COUNT>` | How many (0 for all). Default: `10`. |

## teifs admin config restore

Set a change's keys again; the change leaves the history.

```
teifs admin config restore [OPTIONS] <ALIAS> <ID>
```

| Argument | |
|---|---|
| `<ALIAS>` | The server's alias. |
| `<ID>` | The change, as `history` lists it. |

## teifs admin config clear-history

Forget a change, or every one with `all`.

```
teifs admin config clear-history [OPTIONS] <ALIAS> <ID>
```

| Argument | |
|---|---|
| `<ALIAS>` | The server's alias. |
| `<ID>` | The change, as `history` lists it, or `all`. |

## teifs admin config export

Write every setting, secrets included, to a file readable only by you.

```
teifs admin config export [OPTIONS] --output <OUTPUT> <ALIAS>
```

| Argument | |
|---|---|
| `<ALIAS>` | The server's alias. |
| `-o, --output <OUTPUT>` | The file to write. |
| `--force` | Replace the file if it exists. |

## teifs admin config import

Replace every setting with an export's.

```
teifs admin config import [OPTIONS] <ALIAS> <FILE>
```

| Argument | |
|---|---|
| `<ALIAS>` | The server's alias. |
| `<FILE>` | The export: a file, or `-` for standard input. |

## teifs admin iam

Export or import the account's IAM: users, groups, policies and access keys.

```
teifs admin iam [OPTIONS] <COMMAND>
```

## teifs admin iam export

Write the account's IAM as JSON, to standard output or a file.

```
teifs admin iam export [OPTIONS] <ALIAS>
```

| Argument | |
|---|---|
| `<ALIAS>` | The server's alias. |
| `-o, --output <OUTPUT>` | The file to write (owner-only); standard output without it. |
| `--secrets` | Include the access keys' secrets, so they keep working after an import (root user only; needs `--output`). |
| `--force` | Replace the file if it exists. |

## teifs admin iam import

Make an export in a server whose IAM is empty, all or nothing.

```
teifs admin iam import [OPTIONS] <ALIAS> <FILE>
```

| Argument | |
|---|---|
| `<ALIAS>` | The server's alias. |
| `<FILE>` | The export: a file, or `-` for standard input. |
| `--adopt-account` | Take the export's account id too, so ARNs in policies and elsewhere keep naming the same account. |

## teifs admin bucket

Export buckets with their settings, or import them onto another server (as `mc admin cluster bucket export|import`); objects aren't moved.

```
teifs admin bucket [OPTIONS] <COMMAND>
```

## teifs admin bucket export

Write every bucket's layout, versioning and settings (policy, lifecycle, Object Lock, encryption, CORS, tags, ACL, Block Public Access…) as JSON.

```
teifs admin bucket export [OPTIONS] <TARGET>
```

| Argument | |
|---|---|
| `<TARGET>` | The server's alias, or ALIAS/BUCKET for one bucket. |
| `-o, --output <OUTPUT>` | The file to write (owner-only); standard output without it. |
| `--force` | Replace the file if it exists. |

## teifs admin bucket import

Create an export's buckets where they're missing and apply their settings, each checked as S3 checks it. Exit code 1 when an item couldn't be applied.

```
teifs admin bucket import [OPTIONS] <ALIAS> <FILE>
```

| Argument | |
|---|---|
| `<ALIAS>` | The server's alias. |
| `<FILE>` | The export: a file, or `-` for standard input. |

## teifs admin snapshot

List a TeiFS server's snapshots of its drive's metadata, or take one now.

```
teifs admin snapshot [OPTIONS] <COMMAND>
```

## teifs admin snapshot ls

List the snapshots kept (in the drive's `.teifs/backups/auto/`), oldest first.

```
teifs admin snapshot ls [OPTIONS] <ALIAS>
```

| Argument | |
|---|---|
| `<ALIAS>` | The server's alias. |

## teifs admin snapshot take

Snapshot the drive's metadata (its buckets, settings, IAM and object index) now.

```
teifs admin snapshot take [OPTIONS] <ALIAS>
```

| Argument | |
|---|---|
| `<ALIAS>` | The server's alias. |

## teifs admin trace

Show each request a TeiFS server answers, as it answers it, until Ctrl-C (as `mc admin trace`): when, status, operation, bucket and key, client, time and bytes. `--json` prints each request's audit entry. Needs `teifs:ServerTrace`.

```
teifs admin trace [OPTIONS] <ALIAS>
```

| Argument | |
|---|---|
| `<ALIAS>` | The server's alias. |
| `-e, --errors` | Only errors: answers from 400 up. |
| `--api <NAME>` | Only this operation (`PutObject`, `GetObject`, `ListObjectsV2`…); repeat for more. |
| `--bucket <BUCKET>` | Only requests on this bucket. |
| `--prefix <PREFIX>` | Only requests on keys starting with this. |
| `--status <CODE>` | Only this HTTP status (`404`); repeat for more. |
| `--slower-than <TIME>` | Only requests that took at least this long (`250ms`, `2s`). |

## teifs admin prometheus

A Prometheus scrape configuration for a TeiFS server's metrics, with its token.

```
teifs admin prometheus [OPTIONS] <COMMAND>
```

## teifs admin prometheus generate

Print a scrape configuration for the server's metrics (`/.teifs/metrics`), with a bearer token signed by the alias's access key, whose policies need `teifs:GetMetrics`. Deleting or deactivating the key revokes the token.

```
teifs admin prometheus generate [OPTIONS] <ALIAS>
```

| Argument | |
|---|---|
| `<ALIAS>` | The server's alias. |
| `--expires <EXPIRES>` | How long the token is good for (`90d`); without it, until the key is revoked. |
| `--token-file <TOKEN_FILE>` | Write the token to this file (owner-only) and have the configuration read it from there (`credentials_file`) rather than hold it. |
| `--force` | Replace the token file if it exists. |
| `--buckets` | Scrape what each bucket holds too (`?buckets=1`): a series per bucket for each figure. |

## teifs admin service

Restart or stop a server, or hold its S3 requests for a while (as `mc admin service`).

```
teifs admin service [OPTIONS] <COMMAND>
```

## teifs admin service restart

Restart the server: it finishes what it's answering, then starts again as it was started (with a binary that was replaced, the new one). Needs `admin:ServiceRestart`.

```
teifs admin service restart [OPTIONS] <ALIAS>
```

| Argument | |
|---|---|
| `<ALIAS>` | The server's alias. |
| `--dry-run` | Only check the alias may restart it. |

## teifs admin service stop

Stop the server: it finishes what it's answering, then exits. Only whatever started it can start it again. Needs `admin:ServiceStop`.

```
teifs admin service stop [OPTIONS] <ALIAS>
```

| Argument | |
|---|---|
| `<ALIAS>` | The server's alias. |
| `--dry-run` | Only check the alias may stop it. |

## teifs admin service freeze

Hold the server's S3 requests (not its admin API's) until `unfreeze`: each freeze needs its own. A restart or stop lets them go. Needs `admin:ServiceFreeze`.

```
teifs admin service freeze [OPTIONS] <ALIAS>
```

| Argument | |
|---|---|
| `<ALIAS>` | The server's alias. |

## teifs admin service unfreeze

Undo a `freeze`. Needs `admin:ServiceFreeze`.

```
teifs admin service unfreeze [OPTIONS] <ALIAS>
```

| Argument | |
|---|---|
| `<ALIAS>` | The server's alias. |

## teifs admin kms

A server's KMS and its keys (as `mc admin kms`).

```
teifs admin kms [OPTIONS] <COMMAND>
```

## teifs admin kms status

The server's KMS: its kind, default key, and whether each endpoint answers. Needs `kms:Status`.

```
teifs admin kms status [OPTIONS] <ALIAS>
```

| Argument | |
|---|---|
| `<ALIAS>` | The server's alias. |

## teifs admin kms key

The server's KMS keys.

```
teifs admin kms key [OPTIONS] <COMMAND>
```

## teifs admin kms key create

Create a key, for SSE-KMS (`x-amz-server-side-encryption-aws-kms-key-id`). Needs `kms:CreateKey` on it (`arn:minio:kms:::NAME`).

```
teifs admin kms key create [OPTIONS] <ALIAS> <NAME>
```

| Argument | |
|---|---|
| `<ALIAS>` | The server's alias. |
| `<NAME>` | The key's name. |

## teifs admin kms key list

List the keys whose names start with PREFIX (all by default) that the alias may list. Needs `kms:ListKeys`.

```
teifs admin kms key list [OPTIONS] <ALIAS> [PREFIX]
```

| Argument | |
|---|---|
| `<ALIAS>` | The server's alias. |
| `<PREFIX>` | Only keys whose names start with this. Default: ``. |

## teifs admin kms key status

Check a key (the default key by default) seals a new data key and unseals it again. Needs `kms:KeyStatus` on it.

```
teifs admin kms key status [OPTIONS] <ALIAS> [NAME]
```

| Argument | |
|---|---|
| `<ALIAS>` | The server's alias. |
| `<NAME>` | The key's name. |

## teifs admin root-key

Replace the root key a TeiFS server's drive generated.

```
teifs admin root-key [OPTIONS] <COMMAND>
```

## teifs admin root-key rotate

Replace it: the old key stops working at once, the server's drive keeps the new one, and the alias is updated to use it.

```
teifs admin root-key rotate [OPTIONS] <ALIAS>
```

| Argument | |
|---|---|
| `<ALIAS>` | The server's alias, signing with the root key. |

## teifs admin user

Add, list and delete users, their access keys and policies.

```
teifs admin user [OPTIONS] <COMMAND>
```

## teifs admin user add

Add a user with a policy and an access key.

```
teifs admin user add [OPTIONS] --policy <POLICY> <--save-alias <ALIAS>|--output <FILE>> <ALIAS> <NAME>
```

| Argument | |
|---|---|
| `<ALIAS>` | The server's alias. |
| `<NAME>` | The user's name. |
| `--policy <POLICY>` | `readonly` (read and list), `readwrite` (all of S3), `admin` (everything: IAM and the admin API too), or a file with an IAM policy document. |
| `--bucket <BUCKET>` | Only this bucket, for `readonly` and `readwrite` (repeatable). |
| `--save-alias <ALIAS>` | Save it as a new alias of this name, for the same server. |
| `-o, --output <FILE>` | Write it to this file (readable only by you), or to standard output with `-`. |

## teifs admin user ls

List the users with their access keys and policies.

```
teifs admin user ls [OPTIONS] <ALIAS>
```

| Argument | |
|---|---|
| `<ALIAS>` | The server's alias. |

## teifs admin user rm

Delete a user with its access keys, policies and group memberships (asks first).

```
teifs admin user rm [OPTIONS] <ALIAS> <NAME>
```

| Argument | |
|---|---|
| `<ALIAS>` | The server's alias. |
| `<NAME>` | The user's name. |

## teifs admin user policy

Replace the policy `user add` gave a user.

```
teifs admin user policy [OPTIONS] --policy <POLICY> <ALIAS> <NAME>
```

| Argument | |
|---|---|
| `<ALIAS>` | The server's alias. |
| `<NAME>` | The user's name. |
| `--policy <POLICY>` | `readonly` (read and list), `readwrite` (all of S3), `admin` (everything: IAM and the admin API too), or a file with an IAM policy document. |
| `--bucket <BUCKET>` | Only this bucket, for `readonly` and `readwrite` (repeatable). |

## teifs admin user key

A user's access keys.

```
teifs admin user key [OPTIONS] <COMMAND>
```

## teifs admin user key add

Add an access key (a user has at most two).

```
teifs admin user key add [OPTIONS] <--save-alias <ALIAS>|--output <FILE>> <ALIAS> <NAME>
```

| Argument | |
|---|---|
| `<ALIAS>` | The server's alias. |
| `<NAME>` | The user's name. |
| `--save-alias <ALIAS>` | Save it as a new alias of this name, for the same server. |
| `-o, --output <FILE>` | Write it to this file (readable only by you), or to standard output with `-`. |

## teifs admin user key ls

List a user's access keys (never their secrets).

```
teifs admin user key ls [OPTIONS] <ALIAS> <NAME>
```

| Argument | |
|---|---|
| `<ALIAS>` | The server's alias. |
| `<NAME>` | The user's name. |

## teifs admin user key rm

Delete an access key: requests signed with it fail from now on.

```
teifs admin user key rm [OPTIONS] <ALIAS> <NAME> <KEY>
```

| Argument | |
|---|---|
| `<ALIAS>` | The server's alias. |
| `<NAME>` | The user's name. |
| `<KEY>` | The access key's id. |

## teifs admin role

Add, list and delete roles: whom they trust and what they may do.

```
teifs admin role [OPTIONS] <COMMAND>
```

## teifs admin role add

Add a role: whom it trusts and what it may do.

```
teifs admin role add [OPTIONS] --trust <TRUST> --policy <POLICY> <ALIAS> <NAME>
```

| Argument | |
|---|---|
| `<ALIAS>` | The server's alias. |
| `<NAME>` | The role's name. |
| `--trust <TRUST>` | `account` (the account's users and roles whose policies allow it), `user:NAME`, `github:OWNER/REPO[:SUBJECT]` (a GitHub Actions workflow: `github:acme/site`, or `github:acme/site:ref:refs/heads/main` for one branch), `oidc:HOST` (tokens of the account's OpenID Connect provider for HOST, with `--sub`), or a trust policy file. |
| `--sub <SUB>` | For `oidc:`, the subjects (`sub`) it trusts; `*` matches any characters. |
| `--aud <AUD>` | For `oidc:`, the audience (`aud`) tokens must be for, when the provider has more than one client id. |
| `--policy <POLICY>` | `readonly` (read and list), `readwrite` (all of S3), `admin` (everything: IAM and the admin API too), or a file with an IAM policy document. |
| `--bucket <BUCKET>` | Only this bucket, for `readonly` and `readwrite` (repeatable). |
| `--max-session <MAX_SESSION>` | The longest session it gives, from `1h` (the default) to `12h`. |
| `--description <DESCRIPTION>` | What it's for. |

## teifs admin role ls

List the roles with whom they trust and their policies.

```
teifs admin role ls [OPTIONS] <ALIAS>
```

| Argument | |
|---|---|
| `<ALIAS>` | The server's alias. |

## teifs admin role rm

Delete a role with its policies (asks first); its sessions stop working.

```
teifs admin role rm [OPTIONS] <ALIAS> <NAME>
```

| Argument | |
|---|---|
| `<ALIAS>` | The server's alias. |
| `<NAME>` | The role's name. |

## teifs admin role policy

Replace the policy `role add` gave a role.

```
teifs admin role policy [OPTIONS] --policy <POLICY> <ALIAS> <NAME>
```

| Argument | |
|---|---|
| `<ALIAS>` | The server's alias. |
| `<NAME>` | The role's name. |
| `--policy <POLICY>` | `readonly` (read and list), `readwrite` (all of S3), `admin` (everything: IAM and the admin API too), or a file with an IAM policy document. |
| `--bucket <BUCKET>` | Only this bucket, for `readonly` and `readwrite` (repeatable). |

## teifs admin role trust

Replace whom a role trusts.

```
teifs admin role trust [OPTIONS] --trust <TRUST> <ALIAS> <NAME>
```

| Argument | |
|---|---|
| `<ALIAS>` | The server's alias. |
| `<NAME>` | The role's name. |
| `--trust <TRUST>` | `account` (the account's users and roles whose policies allow it), `user:NAME`, `github:OWNER/REPO[:SUBJECT]` (a GitHub Actions workflow: `github:acme/site`, or `github:acme/site:ref:refs/heads/main` for one branch), `oidc:HOST` (tokens of the account's OpenID Connect provider for HOST, with `--sub`), or a trust policy file. |
| `--sub <SUB>` | For `oidc:`, the subjects (`sub`) it trusts; `*` matches any characters. |
| `--aud <AUD>` | For `oidc:`, the audience (`aud`) tokens must be for, when the provider has more than one client id. |

## teifs admin oidc

Add, list and delete OpenID Connect providers, whose tokens get credentials.

```
teifs admin oidc [OPTIONS] <COMMAND>
```

## teifs admin oidc add

Add a provider: the issuer URL its tokens name, and the audiences they may be for.

```
teifs admin oidc add [OPTIONS] --client-id <ID> <ALIAS> <URL>
```

| Argument | |
|---|---|
| `<ALIAS>` | The server's alias. |
| `<URL>` | The provider's URL, like `https://token.actions.githubusercontent.com`. |
| `--client-id <ID>` | An audience (`aud`) its tokens may be for (repeatable); GitHub Actions' for AWS is `sts.amazonaws.com`. |
| `--thumbprint <HEX>` | The SHA-1 thumbprint of a certificate to trust for it, when the system doesn't trust its certificate (repeatable). |
| `--policy-claim <CLAIM>` | Let its tokens name the account's managed policies in this claim (`policy` if not given), for credentials without a role, as MinIO has it. |
| `--role-policy <NAMES>` | Give every token of each client these managed policies when it names the client's role (`arn:minio:iam:::role/…`, shown after), as MinIO's `role_policy` (repeatable, or comma-separated). |
| `--claim-userinfo` | Complete its tokens' claims from its userinfo endpoint, with the access token a request gives (`WebIdentityAccessToken`), as MinIO's `claim_userinfo`. |

## teifs admin oidc ls

List the providers.

```
teifs admin oidc ls [OPTIONS] <ALIAS>
```

| Argument | |
|---|---|
| `<ALIAS>` | The server's alias. |

## teifs admin oidc rm

Delete a provider (asks first): its tokens get no credentials from now on.

```
teifs admin oidc rm [OPTIONS] <ALIAS> <PROVIDER>
```

| Argument | |
|---|---|
| `<ALIAS>` | The server's alias. |
| `<PROVIDER>` | The provider: its URL, host or ARN. |

## teifs admin saml

Add, list, change and delete SAML providers, whose responses get a role's credentials.

```
teifs admin saml [OPTIONS] <COMMAND>
```

## teifs admin saml add

Add a provider from its metadata document (the XML its administration exports).

```
teifs admin saml add [OPTIONS] --metadata <FILE> <ALIAS> <NAME>
```

| Argument | |
|---|---|
| `<ALIAS>` | The server's alias. |
| `<NAME>` | The provider's name: letters, digits and `_.-`. |
| `--metadata <FILE>` | Its metadata document (`-` for standard input). |
| `--private-key <FILE>` | A private key (PEM) that decrypts its encrypted assertions. |
| `--encryption <ENCRYPTION>` | Whether its assertions must be encrypted. One of `required`, `allowed`. |

## teifs admin saml ls

List the providers.

```
teifs admin saml ls [OPTIONS] <ALIAS>
```

| Argument | |
|---|---|
| `<ALIAS>` | The server's alias. |

## teifs admin saml update

Change a provider: its metadata, its private keys (two at most, to rotate them) or whether its assertions must be encrypted.

```
teifs admin saml update [OPTIONS] <ALIAS> <PROVIDER>
```

| Argument | |
|---|---|
| `<ALIAS>` | The server's alias. |
| `<PROVIDER>` | The provider: its name or ARN. |
| `--metadata <FILE>` | A new metadata document (`-` for standard input). |
| `--add-key <FILE>` | Add a private key (PEM). |
| `--remove-key <ID>` | Remove the private key with this id (see `teifs admin saml ls`). |
| `--encryption <ENCRYPTION>` | Whether its assertions must be encrypted. One of `required`, `allowed`. |

## teifs admin saml rm

Delete a provider (asks first): its responses get no credentials from now on.

```
teifs admin saml rm [OPTIONS] <ALIAS> <PROVIDER>
```

| Argument | |
|---|---|
| `<ALIAS>` | The server's alias. |
| `<PROVIDER>` | The provider: its name or ARN. |

## teifs admin ldap

Map managed policies to LDAP users and groups, whose sessions (`teifs sts assume-ldap`) get them.

```
teifs admin ldap [OPTIONS] <COMMAND>
```

## teifs admin ldap policy

Map managed policies to LDAP users and groups, or list and remove mappings.

```
teifs admin ldap policy [OPTIONS] <COMMAND>
```

## teifs admin ldap policy attach

Map managed policies to a user's or a group's DN: their sessions get them at the next request.

```
teifs admin ldap policy attach [OPTIONS] <--user <DN>|--group <DN>> <ALIAS> <POLICIES>...
```

| Argument | |
|---|---|
| `<ALIAS>` | The server's alias. |
| `<POLICIES>` | The managed policies: names or ARNs. |
| `--user <DN>` | The user's DN, like `uid=dillon,ou=people,dc=example,dc=com`. |
| `--group <DN>` | The group's DN, like `cn=engineers,ou=groups,dc=example,dc=com`. |

## teifs admin ldap policy detach

Remove managed policies from a user's or a group's DN.

```
teifs admin ldap policy detach [OPTIONS] <--user <DN>|--group <DN>> <ALIAS> <POLICIES>...
```

| Argument | |
|---|---|
| `<ALIAS>` | The server's alias. |
| `<POLICIES>` | The managed policies: names or ARNs. |
| `--user <DN>` | The user's DN, like `uid=dillon,ou=people,dc=example,dc=com`. |
| `--group <DN>` | The group's DN, like `cn=engineers,ou=groups,dc=example,dc=com`. |

## teifs admin ldap policy ls

List the DNs with policies.

```
teifs admin ldap policy ls [OPTIONS] <ALIAS>
```

| Argument | |
|---|---|
| `<ALIAS>` | The server's alias. |
| `--user <DN>` | Only this user's DN. |
| `--group <DN>` | Only this group's DN. |

## teifs sts

Temporary credentials: whom an alias signs as, a role's session, or a session for a CI job's OpenID Connect token.

```
teifs sts [OPTIONS] <COMMAND>
```

## teifs sts whoami

Show whom an alias signs as: its ARN, user id and account.

```
teifs sts whoami [OPTIONS] <ALIAS>
```

| Argument | |
|---|---|
| `<ALIAS>` | The alias. |

## teifs sts assume

Get temporary credentials: a role's session, or without a role (as MinIO has it) a session with the user's own permissions, narrowed by `--policy`.

```
teifs sts assume [OPTIONS] <--save-alias <ALIAS>|--output <FILE>> <ALIAS> [ROLE]
```

| Argument | |
|---|---|
| `<ALIAS>` | The alias to ask with. |
| `<ROLE>` | The role: its name in the alias's account, or its ARN. |
| `--session-name <SESSION_NAME>` | The session's name, as the role's sessions show it. Default: `teifs`. |
| `--external-id <EXTERNAL_ID>` | The external id the role's trust policy asks for. |
| `--tag <KEY=VALUE>` | A session tag, `KEY=VALUE` (repeatable). |
| `--source-identity <SOURCE_IDENTITY>` | The source identity to set, kept along a chain of roles. |
| `--duration <DURATION>` | How long the credentials last, like `15m` or `12h` (the server's default otherwise: an hour for a role). |
| `--policy <FILE>` | A file with a session policy: the session may do only what it allows too. |
| `--save-alias <ALIAS>` | Save them as this alias, for the same server; an alias that already has temporary credentials is refreshed. |
| `-o, --output <FILE>` | Write them to this file (readable only by you), or to standard output with `-`, in the AWS CLI's `credential_process` format. |

## teifs sts assume-web

Exchange an OpenID Connect ID token (a CI job's) for temporary credentials: a role's session, or without a role the policies the token names, where the server allows it. Needs no keys.

```
teifs sts assume-web [OPTIONS] --token-file <TOKEN_FILE> <--save-alias <ALIAS>|--output <FILE>> <SERVER>
```

| Argument | |
|---|---|
| `<SERVER>` | The server, like `https://s3.example.com`, or an alias for it. |
| `--role <ROLE>` | The role's ARN (or `AWS_ROLE_ARN`). Environment: `AWS_ROLE_ARN`. |
| `--token-file <TOKEN_FILE>` | The file with the token (or `AWS_WEB_IDENTITY_TOKEN_FILE`). Environment: `AWS_WEB_IDENTITY_TOKEN_FILE`. |
| `--session-name <SESSION_NAME>` | The session's name (or `AWS_ROLE_SESSION_NAME`). Default: `teifs`. Environment: `AWS_ROLE_SESSION_NAME`. |
| `--region <REGION>` | The region to sign for. Default: `us-east-1`. |
| `--duration <DURATION>` | How long the credentials last, like `15m` or `12h` (the server's default otherwise: an hour for a role). |
| `--policy <FILE>` | A file with a session policy: the session may do only what it allows too. |
| `--save-alias <ALIAS>` | Save them as this alias, for the same server; an alias that already has temporary credentials is refreshed. |
| `-o, --output <FILE>` | Write them to this file (readable only by you), or to standard output with `-`, in the AWS CLI's `credential_process` format. |

## teifs sts assume-saml

Exchange the response of a SAML identity provider (Okta, Entra ID, AD FS) for a role's session, as `aws sts assume-role-with-saml` does. Needs no keys.

```
teifs sts assume-saml [OPTIONS] --role-arn <ARN> --principal-arn <ARN> --assertion-file <FILE> <--save-alias <ALIAS>|--output <FILE>> <SERVER>
```

| Argument | |
|---|---|
| `<SERVER>` | The server, like `https://s3.example.com`, or an alias for it. |
| `--role-arn <ARN>` | The role's ARN, which the response's `Role` attribute must name. |
| `--principal-arn <ARN>` | The SAML provider's ARN, `arn:aws:iam::ACCOUNT:saml-provider/NAME`. |
| `--assertion-file <FILE>` | The file with the response the provider gave the browser (its `SAMLResponse`, base64, or the XML itself), or `-` for standard input. |
| `--region <REGION>` | The region to sign for. Default: `us-east-1`. |
| `--duration <DURATION>` | How long the credentials last, like `15m` or `12h` (the server's default otherwise: an hour for a role). |
| `--policy <FILE>` | A file with a session policy: the session may do only what it allows too. |
| `--save-alias <ALIAS>` | Save them as this alias, for the same server; an alias that already has temporary credentials is refreshed. |
| `-o, --output <FILE>` | Write them to this file (readable only by you), or to standard output with `-`, in the AWS CLI's `credential_process` format. |

## teifs sts assume-ldap

Sign in with an LDAP user's name and password for temporary credentials with the policies mapped to the user and its groups. Needs no keys.

```
teifs sts assume-ldap [OPTIONS] --username <USERNAME> <--save-alias <ALIAS>|--output <FILE>> <SERVER>
```

| Argument | |
|---|---|
| `<SERVER>` | The server, like `https://s3.example.com`, or an alias for it. |
| `-u, --username <USERNAME>` | The LDAP user's name, as the directory knows it. |
| `--password-stdin` | Read the password from standard input (else `TEIFS_LDAP_PASSWORD`, else it's asked for). |
| `--region <REGION>` | The region to sign for. Default: `us-east-1`. |
| `--duration <DURATION>` | How long the credentials last, like `15m` or `12h` (the server's default otherwise: an hour for a role). |
| `--policy <FILE>` | A file with a session policy: the session may do only what it allows too. |
| `--save-alias <ALIAS>` | Save them as this alias, for the same server; an alias that already has temporary credentials is refreshed. |
| `-o, --output <FILE>` | Write them to this file (readable only by you), or to standard output with `-`, in the AWS CLI's `credential_process` format. |

## teifs sts assume-cert

Sign in with a client certificate for temporary credentials with the policy its subject common name names, where the server takes certificates. Needs no keys.

```
teifs sts assume-cert [OPTIONS] --cert <FILE> --key <FILE> <--save-alias <ALIAS>|--output <FILE>> <SERVER>
```

| Argument | |
|---|---|
| `<SERVER>` | The server, like `https://s3.example.com`, or an alias for it. |
| `--cert <FILE>` | The client certificate (PEM, with any intermediate CAs after it). |
| `--key <FILE>` | Its private key (PEM). |
| `--region <REGION>` | The region to sign for. Default: `us-east-1`. |
| `--duration <DURATION>` | How long the credentials last, like `15m` or `12h` (the server's default otherwise: an hour for a role). |
| `--policy <FILE>` | A file with a session policy: the session may do only what it allows too. |
| `--save-alias <ALIAS>` | Save them as this alias, for the same server; an alias that already has temporary credentials is refreshed. |
| `-o, --output <FILE>` | Write them to this file (readable only by you), or to standard output with `-`, in the AWS CLI's `credential_process` format. |

## teifs sts assume-custom

Exchange a token the server's identity plugin vouches for for temporary credentials with the plugin role's policies. Needs no keys.

```
teifs sts assume-custom [OPTIONS] --role-arn <ARN> <--save-alias <ALIAS>|--output <FILE>> <SERVER>
```

| Argument | |
|---|---|
| `<SERVER>` | The server, like `https://s3.example.com`, or an alias for it. |
| `--role-arn <ARN>` | The plugin role's ARN, `arn:minio:iam:…:role/idmp-…`, as the server shows it. |
| `--token-stdin` | Read the token from standard input (else `TEIFS_STS_CUSTOM_TOKEN`, else it's asked for). |
| `--region <REGION>` | The region to sign for. Default: `us-east-1`. |
| `--duration <DURATION>` | How long the credentials last, like `15m` or `12h` (the server's default otherwise: an hour for a role). |
| `--policy <FILE>` | A file with a session policy: the session may do only what it allows too. |
| `--save-alias <ALIAS>` | Save them as this alias, for the same server; an alias that already has temporary credentials is refreshed. |
| `-o, --output <FILE>` | Write them to this file (readable only by you), or to standard output with `-`, in the AWS CLI's `credential_process` format. |

## teifs health

Check that a TeiFS server answers its health check (exit code 0 when it does); for container health checks and scripts.

```
teifs health [OPTIONS] [ADDRESS]
```

| Argument | |
|---|---|
| `<ADDRESS>` | The server's address (`teifs serve --listen`'s), or its `http://` or `https://` URL. An address is asked over HTTPS when the server only speaks that. Default: `127.0.0.1:9000`. Environment: `TEIFS_LISTEN`. |
| `--timeout <TIMEOUT>` | How long to wait for an answer. Default: `5s`. |

## teifs status

Check how a server is doing: whether it answers and how fast, whether its drive can serve and take writes, whether the clocks agree, when its certificate expires, and (with keys that may read it) its version, disks, jobs and scrubs. Exit code 1 when a check fails.

```
teifs status [OPTIONS] [ALIAS]
```

| Argument | |
|---|---|
| `<ALIAS>` | The server's alias. Default: `local`. |

## teifs doctor

Find what would stop `teifs serve` with these settings, or make it serve badly: the drive (format, databases, in use, writable), its disk's room, the root keys, the keyring, the TLS certificates and the listen address, each with what to do. Changes nothing. Exit code 1 when a check fails.

```
teifs doctor [OPTIONS] [DIR]
```

| Argument | |
|---|---|
| `--config <CONFIG>` | A TOML file of settings, under the flags' names (`listen = "0.0.0.0:9000"`). Environment: `TEIFS_CONFIG`. |
| `<DIR>` | The drive's folder (created if missing). Default: `.`. Environment: `TEIFS_DIR`. |
| `--listen <LISTEN>` | Address to listen on. Default: `127.0.0.1:9000`. Environment: `TEIFS_LISTEN`. |
| `--certs-dir <CERTS_DIR>` | Serve HTTPS with the certificates in this folder: `public.crt` and `private.key` (or `tls.crt` and `tls.key`), and a subfolder with the same files for each further certificate, chosen by the name clients ask for. They're reloaded when they change, and on SIGHUP. Environment: `TEIFS_CERTS_DIR`. |
| `--tls-cert <TLS_CERT>` | Serve HTTPS with this certificate (PEM, its chain after it), reloaded when it changes; needs `--tls-key`. Environment: `TEIFS_TLS_CERT`. |
| `--tls-key <TLS_KEY>` | The private key (PEM) of `--tls-cert`. Environment: `TEIFS_TLS_KEY`. |
| `--trusted-proxy <CIDR>` | Trust the reverse proxy at this address or network (`10.0.0.5`, `10.0.0.0/8`; repeatable) to say who its clients are, in `--proxy-header`, and whether they came over HTTPS, in `X-Forwarded-Proto`. Nobody else can. Environment: `TEIFS_TRUSTED_PROXIES`. |
| `--proxy-header <PROXY_HEADER>` | The header trusted proxies name clients in: `x-forwarded-for` (nginx, HAProxy, Traefik, Caddy, Envoy, AWS load balancers), `forwarded` (RFC 7239) or `x-real-ip`. Choose one the proxy adds to or sets, never one it passes on. Default: `x-forwarded-for`. Environment: `TEIFS_PROXY_HEADER`. |
| `--domain <DOMAINS>` | A domain for virtual-hosted-style requests (bucket.domain); repeatable. Environment: `TEIFS_DOMAINS`. |
| `--website-domain <WEBSITE_DOMAINS>` | A domain for buckets' static websites (`bucket.domain`), as S3's website endpoint; repeatable. Buckets with a website configuration answer there. Environment: `TEIFS_WEBSITE_DOMAINS`. |
| `--access-key <ACCESS_KEY>` | The access key (else one is generated and kept in the drive). Environment: `TEIFS_ACCESS_KEY`. |
| `--default-layout <DEFAULT_LAYOUT>` | How buckets created over S3 store objects, unless the request says: `object` (any key S3 allows, encrypted at rest by default, as on AWS) or `folder` (plain files you can open anywhere). One of `object`, `folder`. Default: `object`. Environment: `TEIFS_DEFAULT_LAYOUT`. |
| `--kms-keyring <KMS_KEYRING>` | The KMS keyring (default: `<config dir>/teifs/keys/<drive id>.json`). Keep it off the drive and back it up: encrypted objects can't be read without it. Environment: `TEIFS_KMS_KEYRING`. |
| `--kms-transit <KMS_TRANSIT>` | Use a Vault or OpenBao transit engine as the KMS (e.g. `https://vault:8200`); its token comes from `VAULT_TOKEN` or `BAO_TOKEN`. Environment: `TEIFS_KMS_TRANSIT`. |
| `--kms-transit-mount <KMS_TRANSIT_MOUNT>` | Where the transit engine is mounted. Default: `transit`. Environment: `TEIFS_KMS_TRANSIT_MOUNT`. |
| `--kms-transit-namespace <KMS_TRANSIT_NAMESPACE>` | The transit engine's namespace (Vault Enterprise, OpenBao). Environment: `TEIFS_KMS_TRANSIT_NAMESPACE`. |
| `--kms-kes <KMS_KES>` | Use KES as the KMS: one or more servers, comma-separated (e.g. `https://kes:7373`). TeiFS signs in with the API key in `TEIFS_KMS_KES_API_KEY`, or with --kms-kes-cert and --kms-kes-key. Environment: `TEIFS_KMS_KES`. |
| `--kms-kes-cert <KMS_KES_CERT>` | A client certificate (PEM) to sign in to KES with, instead of an API key. Environment: `TEIFS_KMS_KES_CERT`. |
| `--kms-kes-key <KMS_KES_KEY>` | The client certificate's private key (PEM). Environment: `TEIFS_KMS_KES_KEY`. |
| `--kms-kes-ca <KMS_KES_CA>` | The certificate authorities KES's certificate is checked against (PEM; default: the system's). Environment: `TEIFS_KMS_KES_CA`. |
| `--kms-aws` | Use AWS KMS: credentials come from AWS's usual places (environment, shared config and SSO, instance and container roles). Environment: `TEIFS_KMS_AWS`. |
| `--kms-aws-region <KMS_AWS_REGION>` | AWS KMS's region (default: AWS's configuration's). Environment: `TEIFS_KMS_AWS_REGION`. |
| `--kms-aws-endpoint <KMS_AWS_ENDPOINT>` | Another AWS KMS endpoint, such as a VPC endpoint or a local emulator. Environment: `TEIFS_KMS_AWS_ENDPOINT`. |
| `--kms-default-key <KMS_DEFAULT_KEY>` | The key to use where TeiFS would use `teifs-default`: SSE-S3, SSE-KMS without a key, and the drive's own secrets. Keys sealed before keep opening. Environment: `TEIFS_KMS_DEFAULT_KEY`. |
| `--ldap-server <ADDRESS>` | Sign users in with this LDAP server (`host` or `host:port`; port 636 when none), as MinIO's `AssumeRoleWithLDAPIdentity`. Its lookup account's password comes from `TEIFS_LDAP_LOOKUP_BIND_PASSWORD`. Environment: `TEIFS_LDAP_SERVER`. |
| `--ldap-srv-record <LDAP_SRV_RECORD>` | Find the servers in DNS SRV records instead: `on` (the address is the record's whole name), `ldap` or `ldaps` (the address is a domain). One of `on`, `ldap`, `ldaps`. Environment: `TEIFS_LDAP_SRV_RECORD`. |
| `--ldap-starttls` | Reach it with plain LDAP upgraded by `StartTLS`, not LDAP over TLS. Environment: `TEIFS_LDAP_STARTTLS`. |
| `--ldap-insecure` | Reach it with plain, unencrypted LDAP: passwords cross the network as they are. Environment: `TEIFS_LDAP_INSECURE`. |
| `--ldap-ca <FILE>` | The certificate authorities (PEM) its certificate is checked against (default: the system's). Environment: `TEIFS_LDAP_CA`. |
| `--ldap-tls-skip-verify` | Accept any certificate from it: for a test directory only. Environment: `TEIFS_LDAP_TLS_SKIP_VERIFY`. |
| `--ldap-lookup-bind-dn <DN>` | The DN of the account users are looked up with. Environment: `TEIFS_LDAP_LOOKUP_BIND_DN`. |
| `--ldap-user-base-dn <DN>` | Where users are searched for (repeatable, or separated by `;`). Environment: `TEIFS_LDAP_USER_BASE_DN`. |
| `--ldap-user-filter <FILTER>` | The filter that finds a user: `%s` is the name it signs in with, like `(uid=%s)`. Environment: `TEIFS_LDAP_USER_FILTER`. |
| `--ldap-user-attributes <NAMES>` | The user's attributes its sessions carry, comma-separated. Environment: `TEIFS_LDAP_USER_ATTRIBUTES`. |
| `--ldap-group-base-dn <DN>` | Where groups are searched for (repeatable, or separated by `;`). Environment: `TEIFS_LDAP_GROUP_BASE_DN`. |
| `--ldap-group-filter <FILTER>` | The filter that finds a user's groups: `%d` is its DN and `%s` the name it signs in with, like `(&(objectclass=groupOfNames)(member=%d))`. Environment: `TEIFS_LDAP_GROUP_FILTER`. |
| `--identity-plugin-url <URL>` | Check custom tokens with this identity plugin (an `http(s)` URL), as MinIO's `AssumeRoleWithCustomToken`: it's sent each token and answers whom it's for. The `Authorization` header it's sent comes from `TEIFS_IDENTITY_PLUGIN_AUTH_TOKEN`. Environment: `TEIFS_IDENTITY_PLUGIN_URL`. |
| `--identity-plugin-role-policy <NAMES>` | The managed policies its users' sessions get (repeatable, or comma-separated). Environment: `TEIFS_IDENTITY_PLUGIN_ROLE_POLICY`. |
| `--identity-plugin-role-id <ID>` | The id in the role ARN clients name, `arn:minio:iam:::role/idmp-<ID>` (default: derived from the URL, as MinIO derives it). Environment: `TEIFS_IDENTITY_PLUGIN_ROLE_ID`. |
| `--identity-plugin-ca <PATH>` | Certificate authorities (PEM: a file, or a folder of them) its certificate may be issued by, besides the system's. Environment: `TEIFS_IDENTITY_PLUGIN_CA`. |
| `--openid-config-url <URL>` | Make an OpenID Connect provider, or keep it in line with these settings, when the server starts: its discovery URL (`https://…/.well-known/openid-configuration`) or its issuer, as MinIO's `config_url`. Environment: `TEIFS_OPENID_CONFIG_URL`. |
| `--openid-client-id <ID>` | The client its tokens are for (their `aud` or `azp`). Environment: `TEIFS_OPENID_CLIENT_ID`. |
| `--openid-role-policy <NAMES>` | Give every token for the client these managed policies when it names the client's role (`arn:minio:iam:::role/…`), as MinIO's `role_policy` (repeatable, or comma-separated). Environment: `TEIFS_OPENID_ROLE_POLICY`. |
| `--openid-claim-name <CLAIM>` | Without role policies, the claim that names a token's managed policies (default: `policy`), as MinIO's `claim_name`. Environment: `TEIFS_OPENID_CLAIM_NAME`. |
| `--openid-claim-userinfo` | Complete tokens' claims from the provider's userinfo endpoint, with the access token a request gives, as MinIO's `claim_userinfo`. Environment: `TEIFS_OPENID_CLAIM_USERINFO`. |
| `--identity-tls` | Sign in clients that connect with a certificate (MinIO's `AssumeRoleWithCertificate`): the session has the policy the certificate's subject common name names. Needs HTTPS. MinIO's `MINIO_IDENTITY_TLS_ENABLE=on` works too. Environment: `TEIFS_IDENTITY_TLS`. |
| `--identity-tls-ca <PATH>` | The CA certificates (PEM: a file, or a folder of them) that must have issued client certificates (default: the certificates folder's `CAs`, as MinIO has it). Environment: `TEIFS_IDENTITY_TLS_CA`. |
| `--identity-tls-skip-verify` | Take any client certificate, whoever issued it: for testing only. MinIO's `MINIO_IDENTITY_TLS_SKIP_VERIFY=on` works too. Environment: `TEIFS_IDENTITY_TLS_SKIP_VERIFY`. |
| `--allow-sse-c` | Allow SSE-C (customer-provided keys) on buckets that don't set it themselves; AWS blocks it by default since April 2026. Environment: `TEIFS_ALLOW_SSE_C`. |
| `--no-root-access` | Refuse the root key, the service accounts it made and the sessions it started, as `MinIO`'s `root_access=off`: only IAM's users sign in. Make an admin user first. Environment: `TEIFS_NO_ROOT_ACCESS`. |
| `--allow-sigv2` | Accept Signature Version 2 (HMAC-SHA1) requests and links, for old clients and boto3's default presigned links. AWS deprecated it and refuses it for newer buckets; prefer configuring clients for Signature Version 4. Environment: `TEIFS_ALLOW_SIGV2`. |
| `--legacy-bucket-defaults` | Make new buckets as S3 did before April 2023: ACLs enabled and no Block Public Access, for applications that upload with public ACLs such as `public-read`. Without it, new buckets start as AWS's do now: ACLs disabled, public access blocked. Either way each bucket's settings can be changed. Environment: `TEIFS_LEGACY_BUCKET_DEFAULTS`. |
| `--public-metrics` | Serve Prometheus metrics (`/.teifs/metrics`) to anyone who can reach the server. Without it, a scrape needs a bearer token from `teifs admin prometheus generate`. Metrics name operations and the drive's size: only on a network you trust. Environment: `TEIFS_PUBLIC_METRICS`. |
| `--audit-log <FILE>` | Keep an audit log: one JSON line per request (who asked what, the answer, bytes and time; never secrets), appended to this file (created owner-only, reopened on SIGHUP for logrotate), or `-` for standard output. Environment: `TEIFS_AUDIT_LOG`. |
| `--audit-webhook <URL>` | Also POST the audit log's entries to this URL, in batches of JSON lines (`application/x-ndjson`), each retried until it's taken; for an https URL, `,ca=PATH` verifies the server with a CA's PEM file, and `,client_cert=PATH` and `,client_key=PATH` are shown to a server that asks. The webhook's token, sent as `Authorization: Bearer TOKEN` (or as given when it names a scheme), is read only from the environment: `TEIFS_AUDIT_WEBHOOK_TOKEN`. Environment: `TEIFS_AUDIT_WEBHOOK`. |
| `--notify-webhook <ID=URL>` | A webhook buckets' notification rules can send events to, as ID=URL, with `ca=PATH`, `client_cert=PATH` and `client_key=PATH` for an https URL, as the audit webhook's (repeat for more; in the environment, separated by spaces). Rules name it by its ARN, `arn:teifs:sqs::ID:webhook`; each event is sent as JSON, retried until it's taken, and waits on the drive meanwhile. Its token, sent as `Authorization: Bearer TOKEN` (or as given when it names a scheme), is read only from the environment: `TEIFS_NOTIFY_WEBHOOK_TOKEN_ID` (the ID in capitals, `-` as `_`). Environment: `TEIFS_NOTIFY_WEBHOOK`. |
| `--notify-elasticsearch <ID=URL,index=NAME>` | An Elasticsearch index buckets' notification rules can send events to, as ID=URL,index=NAME, with format=namespace (a document per object, replaced by each event and removed with it: the default) or format=access (a document per event), user=NAME, and for an https URL `ca=PATH`, `client_cert=PATH` and `client_key=PATH` (repeat for more; in the environment, separated by spaces). Rules name it `arn:teifs:sqs::ID:elasticsearch`; the index is created when missing. Its password, `TEIFS_NOTIFY_ELASTICSEARCH_PASSWORD_ID`, or API key, `TEIFS_NOTIFY_ELASTICSEARCH_API_KEY_ID`, is read only from the environment. Environment: `TEIFS_NOTIFY_ELASTICSEARCH`. |
| `--notify-redis <ID=HOST:PORT,key=NAME>` | A Redis key buckets' notification rules can send events to, as ID=HOST:PORT,key=NAME, with format=namespace (a hash, a field per object, set by each event and removed with it: the default) or format=access (a list, an entry per event), db=N, user=NAME, and tls=true (the server verified with the system's certificates) or ca=PATH (with a CA's PEM file), with `client_cert=PATH` and `client_key=PATH` for a server that wants a client certificate (repeat for more; in the environment, separated by spaces). Rules name it `arn:teifs:sqs::ID:redis`. Its password, `TEIFS_NOTIFY_REDIS_PASSWORD_ID`, is read only from the environment. Environment: `TEIFS_NOTIFY_REDIS`. |
| `--notify-nsq <ID=HOST:PORT,topic=NAME>` | An NSQ topic buckets' notification rules can send events to, as ID=HOST:PORT,topic=NAME, the nsqd's TCP address, with `tls=true` or `ca=PATH` (and `client_cert=PATH` and `client_key=PATH`) for TLS (repeat for more; in the environment, separated by spaces). Rules name it `arn:teifs:sqs::ID:nsq`; each event is published as a webhook is sent it. The secret for an nsqd that wants `AUTH`, `TEIFS_NOTIFY_NSQ_SECRET_ID`, is read only from the environment and sent only over TLS. Environment: `TEIFS_NOTIFY_NSQ`. |
| `--notify-nats <ID=HOST:PORT,subject=NAME>` | A NATS subject buckets' notification rules can send events to, as ID=HOST:PORT,subject=NAME, with jetstream=true (a `JetStream` stream that takes the subject acknowledges each event), user=NAME, creds=PATH (a `.creds` file's user JWT and key) or nkey=PATH (a file holding a user seed), and tls=true or ca=PATH, `client_cert=PATH` and `client_key=PATH`, with `tls_first=true` for a server that starts TLS first (repeat for more; in the environment, separated by spaces). Rules name it `arn:teifs:sqs::ID:nats`. Its password or token, `TEIFS_NOTIFY_NATS_PASSWORD_ID` or `TEIFS_NOTIFY_NATS_TOKEN_ID`, is read only from the environment. Environment: `TEIFS_NOTIFY_NATS`. |
| `--notify-mqtt <ID=HOST:PORT,topic=NAME>` | An MQTT topic buckets' notification rules can send events to, as ID=HOST:PORT,topic=NAME, the broker's address (or its URL: tcp://, ssl:// for TLS, ws:// or wss:// with the WebSocket's path), with qos=0, 1 (the default) or 2, user=NAME, keepalive=SECONDS, and tls=true or ca=PATH with `client_cert=PATH` and `client_key=PATH` (repeat for more; in the environment, separated by spaces). Rules name it `arn:teifs:sqs::ID:mqtt`. Its password, `TEIFS_NOTIFY_MQTT_PASSWORD_ID`, is read only from the environment. Environment: `TEIFS_NOTIFY_MQTT`. |
| `--notify-kafka <ID=BROKER,topic=NAME>` | A Kafka topic buckets' notification rules can send events to, as ID=BROKER[;BROKER…],topic=NAME, the brokers first asked about the topic (`HOST:PORT`), with acks=all (the default: every in-sync replica has each event) or acks=1, compression=gzip, snappy, lz4 or zstd (Kafka 2.1 or later), sasl=plain, scram-sha-256 or scram-sha-512 with user=NAME, and tls=true or ca=PATH with `client_cert=PATH` and `client_key=PATH` (repeat for more; in the environment, separated by spaces). Rules name it `arn:teifs:sqs::ID:kafka`; each event is produced as a webhook is sent it, keyed `bucket/object`. Its SASL password, `TEIFS_NOTIFY_KAFKA_PASSWORD_ID`, is read only from the environment. Environment: `TEIFS_NOTIFY_KAFKA`. |
| `--notify-amqp <ID=URL,exchange=NAME,routing_key=KEY>` | An AMQP 0-9-1 exchange (`RabbitMQ`) buckets' notification rules can send events to, as `ID=amqp[s]://HOST[:PORT][/VHOST],exchange=NAME,routing_key=KEY`, with `exchange_type=direct` (the default), fanout, topic or headers, `durable=false`, `auto_delete=true`, `internal=true`, `declare=false` (only check that the exchange exists), `mandatory=true` (a message no queue takes fails and is tried again), `persistent=false`, `user=NAME`, and for `amqps://` `ca=PATH`, `client_cert=PATH` and `client_key=PATH` (repeat for more; in the environment, separated by spaces). Rules name it `arn:teifs:sqs::ID:amqp`; each event is published as a webhook is sent it and confirmed by the broker. Its password, `TEIFS_NOTIFY_AMQP_PASSWORD_ID`, is read only from the environment. Environment: `TEIFS_NOTIFY_AMQP`. |
| `--notify-postgresql <ID=HOST:PORT,database=NAME,table=NAME,user=NAME>` | A PostgreSQL table buckets' notification rules can send events to, as `ID=HOST:PORT,database=NAME,table=NAME,user=NAME` (a table's name in double quotes keeps its capitals, as `table="S3Events"`), with `format=namespace` (a row per object, set by each event and deleted with it: the default) or `format=access` (a row per event), and `tls=true` (the server verified with the system's certificates) or `ca=PATH`, with `client_cert=PATH` and `client_key=PATH` (repeat for more; in the environment, separated by spaces). The table is made if it's missing. Rules name it `arn:teifs:sqs::ID:postgresql`. Its password, `TEIFS_NOTIFY_POSTGRESQL_PASSWORD_ID`, is read only from the environment. Environment: `TEIFS_NOTIFY_POSTGRESQL`. |
| `--notify-mysql <ID=HOST:PORT,database=NAME,table=NAME,user=NAME>` | A MySQL (5.7 or later) or `MariaDB` table buckets' notification rules can send events to, as `ID=HOST:PORT,database=NAME,table=NAME,user=NAME` (a table's name in backquotes keeps its capitals), with `format=namespace` (a row per object: the default) or `format=access` (a row per event), `tls=true` or `ca=PATH` with `client_cert=PATH` and `client_key=PATH`, and, for a server that wants the whole password without TLS, `server_public_key=PATH` (its RSA key, `public_key.pem`) or `get_server_public_key=true` (asked for, which a machine in between could swap). The table is made if it's missing. Rules name it `arn:teifs:sqs::ID:mysql`. Its password, `TEIFS_NOTIFY_MYSQL_PASSWORD_ID`, is read only from the environment. Environment: `TEIFS_NOTIFY_MYSQL`. |
| `--notify-sqs <ID=QUEUE_URL>` | An SQS queue buckets' notification rules can send events to, as S3 sends them, as `ID=QUEUE_URL` (`https://sqs.REGION.amazonaws.com/ACCOUNT/NAME`, or any service that speaks SQS's API), with region=NAME when its host doesn't name it (repeat for more; in the environment, separated by spaces). Rules name it `arn:teifs:sqs::ID:sqs`. Requests are signed with `TEIFS_NOTIFY_SQS_ACCESS_KEY_ID`, `TEIFS_NOTIFY_SQS_SECRET_KEY_ID` and `TEIFS_NOTIFY_SQS_SESSION_TOKEN_ID`, else `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN`, read only from the environment. Environment: `TEIFS_NOTIFY_SQS`. |
| `--notify-sns <ID=TOPIC_ARN>` | An SNS topic buckets' notification rules can publish events to, as S3 publishes them, as `ID=TOPIC_ARN` (`arn:aws:sns:REGION:ACCOUNT:NAME`), with endpoint=URL for a service other than AWS's (repeat for more; in the environment, separated by spaces). Rules name it by the topic's ARN, as on S3, or `arn:teifs:sqs::ID:sns`. Requests are signed with `TEIFS_NOTIFY_SNS_ACCESS_KEY_ID`, `TEIFS_NOTIFY_SNS_SECRET_KEY_ID` and `TEIFS_NOTIFY_SNS_SESSION_TOKEN_ID`, else `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN`, read only from the environment. Environment: `TEIFS_NOTIFY_SNS`. |
| `--notify-lambda <ID=FUNCTION_ARN>` | A Lambda function buckets' notification rules can invoke with events, as S3 invokes it, as `ID=FUNCTION_ARN` (`arn:aws:lambda:REGION:ACCOUNT:function:NAME`, with `:VERSION` or `:ALIAS` if one is meant), with endpoint=URL for a service other than AWS's (repeat for more; in the environment, separated by spaces). Rules name it by the function's ARN, as on S3, or `arn:teifs:sqs::ID:lambda`. Requests are signed with `TEIFS_NOTIFY_LAMBDA_ACCESS_KEY_ID`, `TEIFS_NOTIFY_LAMBDA_SECRET_KEY_ID` and `TEIFS_NOTIFY_LAMBDA_SESSION_TOKEN_ID`, else `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN`, read only from the environment. Environment: `TEIFS_NOTIFY_LAMBDA`. |
| `--notify-eventbridge <ID=BUS_ARN>` | The EventBridge event bus buckets send every event to once EventBridge is turned on for them (`EventBridgeConfiguration`), as S3 does, as `ID=BUS_ARN` (`arn:aws:events:REGION:ACCOUNT:event-bus/default`), with source=NAME (`teifs.s3` by default: EventBridge keeps `aws.` sources for AWS's services) and endpoint=URL for a service other than AWS's. Requests are signed with `TEIFS_NOTIFY_EVENTBRIDGE_ACCESS_KEY_ID`, `TEIFS_NOTIFY_EVENTBRIDGE_SECRET_KEY_ID` and `TEIFS_NOTIFY_EVENTBRIDGE_SESSION_TOKEN_ID`, else `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN`, read only from the environment. Environment: `TEIFS_NOTIFY_EVENTBRIDGE`. |
| `--sse-c-over-http` | Accept SSE-C keys over plain HTTP. Only behind a proxy that terminates TLS; a server listening on this machine only accepts them anyway. Environment: `TEIFS_SSE_C_OVER_HTTP`. |
| `--upload-expiry <UPLOAD_EXPIRY>` | Abort multipart uploads left unfinished this long (`30m`, `12h`, `7d`), or `never`. Default: `7d`. Environment: `TEIFS_UPLOAD_EXPIRY`. |
| `--scrub-every <SCRUB_EVERY>` | Read every stored version back this often (`7d`, `30d`), checking it against its checksums and ETag so damage on the disk is found early, or `never`. Passes go at the background jobs' pace and carry on after a restart. Default: `30d`. Environment: `TEIFS_SCRUB_EVERY`. |
| `--snapshots <SNAPSHOTS>` | How many daily snapshots of the drive's metadata (its buckets, settings, IAM and object index) to keep in `.teifs/backups/auto/`; 0 takes none. Default: `3`. Environment: `TEIFS_SNAPSHOTS`. |
| `--durability <DURABILITY>` | How hard writes are made to survive a power cut: `strict` (nothing acknowledged is lost), `relaxed` (file data synced; the last moments' writes may be lost) or `none` (scratch data). None of them can corrupt the drive. One of `strict`, `relaxed`, `none`. Default: `strict`. Environment: `TEIFS_DURABILITY`. |
| `--key-names <KEY_NAMES>` | Which names folder buckets may create: `portable` (names Windows, macOS and Linux can all hold, so the drive can move between them) or `host` (whatever this system can hold). Object buckets take any S3 key either way. One of `portable`, `host`. Default: `portable`. Environment: `TEIFS_KEY_NAMES`. |
| `--access-log-interval <ACCESS_LOG_INTERVAL>` | How often each bucket's server access log is delivered into its target bucket as a log object (AWS delivers within hours; sooner here). A log object is also delivered at 1 MiB, and when the day changes. Default: `5m`. Environment: `TEIFS_ACCESS_LOG_INTERVAL`. |
| `--header-timeout <HEADER_TIMEOUT>` | How long a client has to send a request's headers; idle connections close after it too. Default: `30s`. Environment: `TEIFS_HEADER_TIMEOUT`. |
| `--body-timeout <BODY_TIMEOUT>` | How long an upload's body may stop arriving before the request fails with `RequestTimeout`. Default: `60s`. Environment: `TEIFS_BODY_TIMEOUT`. |
| `--max-connections <MAX_CONNECTIONS>` | The most connections served at once; more wait until one closes. Default: `4096`. Environment: `TEIFS_MAX_CONNECTIONS`. |
| `--secret-key-file <SECRET_KEY_FILE>` | A file holding the secret key, for use with the access key (Docker and systemd secrets). Or set `TEIFS_SECRET_KEY`; never on the command line. Environment: `TEIFS_SECRET_KEY_FILE`. |

## teifs completions

Print the shell completion script for `shell`, for example `teifs completions zsh > ~/.zfunc/_teifs` or `teifs completions bash > ~/.local/share/bash-completion/completions/teifs`.

```
teifs completions [OPTIONS] <SHELL>
```

| Argument | |
|---|---|
| `<SHELL>` | The shell: bash, elvish, fish, powershell or zsh. One of `bash`, `elvish`, `fish`, `powershell`, `zsh`. |

<!-- end generated -->
