# Admin API

Everything TeiFS serves besides S3's operations: its admin API, for what AWS has no API
for, and the parts of AWS's other APIs it serves on the S3 endpoint (S3 Control, IAM and
STS). `teifs admin` calls the admin API through an alias, and the `teifs-client` crate
is the same as a Rust library.

## Requests

The admin API is JSON under `/.teifs/admin/v1/`, signed with Signature V4 like any S3
request (service `s3`). A bucket name can't start with a dot, so no path-style bucket
request reaches it; a virtual-hosted-style request (`photos.example.com/.teifs/…`) is a
key in that bucket, never the admin API. S3 Control requests are told apart from a
bucket's by the `x-amz-account-id` header, which must name the drive's account, and IAM
and STS requests by their form body, as the AWS SDKs and CLI send them.

With curl, which reads the key from standard input so it stays off the command line:

```sh
printf 'user = "%s:%s"\n' "$ACCESS_KEY" "$SECRET_KEY" |
  curl --config - --aws-sigv4 aws:amz:us-east-1:s3 http://127.0.0.1:9000/.teifs/admin/v1/info
```

## Who may call it

Unsigned requests and keys IAM doesn't know are refused before any endpoint runs. The
root user may call everything; an IAM user or role session needs the endpoint's action
in its policies (the resource is `*` for the admin API, the account for Block Public
Access), and endpoints marked *root user* are the root user's alone, whatever policies
say. S3 Control's calls on a bucket's tags are decided on the bucket
(`arn:aws:s3:::bucket`), with its bucket policy and, while its ABAC is on, its tags
(`aws:ResourceTag`); the tags a call adds are `aws:RequestTag` and `aws:TagKeys`, and
the keys it removes are `aws:TagKeys`. A bucket policy's Deny binds the root user here
too. The calls of `MinIO`'s admin API TeiFS serves (bucket quotas) are decided on the
bucket their `?bucket=NAME` names (`arn:aws:s3:::bucket`), with `MinIO`'s actions
(`admin:SetBucketQuota`, `admin:GetBucketQuota`) in the caller's policies; `s3:*` grants
none of them. Credentials from `GetSessionToken` and federated
users' sessions can't call the admin API or `MinIO`'s, as they can't call IAM on AWS.

## Endpoints

The table is generated from the server's route table (`crates/s3/src/routes.rs`), and a
test fails when it's out of date: `UPDATE_DOCS=1 cargo nextest run -p teifs-s3 -E
'test(admin_api_reference)'` writes it again.

<!-- generated: endpoints -->

### The admin API

| Method | Path | What it does | Who may |
|---|---|---|---|
| `GET` | `/.teifs/admin/v1/info` | Version, drive, account, uptime, what the drive holds, its disks' room, background jobs and what scrubs found: `ServerInfo` | `teifs:GetServerInfo` |
| `GET` | `/.teifs/admin/v1/config` | How the server was started, without secrets: `ServerConfig` | `teifs:GetServerConfig` |
| `GET` | `/.teifs/admin/v1/snapshots` | The drive's metadata snapshots, oldest first: `Snapshot`s | `teifs:ListSnapshots` |
| `POST` | `/.teifs/admin/v1/snapshots` | Snapshots the drive's metadata now (both databases, kept with the daily ones): `Snapshot` | `teifs:TakeSnapshot` |
| `GET` | `/.teifs/admin/v1/buckets` | Every bucket (`?bucket=NAME`: one) with its layout, versioning and settings: `BucketsExport` | `teifs:ExportBucketMetadata` |
| `PUT` | `/.teifs/admin/v1/buckets` | Imports a `BucketsExport`: creates missing buckets and applies the settings given, checked as S3's calls check them: `BucketsImportReport` | `teifs:ImportBucketMetadata` |
| `GET` | `/.teifs/admin/v1/trace` | A live trace: each request answered from now on, as its audit entry, one JSON line each (`application/x-ndjson`), until the caller leaves; the query filters it (`errors`, `api`, `bucket`, `prefix`, `status`, `slowerThanMs`) | `teifs:ServerTrace` |
| `GET` | `/.teifs/admin/v1/iam` | The account's IAM, access keys without their secrets: `IamExport` | `teifs:ExportIAM` |
| `GET` | `/.teifs/admin/v1/iam/secrets` | The account's IAM with access keys' secrets, to move it to another drive | root user |
| `PUT` | `/.teifs/admin/v1/iam` | Imports an `IamExport` into an empty IAM, all or nothing: `ImportReport`; `?account=adopt` also takes its account id | root user |
| `POST` | `/.teifs/admin/v1/root-key` | Replaces a root key the drive generated and answers the new one: `RootKeyRotated` | root user |
| `GET` | `/.teifs/admin/v1/ldap/policies` | The managed policies mapped to LDAP users' and groups' DNs (`?dn=DN`: one): `LdapPolicyMapping`s | `teifs:ListLDAPPolicies` |
| `POST` | `/.teifs/admin/v1/ldap/attach` | Maps managed policies to an LDAP user's or group's DN, which the directory must have (`LdapPolicyRequest`): `LdapPolicyChanged` | `teifs:AttachLDAPPolicy` |
| `POST` | `/.teifs/admin/v1/ldap/detach` | Removes managed policies from an LDAP user's or group's DN (`LdapPolicyRequest`): `LdapPolicyChanged` | `teifs:DetachLDAPPolicy` |

### S3 Control

| Method | Path | What it does | Who may |
|---|---|---|---|
| `GET` | `/v20180820/configuration/publicAccessBlock` | The account's Block Public Access settings | `s3:GetAccountPublicAccessBlock` |
| `PUT` | `/v20180820/configuration/publicAccessBlock` | Sets the account's Block Public Access, combined with every bucket's own | `s3:PutAccountPublicAccessBlock` |
| `DELETE` | `/v20180820/configuration/publicAccessBlock` | Removes the account's Block Public Access, leaving each bucket's own | `s3:PutAccountPublicAccessBlock` |
| `GET` | `/v20180820/tags/{resourceArn}` | A bucket's tags (`ListTagsForResource`) | `s3:ListTagsForResource` |
| `POST` | `/v20180820/tags/{resourceArn}` | Adds tags to a bucket, or changes their values (`TagResource`), with ABAC too | `s3:TagResource` |
| `DELETE` | `/v20180820/tags/{resourceArn}` | Removes a bucket's tags by key (`UntagResource`), with ABAC too | `s3:UntagResource` |

### IAM and STS

| Method | Path | What it does | Who may |
|---|---|---|---|
| `POST` | `/` | The IAM and STS Query APIs: each call names its action in the signed form | the action each call names |

### MinIO's admin and KMS APIs

| Method | Path | What it does | Who may |
|---|---|---|---|
| `PUT` | `/minio/admin/v3/set-bucket-quota` | Sets `?bucket=NAME`'s hard quota in bytes (`{"size":N,"quotatype":"hard"}`, or `quota` for `size`), or clears it with none: `mc quota set` and `clear` | `admin:SetBucketQuota` |
| `GET` | `/minio/admin/v3/get-bucket-quota` | `?bucket=NAME`'s quota (`quota` and `size` in bytes, `0` for none): `mc quota info` | `admin:GetBucketQuota` |
| `GET` | `/minio/admin/v3/accountinfo` | The caller's name and policy, and the buckets it may read (`s3:ListBucket`) or write (`s3:PutObject`) with what each holds and has turned on: `mc admin accountinfo`, the console's buckets | anyone who signs, about themselves |
| `PUT` | `/minio/admin/v3/add-user` | Makes user `?accessKey=` (an IAM user of that name, signing with a key of that id) or changes its secret and status; the body is an encrypted `AddOrUpdateUserReq`: `mc admin user add` | `admin:CreateUser`, or anyone on their own key unless denied |
| `POST` | `/minio/admin/v3/change-my-password` | A new secret (an encrypted `AddOrUpdateUserReq`) for the access key that signs the request | `admin:ChangeMyPassword`, or anyone on their own key unless denied |
| `DELETE` | `/minio/admin/v3/remove-user` | Deletes user `?accessKey=` with its keys, policies and memberships: `mc admin user rm` | `admin:DeleteUser` |
| `GET` | `/minio/admin/v3/list-users` | Every user's `UserInfo` by name, encrypted: `mc admin user ls` | `admin:ListUsers` |
| `GET` | `/minio/admin/v3/user-info` | User `?accessKey=`'s `UserInfo` (status, policies, groups): `mc admin user info` | `admin:GetUser`, or anyone on their own key unless denied |
| `PUT` | `/minio/admin/v3/set-user-status` | Enables or disables user `?accessKey=` (`&status=enabled|disabled`); a disabled user's keys and sessions don't sign: `mc admin user enable` and `disable` | `admin:EnableUser` |
| `PUT` | `/minio/admin/v3/update-group-members` | Adds members to a group (made if needed) or removes them, or the group when it's empty (`GroupAddRemove`): `mc admin group add` and `rm` | `admin:AddUserToGroup` |
| `GET` | `/minio/admin/v3/group` | Group `?group=`'s `GroupDesc`: `mc admin group info` | `admin:GetGroup` |
| `GET` | `/minio/admin/v3/groups` | Every group's name: `mc admin group ls` | `admin:ListGroups` |
| `PUT` | `/minio/admin/v3/set-group-status` | Enables or disables group `?group=` (`&status=`); a disabled group's policies don't count: `mc admin group enable` and `disable` | `admin:EnableGroup` |
| `PUT` | `/minio/admin/v3/add-canned-policy` | Makes policy `?name=` from the body's document or gives it a new version; a built-in name with `&overrideBuiltin=true`, and `&resetBuiltin=true` removes the override: `mc admin policy create` | `admin:CreatePolicy` |
| `GET` | `/minio/admin/v3/info-canned-policy` | Policy `?name=`'s document, or with `&v=2` its `PolicyInfo`: `mc admin policy info` | `admin:GetPolicy` |
| `GET` | `/minio/admin/v3/list-canned-policies` | Every policy's document by name, built-in ones included: `mc admin policy ls` | `admin:ListUserPolicies` |
| `DELETE` | `/minio/admin/v3/remove-canned-policy` | Deletes policy `?name=`, which nothing may use: `mc admin policy rm` | `admin:DeletePolicy` |
| `PUT` | `/minio/admin/v3/set-user-or-group-policy` | Maps exactly `?policyName=` (comma-separated; empty: none) to `?userOrGroup=` (`?isGroup=true|false`), a built-in user or group or else the LDAP directory's: `MinIO`'s older `mc admin policy set` | `admin:AttachUserOrGroupPolicy` |
| `POST` | `/minio/admin/v3/idp/builtin/policy/attach` | Attaches policies to a user or group (an encrypted `PolicyAssociationReq`), answering what changed, encrypted: `mc admin policy attach` | `admin:UpdatePolicyAssociation` |
| `POST` | `/minio/admin/v3/idp/builtin/policy/detach` | Detaches policies from a user or group, as `attach`: `mc admin policy detach` | `admin:UpdatePolicyAssociation` |
| `GET` | `/minio/admin/v3/idp/builtin/policy-entities` | Who has which policies (`?user=`, `?group=`, `?policy=`, each repeated, or all), encrypted: `mc admin policy entities` | `admin:ListUserPolicies` |
| `PUT` | `/minio/admin/v3/add-service-account` | Makes a service account for the encrypted `AddServiceAccountReq`'s `targetUser` (the caller's own user by default) and answers its credentials, encrypted: `mc admin user svcacct add`, `mc admin accesskey create` | `admin:CreateServiceAccount`, or anyone on their own key unless denied |
| `POST` | `/minio/admin/v3/update-service-account` | Changes service account `?accessKey=` as the encrypted `UpdateServiceAccountReq` says; what it leaves out stays: `mc admin user svcacct edit` | `admin:UpdateServiceAccount` |
| `GET` | `/minio/admin/v3/info-service-account` | Service account `?accessKey=`: its parent, status, policy (its parent's when implied), name, description and expiry, encrypted: `mc admin user svcacct info` | `admin:ListServiceAccounts`, or anyone on their own key unless denied |
| `GET` | `/minio/admin/v3/list-service-accounts` | The service accounts of `?user=` (the caller's own user by default), encrypted: `mc admin user svcacct list` | `admin:ListServiceAccounts`, or anyone on their own key unless denied |
| `DELETE` | `/minio/admin/v3/delete-service-account` | Deletes service account `?accessKey=`: `mc admin user svcacct rm` | `admin:RemoveServiceAccount`, or anyone on their own key unless denied |
| `POST` | `/minio/admin/v3/revoke-tokens/{userProvider}` | Ends the temporary credentials of `?user=` (`builtin` or `ldap` `{userProvider}`; without the action or a user, the caller's own) issued until now: all of them (`fullRevoke=true`) or those of `tokenRevokeType`: `mc admin user revoke`, `mc idp ldap revoke` | `admin:RemoveServiceAccount`, or anyone on their own key unless denied |
| `GET` | `/minio/admin/v3/list-access-keys-bulk` | The service accounts of `?users=` (repeated), every user's with `all=true` (which needs `admin:ListUsers`), or the caller's, by `listType` (`users-only`, `sts-only`, `svcacc-only`, `all`), encrypted: `mc admin accesskey ls` | `admin:ListServiceAccounts`, or anyone on their own key unless denied |
| `GET` | `/minio/admin/v3/info-access-key` | Access key `?accessKey=` (the caller's by default) when it's a service account, encrypted: `mc admin accesskey info` | `admin:ListServiceAccounts`, or anyone on their own key unless denied |
| `POST` | `/minio/admin/v3/idp/ldap/policy/attach` | Maps policies to an LDAP user (by name or DN) or group (by DN), from an encrypted `PolicyAssociationReq`, answering what changed, encrypted: `mc idp ldap policy attach` | `admin:UpdatePolicyAssociation` |
| `POST` | `/minio/admin/v3/idp/ldap/policy/detach` | Unmaps policies from an LDAP user or group, as `attach`: `mc idp ldap policy detach` | `admin:UpdatePolicyAssociation` |
| `GET` | `/minio/admin/v3/idp/ldap/policy-entities` | Which LDAP users and groups have which policies (`?user=`, `?group=`, `?policy=`, each repeated, or all), encrypted: `mc idp ldap policy entities` | `admin:ListUserPolicies`, `admin:ListUsers` or `admin:ListGroups` |
| `PUT` | `/minio/admin/v3/idp/ldap/add-service-account` | Makes a service account for the encrypted request's `targetUser`, an LDAP user's name (the caller's own LDAP user by default), and answers its credentials, encrypted: `mc idp ldap accesskey create` | `admin:CreateServiceAccount`, or anyone on their own key unless denied |
| `GET` | `/minio/admin/v3/idp/ldap/list-access-keys` | LDAP user `?userDN=`'s service accounts (the caller's own by default), encrypted | `admin:ListServiceAccounts`, or anyone on their own key unless denied |
| `GET` | `/minio/admin/v3/idp/ldap/list-access-keys-bulk` | LDAP users' service accounts by DN (`?userDNs=`, repeated; the caller's own by default; `&all=true` with `admin:ListUsers`), encrypted: `mc idp ldap accesskey ls` | `admin:ListServiceAccounts`, or anyone on their own key unless denied |
| `GET` | `/minio/admin/v3/idp/openid/list-access-keys-bulk` | OpenID Connect users' access keys by configuration, of which none are kept, encrypted: `mc idp openid accesskey ls` | `admin:ListServiceAccounts`, or anyone on their own key unless denied |
| `GET` | `/minio/admin/v3/temporary-account-info` | Temporary credentials `?accessKey=`: TeiFS keeps nothing about a session, so always `XMinioAdminNoSuchAccessKey` | `admin:ListTemporaryAccounts` |
| `GET` | `/minio/admin/v3/info` | The server as `madmin.InfoMessage`: one server with one pool of one set, its drives the disks the drive uses, what it holds, and whether its KMS and LDAP directory answer: `mc admin info` | `admin:ServerInfo` |
| `GET` | `/minio/admin/v3/storageinfo` | The drive's disks and their room as `madmin.StorageInfo` | `admin:StorageInfo` |
| `GET` | `/minio/admin/v3/datausageinfo` | What each bucket holds as `madmin.DataUsageInfo`, with the disks' room when `?capacity=true`: `mc admin info`, the console's dashboard | `admin:DataUsageInfo` |
| `POST` | `/minio/admin/v3/service` | Restarts or stops the server once it has answered, or freezes S3's requests until as many unfreezes have come, as `?action=` (`restart`, `stop`, `freeze`, `unfreeze`) asks; with `?dry-run=true` it only answers. Restarting needs `admin:ServiceRestart`, stopping `admin:ServiceStop`, freezing and unfreezing `admin:ServiceFreeze`: `mc admin service` | the action each call names |
| `GET` | `/minio/admin/v3/trace` | A live trace as `madmin.TraceInfo` documents, until the caller leaves: S3's requests as `MinIO`'s S3 type, the other APIs' as its internal type, filtered by `types` (or `s3`, `internal`, `all`), `err` and `threshold`; headers and queries with their secrets redacted: `mc admin trace` | `admin:ServerTrace` |
| `GET` | `/minio/admin/v3/log` | The server's log as `madmin.LogInfo` documents: the last `limit` lines (of the 10,000 kept) of the kind `logType` asks (`ERROR`, `WARNING`, `INFO`; all by default), then each as it's logged, until the caller leaves: `mc admin logs` | `admin:ConsoleLog` |
| `GET` | `/minio/admin/v3/metrics` | Live metrics as `madmin.RealtimeMetrics` documents, the first at once and then one every `interval` (a second at least), `n` times or until the caller leaves: S3's requests being served and those answered since the server started, `MinIO`'s API metrics: `mc admin scanner status` | `admin:ServerInfo` |
| `GET` | `/minio/admin/v3/top/locks` | The oldest locks held, as `madmin.LockEntries`: always none, since a request holds no lock past its answer: `mc admin top locks` | `admin:TopLocksInfo` |
| `POST` | `/minio/admin/v3/force-unlock` | Releases the locks `paths` names: none is ever held past a request, so there's nothing to release: `mc admin force-unlock` | `admin:ForceUnlock` |
| `POST` | `/minio/admin/v3/heal/` | Starts a heal of every bucket, as `madmin.HealOpts` asks, and answers its token; with `?clientToken=` the results since the last call; `?forceStart`, `?forceStop`. One drive has no other copy to heal from: a heal checks each bucket and object and reports it, changing nothing; a deep scan reads each version's bytes, as `teifs verify` does: `mc admin heal` | `admin:Heal` |
| `POST` | `/minio/admin/v3/heal/{path}` | A heal of one bucket, or of its objects under a prefix (`{bucket}/{prefix}`): as `heal/`: `mc admin heal ALIAS/BUCKET/PREFIX` | `admin:Heal` |
| `GET` | `/minio/admin/v3/pools/list` | The server's pools as `madmin.PoolStatus`: the drive, its only pool, named by its path: `mc admin decommission status` | `admin:ServerInfo` or `admin:Decommission` |
| `GET` | `/minio/admin/v3/pools/status` | The `pool` named (its path, or `0` with `by-id=true`) as `madmin.PoolStatus` | `admin:ServerInfo` or `admin:Decommission` |
| `POST` | `/minio/admin/v3/pools/decommission` | 501 NotImplemented: the drive is the only pool, with no other to move its objects to: `mc admin decommission start` | `admin:Decommission` |
| `POST` | `/minio/admin/v3/pools/cancel` | 501 NotImplemented, as no decommission can run: `mc admin decommission cancel` | `admin:Decommission` |
| `POST` | `/minio/admin/v3/rebalance/start` | 501 NotImplemented: one pool has nothing to balance with: `mc admin rebalance start` | `admin:Rebalance` |
| `GET` | `/minio/admin/v3/rebalance/status` | 404 XMinioAdminRebalanceNotStarted, as MinIO answers when none runs: `mc admin rebalance status` | `admin:Rebalance` |
| `POST` | `/minio/admin/v3/rebalance/stop` | 501 NotImplemented, as no rebalance can run: `mc admin rebalance stop` | `admin:Rebalance` |
| `POST` | `/minio/admin/v3/profile` | Takes the `profilerType` profiles (`cpu`) for `duration` (a minute unless told, an hour at most) and answers them in a zip with `cluster.info`, as MinIO does: `mc admin profile`, `mc support profile` | `admin:Profiling` |
| `POST` | `/minio/admin/v3/profiling/start` | Starts the `profilerType` profiles, answering a `madmin.StartProfilingResult` for each: MinIO's older profiling calls | `admin:Profiling` |
| `GET` | `/minio/admin/v3/profiling/download` | Stops the profiles started and answers them in a zip, as `POST profile` does | `admin:Profiling` |
| `POST` | `/minio/admin/v3/speedtest` | Measures the store: writes objects of `size` with `concurrent` writers for `duration`, reads them back as long, and streams `madmin.SpeedTestResult`; `autotune` adds writers while reads get faster. S3's requests wait meanwhile: `mc admin speedtest` | `admin:OBDInfo` |
| `POST` | `/minio/admin/v3/speedtest/object` | Measures the store: writes objects of `size` with `concurrent` writers for `duration`, reads them back as long, and streams `madmin.SpeedTestResult`; `autotune` adds writers while reads get faster. S3's requests wait meanwhile: `mc admin speedtest` | `admin:OBDInfo` |
| `POST` | `/minio/admin/v3/speedtest/drive` | Writes a file of `filesize` to each disk in blocks of `blocksize`, syncs it and reads it back: `madmin.DriveSpeedTestResult`, `mc support perf drive` | `admin:OBDInfo` |
| `POST` | `/minio/admin/v3/speedtest/net` | 501 NotImplemented: a server is one node, with no network between nodes to measure | `admin:OBDInfo` |
| `POST` | `/minio/admin/v3/speedtest/site` | 501 NotImplemented: there are no other sites to measure the network to | `admin:OBDInfo` |
| `POST` | `/minio/admin/v3/background-heal/status` | The background heal's status as `madmin.BgHealState`: the drive's scrub, with the versions it checked and the drive's disks: `mc admin heal` with no target | `admin:Heal` |
| `POST` | `/minio/admin/v3/kms/status` | The KMS as `madmin.KMSStatus`: its kind, default key, and whether each of its endpoints answers (older clients; newer ones call `/minio/kms/v1/status`) | `admin:KMSKeyStatus` |
| `POST` | `/minio/admin/v3/kms/key/create` | Creates the KMS key `?key-id=` (older clients; newer ones call `/minio/kms/v1/key/create`) | `admin:KMSCreateKey` |
| `GET` | `/minio/admin/v3/kms/key/status` | Whether KMS key `?key-id=` (the default key by default) seals a new data key and unseals it again, as `madmin.KMSKeyStatus` (older clients; newer ones call `/minio/kms/v1/key/status`) | `admin:KMSKeyStatus` |
| `GET` | `/minio/kms/v1/status` | The KMS as `madmin.KMSStatus`: its kind, default key, and whether each of its endpoints answers: `mc admin kms status` | `kms:Status` |
| `GET` | `/minio/kms/v1/metrics` | The KMS's calls since the server started (sealing, unsealing, creating and rotating keys): how many succeeded, were refused and failed, and a cumulative latency histogram | `kms:Metrics` |
| `GET` | `/minio/kms/v1/apis` | The KMS API's calls, as `madmin.KMSAPI` | `kms:API` |
| `GET` | `/minio/kms/v1/version` | The server's version, as `madmin.KMSVersion` | `kms:Version` |
| `POST` | `/minio/kms/v1/key/create` | Creates KMS key `?key-id=`: `mc admin kms key create` | `kms:CreateKey` |
| `GET` | `/minio/kms/v1/key/list` | The KMS keys whose names start with `?pattern=` (`*` or nothing for all) that the caller may list, as `madmin.KMSKeyInfo`: `mc admin kms key list` | `kms:ListKeys` |
| `GET` | `/minio/kms/v1/key/status` | Whether KMS key `?key-id=` (the default key by default) seals a new data key and unseals it again, as `madmin.KMSKeyStatus`: `mc admin kms key status` | `kms:KeyStatus` |
| `GET` | `/minio/admin/v3/get-config-kv` | A sub-system's settings (`?key=subsys`, `subsys:` for its default target, `subsys:target` for one), without secrets, as key-value lines encrypted with the caller's secret key: `mc admin config get` | `admin:ConfigUpdate` |
| `PUT` | `/minio/admin/v3/set-config-kv` | Sets the key-value lines of the encrypted body; they take effect when the server starts again: `mc admin config set` | `admin:ConfigUpdate` |
| `DELETE` | `/minio/admin/v3/del-config-kv` | Resets the targets or keys the encrypted body names to their defaults: `mc admin config reset` | `admin:ConfigUpdate` |
| `GET` | `/minio/admin/v3/help-config-kv` | Help for sub-system `?subSys=` (all of them when empty) or its key `?key=`, keys named by their variables with `?env`, as `madmin.Help` | `admin:ConfigUpdate` |
| `GET` | `/minio/admin/v3/list-config-history-kv` | The newest `?count=` changes (0 for all), oldest first, as `madmin.ConfigHistoryEntry` encrypted with the caller's secret key: `mc admin config history` | `admin:ConfigUpdate` |
| `DELETE` | `/minio/admin/v3/clear-config-history-kv` | Forgets change `?restoreId=` (`all` for every one) | `admin:ConfigUpdate` |
| `PUT` | `/minio/admin/v3/restore-config-history-kv` | Sets change `?restoreId=`'s lines again, then forgets it: `mc admin config restore` | `admin:ConfigUpdate` |
| `GET` | `/minio/admin/v3/config` | The whole configuration, secrets included, encrypted with the caller's secret key: `mc admin config export` | `admin:ConfigUpdate` |
| `PUT` | `/minio/admin/v3/config` | Replaces the whole configuration with the encrypted body's: `mc admin config import` | `admin:ConfigUpdate` |
| `PUT` | `/minio/admin/v3/idp-config/{type}/{name}` | Adds identity provider configuration `{name}` (`_` for the default; LDAP has only that) of `{type}` `ldap` or `openid`, from the encrypted body's `key=value` pairs; it takes effect when the server starts again: `mc admin idp ldap|openid add` | `admin:ConfigUpdate` |
| `POST` | `/minio/admin/v3/idp-config/{type}/{name}` | Changes identity provider configuration `{name}` with the encrypted body's `key=value` pairs: `mc admin idp ldap|openid update` | `admin:ConfigUpdate` |
| `GET` | `/minio/admin/v3/idp-config/{type}/{name}` | Identity provider configuration `{name}`'s values (from the drive's configuration or `MinIO`'s variables, without secrets) and role ARN, as `madmin.IDPConfig` encrypted with the caller's secret key: `mc admin idp ldap|openid info` | `admin:ConfigUpdate` |
| `GET` | `/minio/admin/v3/idp-config/{type}` | The identity provider configurations of `{type}`, whether each is on and its role ARN, as `madmin.IDPListItem` encrypted with the caller's secret key: `mc admin idp ldap|openid list` | `admin:ConfigUpdate` |
| `DELETE` | `/minio/admin/v3/idp-config/{type}/{name}` | Removes identity provider configuration `{name}` (not one `MinIO`'s variables set): `mc admin idp ldap|openid remove` | `admin:ConfigUpdate` |
| `GET` | `/minio/admin/v3/export-iam` | A zip of `MinIO`'s `iam-assets/*.json` with the IAM's policies, users, groups, service accounts and the policies mapped to them, secrets included: `mc admin cluster iam export` | root user |
| `PUT` | `/minio/admin/v3/import-iam` | Merges such a zip (from TeiFS or `MinIO`) into the IAM: `mc admin cluster iam import` | root user |
| `PUT` | `/minio/admin/v3/import-iam-v2` | Merges such a zip and answers what it added, removed, skipped and couldn't, as `madmin.ImportIAMResult` | root user |
| `GET` | `/minio/admin/v3/export-bucket-metadata` | A zip of every bucket's (`?bucket=NAME`: one's) settings as `MinIO`'s files: `{bucket}/policy.json`, `notification.xml`, `lifecycle.xml`, `bucket-encryption.xml`, `tagging.xml`, `quota.json`, `object-lock.xml`, `versioning.xml` and `cors.xml`: `mc admin cluster bucket export` | `admin:ExportBucketMetadata` |
| `PUT` | `/minio/admin/v3/import-bucket-metadata` | Makes the buckets of such a zip (from TeiFS or `MinIO`) that aren't there and applies their settings, checked as S3's calls check them; answers each file's outcome as `madmin.BucketMetaImportErrs`: `mc admin cluster bucket import` | `admin:ImportBucketMetadata` |

<!-- end generated -->

## Messages

Requests and answers are JSON objects with camelCase fields, defined with their
documentation in `teifs_types::admin` (`crates/types/src/admin.rs`), which the server and
clients share. Times are milliseconds since the Unix epoch (`startedMs`), and values that
name a choice (a layout, a durability) are strings, so a client keeps working when a
later server adds one. A client should ignore fields it doesn't know; an IAM import is
the exception, and refuses them, so nothing in an export is silently dropped.

An IAM export (`teifs-iam/1`) names users, groups, roles, policies and OpenID Connect
providers by name, not by id, so it can be imported into another drive's account. An
import makes everything with the IAM API's own checks, in one transaction or not at all;
gives everything new unique ids (names and ARNs stay); numbers policy versions from
`v1`; and skips, and reports, keys exported without secrets.

## Errors

Errors are JSON with the HTTP status that fits, and the request id (16 hex digits, as
every answer's, S3's included) also in the `x-amz-request-id` header:

```json
{"code":"AccessDenied","message":"…","requestId":"…"}
```

IAM's own errors keep IAM's code and status (`EntityAlreadyExists`, `409`). A path or
method the admin API doesn't serve is `404 NotFound`. Requests refused before they reach
the admin API (a signature that doesn't match, an unknown key) get S3's XML errors, as
from any S3 request; `teifs-client` reads both. `MinIO`'s admin API answers errors as
`MinIO` does, the JSON its clients read:

```json
{"Code":"NoSuchBucket","Message":"…","Resource":"/minio/admin/v3/get-bucket-quota","RequestId":"…"}
```

## Metrics

`GET /.teifs/metrics` serves Prometheus metrics in the OpenMetrics text format, beside
the admin API rather than in it: Prometheus can't sign requests, so a scrape carries a
bearer token instead, which `teifs admin prometheus generate ALIAS` makes and
[OPERATIONS.md](OPERATIONS.md) describes with every metric.
