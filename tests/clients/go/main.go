// The AWS SDK for Go v2 against TeiFS: what applications do with it; and madmin-go, the
// library `mc` calls MinIO's admin API with, for bucket quotas, users, groups, policies,
// the KMS, settings, traces and logs.
package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/google/pprof/profile"
	"github.com/minio/madmin-go/v3"
)

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed:", err)
		os.Exit(1)
	}
}

func check(ok bool, what string) {
	if !ok {
		fmt.Fprintln(os.Stderr, "failed:", what)
		os.Exit(1)
	}
}

func step(text string) { fmt.Println("==", text) }

func main() {
	ctx := context.Background()
	bucket := aws.String(os.Getenv("BUCKET"))
	cfg, err := config.LoadDefaultConfig(ctx)
	must(err)
	s3c := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(os.Getenv("ENDPOINT"))
		o.UsePathStyle = true
	})

	step("bucket")
	_, err = s3c.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: bucket})
	must(err)

	step("put with the SDK's default checksum, get, head")
	small, err := os.ReadFile("small.txt")
	must(err)
	_, err = s3c.PutObject(ctx, &s3.PutObjectInput{
		Bucket: bucket, Key: aws.String("small.txt"), Body: bytes.NewReader(small),
		Metadata: map[string]string{"owner": "go"},
	})
	must(err)
	got, err := s3c.GetObject(ctx, &s3.GetObjectInput{Bucket: bucket, Key: aws.String("small.txt")})
	must(err)
	body, err := io.ReadAll(got.Body)
	must(err)
	check(bytes.Equal(body, small), "get returns what was put")
	head, err := s3c.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: bucket, Key: aws.String("small.txt"), ChecksumMode: types.ChecksumModeEnabled,
	})
	must(err)
	check(head.Metadata["owner"] == "go", "metadata kept")

	step("multipart upload and download through the transfer manager")
	big, err := os.ReadFile("big.bin")
	must(err)
	uploader := manager.NewUploader(s3c, func(u *manager.Uploader) { u.PartSize = 5 << 20 })
	_, err = uploader.Upload(ctx, &s3.PutObjectInput{Bucket: bucket, Key: aws.String("big.bin"), Body: bytes.NewReader(big)})
	must(err)
	buf := manager.NewWriteAtBuffer(nil)
	downloader := manager.NewDownloader(s3c, func(d *manager.Downloader) { d.PartSize = 5 << 20 })
	_, err = downloader.Download(ctx, buf, &s3.GetObjectInput{Bucket: bucket, Key: aws.String("big.bin")})
	must(err)
	check(sha256.Sum256(buf.Bytes()) == sha256.Sum256(big), "multipart round trip")

	step("copy, paginate, delete many")
	_, err = s3c.CopyObject(ctx, &s3.CopyObjectInput{
		Bucket: bucket, Key: aws.String("copy.txt"), CopySource: aws.String(*bucket + "/small.txt"),
	})
	must(err)
	for i := 0; i < 12; i++ {
		_, err = s3c.PutObject(ctx, &s3.PutObjectInput{
			Bucket: bucket, Key: aws.String(fmt.Sprintf("many/%03d", i)), Body: bytes.NewReader([]byte("x")),
		})
		must(err)
	}
	var ids []types.ObjectIdentifier
	pages := s3.NewListObjectsV2Paginator(s3c, &s3.ListObjectsV2Input{Bucket: bucket, MaxKeys: aws.Int32(5)})
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		must(err)
		for _, o := range page.Contents {
			ids = append(ids, types.ObjectIdentifier{Key: o.Key})
		}
	}
	check(len(ids) == 15, fmt.Sprintf("15 objects listed, not %d", len(ids)))

	step("presigned GET")
	link, err := s3.NewPresignClient(s3c).PresignGetObject(ctx,
		&s3.GetObjectInput{Bucket: bucket, Key: aws.String("small.txt")},
		s3.WithPresignExpires(time.Minute))
	must(err)
	resp, err := http.Get(link.URL)
	must(err)
	linked, err := io.ReadAll(resp.Body)
	must(err)
	check(resp.StatusCode == 200 && bytes.Equal(linked, small), "presigned link")

	step("a bucket quota through MinIO's admin API, as mc quota sets it")
	endpoint, err := url.Parse(os.Getenv("ENDPOINT"))
	must(err)
	adm, err := madmin.New(endpoint.Host, os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY"), false)
	must(err)
	must(adm.SetBucketQuota(ctx, *bucket, &madmin.BucketQuota{Quota: 1024, Type: madmin.HardQuota}))
	quota, err := adm.GetBucketQuota(ctx, *bucket)
	must(err)
	check(quota.Size == 1024 && quota.Type == madmin.HardQuota, fmt.Sprintf("the quota read back: %+v", quota))
	_, err = s3c.PutObject(ctx, &s3.PutObjectInput{
		Bucket: bucket, Key: aws.String("over.txt"), Body: bytes.NewReader([]byte("x")),
	})
	var refused smithy.APIError
	check(errors.As(err, &refused) && refused.ErrorCode() == "XMinioAdminBucketQuotaExceeded",
		fmt.Sprintf("a write past the quota refused: %v", err))
	must(adm.SetBucketQuota(ctx, *bucket, &madmin.BucketQuota{}))
	quota, err = adm.GetBucketQuota(ctx, *bucket)
	must(err)
	check(quota.Size == 0 && quota.Quota == 0, fmt.Sprintf("the quota cleared: %+v", quota))

	minioIAM(ctx, adm)
	serverInfo(ctx, adm, *bucket)
	service(ctx, adm)
	kms(ctx, adm)
	configKV(ctx, adm)
	idpConfig(ctx, adm)
	trace(ctx, adm, s3c, *bucket)
	consoleLog(ctx, adm)
	realtime(ctx, adm)
	heal(ctx, adm, *bucket)
	speedtest(ctx, adm)
	cpuProfile(ctx, adm)
	pools(ctx, adm)

	step("empty and remove the bucket")
	_, err = s3c.DeleteObjects(ctx, &s3.DeleteObjectsInput{Bucket: bucket, Delete: &types.Delete{Objects: ids}})
	must(err)
	_, err = s3c.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: bucket})
	must(err)
	fmt.Println("ok")
}

// trace is mc admin trace: S3's calls as MinIO's trace documents, filtered on the server.
func trace(ctx context.Context, adm *madmin.AdminClient, s3c *s3.Client, bucket string) {
	step("a live trace, as mc admin trace reads it")
	traced, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	traces := adm.ServiceTrace(traced, madmin.ServiceTraceOpts{S3: true, OnlyErrors: true})
	// The trace starts once the server answers it: ask until one comes.
	go func() {
		for traced.Err() == nil {
			_, _ = s3c.GetObject(traced, &s3.GetObjectInput{Bucket: &bucket, Key: aws.String("not-there")})
			_, _ = s3c.ListObjectsV2(traced, &s3.ListObjectsV2Input{Bucket: &bucket})
			time.Sleep(200 * time.Millisecond)
		}
	}()
	info, ok := <-traces
	check(ok, "a trace came")
	must(info.Err)
	got := info.Trace
	check(got.FuncName == "s3.GetObject" && got.TraceType == madmin.TraceS3 && got.HTTP != nil &&
		got.HTTP.RespInfo.StatusCode == 404 && got.HTTP.ReqInfo.Method == "GET",
		fmt.Sprintf("only the failed call traced: %+v", got))
}

// consoleLog is mc admin logs: the server's last lines (there may be none), each a
// madmin.LogInfo.
func consoleLog(ctx context.Context, adm *madmin.AdminClient) {
	step("the server's log, as mc admin logs reads it")
	read, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	select {
	case info, ok := <-adm.GetLogs(read, "", 10, "all"):
		if ok {
			must(info.Err)
			check(info.LogKind != "" && info.Time != "", fmt.Sprintf("a log line: %+v", info))
		}
	case <-read.Done():
	}
}

// realtime is the console's realtime view and mc admin top locks: two metrics
// documents, the last one final, and no locks held.
func realtime(ctx context.Context, adm *madmin.AdminClient) {
	step("live metrics and locks, as mc admin scanner status and top locks read them")
	var seen []madmin.RealtimeMetrics
	must(adm.Metrics(ctx, madmin.MetricsOptions{Type: madmin.MetricsAll, N: 2, Interval: time.Second},
		func(m madmin.RealtimeMetrics) { seen = append(seen, m) }))
	check(len(seen) == 2 && seen[1].Final && len(seen[0].Hosts) == 1,
		fmt.Sprintf("the metrics: %+v", seen))
	locks, err := adm.TopLocks(ctx)
	must(err)
	check(len(locks) == 0, fmt.Sprintf("the locks: %+v", locks))
}

// heal is mc admin heal: a deep, recursive heal of the bucket polled with its token
// until it's done, every item intact, then the background heal's status.
func heal(ctx context.Context, adm *madmin.AdminClient, bucket string) {
	step("a deep heal of the bucket and the background heal, as mc admin heal runs them")
	opts := madmin.HealOpts{Recursive: true, ScanMode: madmin.HealDeepScan}
	started, _, err := adm.Heal(ctx, bucket, "", opts, "", false, false)
	must(err)
	check(started.ClientToken != "", fmt.Sprintf("the heal started: %+v", started))
	var items []madmin.HealResultItem
	for i := 0; ; i++ {
		_, status, err := adm.Heal(ctx, bucket, "", opts, started.ClientToken, false, false)
		must(err)
		items = append(items, status.Items...)
		if status.Summary != "running" {
			check(status.Summary == "finished", fmt.Sprintf("the heal ended: %+v", status))
			break
		}
		check(i < 200, "the heal didn't finish")
		time.Sleep(50 * time.Millisecond)
	}
	check(len(items) > 1 && items[0].Type == madmin.HealItemBucket, fmt.Sprintf("the items: %+v", items))
	for _, item := range items {
		b, a := item.GetCorruptedCounts()
		check(b == 0 && a == 0, fmt.Sprintf("a damaged item: %+v", item))
	}
	state, err := adm.BackgroundHealStatus(ctx)
	must(err)
	check(len(state.Sets) == 1, fmt.Sprintf("the background heal: %+v", state))
}

func speedtest(ctx context.Context, adm *madmin.AdminClient) {
	step("the object and drive speed tests, as mc admin speedtest and mc support perf drive run them")
	results, err := adm.Speedtest(ctx, madmin.SpeedtestOpts{Size: 64 << 10, Concurrency: 2, Duration: 2 * time.Second})
	must(err)
	var last madmin.SpeedTestResult
	for result := range results {
		last = result
	}
	check(last.Servers == 1 && last.PUTStats.ThroughputPerSec > 0 && last.GETStats.ThroughputPerSec > 0,
		fmt.Sprintf("the object speed test: %+v", last))
	check(last.GETStats.Servers[0].Err == "", fmt.Sprintf("the object speed test failed: %+v", last))
	drives, err := adm.DriveSpeedtest(ctx, madmin.DriveSpeedTestOpts{BlockSize: 64 << 10, FileSize: 1 << 20})
	must(err)
	var disks []madmin.DrivePerf
	for result := range drives {
		disks = append(disks, result.DrivePerf...)
	}
	check(len(disks) > 0 && disks[0].Error == "" && disks[0].WriteThroughput > 0 && disks[0].ReadThroughput > 0,
		fmt.Sprintf("the drive speed test: %+v", disks))
}

func cpuProfile(ctx context.Context, adm *madmin.AdminClient) {
	step("a CPU profile, as mc admin profile takes it, read by Go's pprof")
	answer, err := adm.Profile(ctx, madmin.ProfilerCPU, time.Second)
	must(err)
	zipped, err := io.ReadAll(answer)
	must(err)
	answer.Close()
	archive, err := zip.NewReader(bytes.NewReader(zipped), int64(len(zipped)))
	must(err)
	var cpu *zip.File
	for _, file := range archive.File {
		if strings.HasSuffix(file.Name, "-cpu.pprof") {
			cpu = file
		}
	}
	check(cpu != nil && archive.File[0].Name == "cluster.info", fmt.Sprintf("the zip: %+v", archive.File))
	opened, err := cpu.Open()
	must(err)
	parsed, err := profile.Parse(opened)
	must(err)
	check(len(parsed.SampleType) > 0 && parsed.Period > 0, fmt.Sprintf("the profile: %v", parsed))
}

func pools(ctx context.Context, adm *madmin.AdminClient) {
	step("the drive as the only pool, as mc admin decommission and rebalance see it")
	all, err := adm.ListPoolsStatus(ctx)
	must(err)
	check(len(all) == 1 && all[0].ID == 0 && !all[0].LastUpdate.IsZero(), fmt.Sprintf("the pools: %+v", all))
	one, err := adm.StatusPool(ctx, all[0].CmdLine)
	must(err)
	check(one.CmdLine == all[0].CmdLine, fmt.Sprintf("the pool: %+v", one))
	err = adm.DecommissionPool(ctx, all[0].CmdLine)
	check(madmin.ToErrorResponse(err).Code == "NotImplemented", fmt.Sprintf("decommissioning: %v", err))
	_, err = adm.RebalanceStatus(ctx)
	check(madmin.ToErrorResponse(err).Code == "XMinioAdminRebalanceNotStarted", fmt.Sprintf("rebalance status: %v", err))
}

// lists says whether a client signing with this key may list buckets.
func lists(ctx context.Context, accessKey, secret string) bool {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithCredentialsProvider(
		aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: accessKey, SecretAccessKey: secret}, nil
		})))
	must(err)
	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(os.Getenv("ENDPOINT"))
		o.UsePathStyle = true
	})
	_, err = client.ListBuckets(ctx, &s3.ListBucketsInput{})
	return err == nil
}

// minioIAM is mc admin user, group and policy: secrets in bodies encrypted with the
// caller's secret key, as madmin-go encrypts and decrypts them.
func minioIAM(ctx context.Context, adm *madmin.AdminClient) {
	step("a user, a group and policies through MinIO's admin API, as mc admin does")
	must(adm.AddUser(ctx, "go-user", "go-user-secret"))
	info, err := adm.GetUserInfo(ctx, "go-user")
	must(err)
	check(info.Status == madmin.AccountEnabled, fmt.Sprintf("the user's info: %+v", info))
	check(!lists(ctx, "go-user", "go-user-secret"), "a user without policies lists buckets")

	attached, err := adm.AttachPolicy(ctx, madmin.PolicyAssociationReq{
		Policies: []string{"readwrite"}, User: "go-user",
	})
	must(err)
	check(len(attached.PoliciesAttached) == 1, fmt.Sprintf("attached: %+v", attached))
	check(lists(ctx, "go-user", "go-user-secret"), "readwrite lets the user list buckets")
	users, err := adm.ListUsers(ctx)
	must(err)
	check(users["go-user"].PolicyName == "readwrite", fmt.Sprintf("the users: %+v", users))
	entities, err := adm.GetPolicyEntities(ctx, madmin.PolicyEntitiesQuery{Users: []string{"go-user"}})
	must(err)
	check(len(entities.UserMappings) == 1 && entities.UserMappings[0].Policies[0] == "readwrite",
		fmt.Sprintf("the policy entities: %+v", entities))

	must(adm.SetUserStatus(ctx, "go-user", madmin.AccountDisabled))
	check(!lists(ctx, "go-user", "go-user-secret"), "a disabled user's key signs")
	must(adm.SetUserStatus(ctx, "go-user", madmin.AccountEnabled))
	detached, err := adm.DetachPolicy(ctx, madmin.PolicyAssociationReq{
		Policies: []string{"readwrite"}, User: "go-user",
	})
	must(err)
	check(len(detached.PoliciesDetached) == 1, fmt.Sprintf("detached: %+v", detached))

	lister := []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListAllMyBuckets","Resource":"*"}]}`)
	must(adm.AddCannedPolicy(ctx, "go-lister", lister))
	policy, err := adm.InfoCannedPolicyV2(ctx, "go-lister")
	must(err)
	check(policy.PolicyName == "go-lister", fmt.Sprintf("the policy: %+v", policy))
	policies, err := adm.ListCannedPolicies(ctx)
	must(err)
	_, ok := policies["consoleAdmin"]
	check(ok && policies["go-lister"] != nil, "the canned policies, built-in ones too")

	must(adm.UpdateGroupMembers(ctx, madmin.GroupAddRemove{Group: "go-group", Members: []string{"go-user"}}))
	_, err = adm.AttachPolicy(ctx, madmin.PolicyAssociationReq{Policies: []string{"go-lister"}, Group: "go-group"})
	must(err)
	check(lists(ctx, "go-user", "go-user-secret"), "the group's policy lets its member list buckets")
	group, err := adm.GetGroupDescription(ctx, "go-group")
	must(err)
	check(group.Policy == "go-lister" && len(group.Members) == 1, fmt.Sprintf("the group: %+v", group))
	groups, err := adm.ListGroups(ctx)
	must(err)
	check(len(groups) == 1 && groups[0] == "go-group", fmt.Sprintf("the groups: %v", groups))
	must(adm.SetGroupStatus(ctx, "go-group", madmin.GroupDisabled))
	check(!lists(ctx, "go-user", "go-user-secret"), "a disabled group's policy counts")

	account, err := adm.AccountInfo(ctx, madmin.AccountOpts{})
	must(err)
	// Other clients' buckets may be there too: this one's is checked.
	mine := false
	for _, b := range account.Buckets {
		mine = mine || (b.Name == os.Getenv("BUCKET") && b.Access.Read && b.Access.Write)
	}
	check(account.AccountName == os.Getenv("AWS_ACCESS_KEY_ID") && mine,
		fmt.Sprintf("the account's info: %+v", account))

	step("service accounts, as mc admin user svcacct and mc admin accesskey make them")
	root := os.Getenv("AWS_ACCESS_KEY_ID")
	creds, err := adm.AddServiceAccount(ctx, madmin.AddServiceAccountReq{Name: "go-svc", Description: "the go client's"})
	must(err)
	check(lists(ctx, creds.AccessKey, creds.SecretKey), "a root service account lists buckets")
	svc, err := adm.InfoServiceAccount(ctx, creds.AccessKey)
	must(err)
	check(svc.ParentUser == root && svc.ImpliedPolicy && svc.Name == "go-svc" && svc.Expiration == nil,
		fmt.Sprintf("the service account: %+v", svc))
	expires := time.Now().Add(48 * time.Hour).Truncate(time.Second).UTC()
	userSvc, err := adm.AddServiceAccount(ctx, madmin.AddServiceAccountReq{
		TargetUser: "go-user", AccessKey: "go-user-svc", SecretKey: "go-user-svc-secret",
		Policy: lister, Expiration: &expires,
	})
	must(err)
	check(userSvc.AccessKey == "go-user-svc" && userSvc.Expiration.Equal(expires),
		fmt.Sprintf("the user's service account: %+v", userSvc))
	listed, err := adm.ListServiceAccounts(ctx, "go-user")
	must(err)
	check(len(listed.Accounts) == 1 && listed.Accounts[0].AccessKey == "go-user-svc" &&
		!listed.Accounts[0].ImpliedPolicy, fmt.Sprintf("the user's service accounts: %+v", listed))
	must(adm.UpdateServiceAccount(ctx, creds.AccessKey, madmin.UpdateServiceAccountReq{NewStatus: "off"}))
	check(!lists(ctx, creds.AccessKey, creds.SecretKey), "a disabled service account signs")
	keys, err := adm.ListAccessKeysBulk(ctx, nil, madmin.ListAccessKeysOpts{ListType: madmin.AccessKeyListSvcaccOnly, All: true})
	must(err)
	check(len(keys["go-user"].ServiceAccounts) == 1 && len(keys[root].ServiceAccounts) >= 1,
		fmt.Sprintf("the access keys: %+v", keys))
	accessKey, err := adm.InfoAccessKey(ctx, "go-user-svc")
	must(err)
	check(accessKey.UserType == "Service Account" && accessKey.ParentUser == "go-user",
		fmt.Sprintf("the access key: %+v", accessKey))
	must(adm.DeleteServiceAccount(ctx, creds.AccessKey))
	_, err = adm.InfoServiceAccount(ctx, creds.AccessKey)
	check(err != nil, "a deleted service account is still there")

	must(adm.UpdateGroupMembers(ctx, madmin.GroupAddRemove{Group: "go-group", Members: []string{"go-user"}, IsRemove: true}))
	must(adm.UpdateGroupMembers(ctx, madmin.GroupAddRemove{Group: "go-group", IsRemove: true}))
	must(adm.RemoveCannedPolicy(ctx, "go-lister"))
	must(adm.RemoveUser(ctx, "go-user"))
	_, err = adm.GetUserInfo(ctx, "go-user")
	var gone madmin.ErrorResponse
	check(errors.As(err, &gone) && gone.Code == "XMinioAdminNoSuchUser", fmt.Sprintf("a removed user: %v", err))
}

// serverInfo is mc admin info: one server, its drives, and what the bucket holds.
func serverInfo(ctx context.Context, adm *madmin.AdminClient, bucket string) {
	step("the server, its drives and what it holds, as mc admin info reads them")
	info, err := adm.ServerInfo(ctx)
	must(err)
	check(info.Mode == "online" && info.BackendType() == madmin.FS && len(info.Servers) == 1 &&
		len(info.Servers[0].Disks) >= 1 && info.Servers[0].Disks[0].TotalSpace > 0 &&
		info.Buckets.Count >= 1, fmt.Sprintf("the server's info: %+v", info))
	storage, err := adm.StorageInfo(ctx)
	must(err)
	check(storage.Backend.Type == madmin.FS && len(storage.Disks) >= 1,
		fmt.Sprintf("the storage info: %+v", storage))
	usage, err := adm.DataUsageInfo(ctx)
	must(err)
	_, has := usage.BucketsUsage[bucket]
	check(has && usage.TotalCapacity > 0 && usage.TotalCapacity >= usage.TotalUsedCapacity,
		fmt.Sprintf("the data usage: %+v", usage))
}

// The service calls a server answers before it acts: restart and stop only as dry runs
// (the server is everyone's), and a freeze undone at once.
func service(ctx context.Context, adm *madmin.AdminClient) {
	step("service restart and stop (dry runs), freeze and unfreeze, as mc admin service calls them")
	for _, action := range []madmin.ServiceAction{madmin.ServiceActionRestart, madmin.ServiceActionStop} {
		result, err := adm.ServiceAction(ctx, madmin.ServiceActionOpts{Action: action, DryRun: true})
		must(err)
		check(result.Action == action && result.DryRun && len(result.Results) == 1 &&
			result.Results[0].Host != "" && result.Results[0].Err == "",
			fmt.Sprintf("a dry-run %s: %+v", action, result))
	}
	for _, action := range []madmin.ServiceAction{madmin.ServiceActionFreeze, madmin.ServiceActionUnfreeze} {
		result, err := adm.ServiceAction(ctx, madmin.ServiceActionOpts{Action: action})
		must(err)
		check(result.Action == action && !result.DryRun && len(result.Results) == 0,
			fmt.Sprintf("a %s: %+v", action, result))
	}
}

func kms(ctx context.Context, adm *madmin.AdminClient) {
	step("KMS status, version, and a key created, listed and checked, as mc admin kms calls them")
	status, err := adm.KMSStatus(ctx)
	must(err)
	check(status.DefaultKeyID != "" && len(status.Endpoints) > 0, fmt.Sprintf("the KMS status: %+v", status))
	for endpoint, state := range status.Endpoints {
		check(state == madmin.ItemOnline, fmt.Sprintf("KMS endpoint %s is %s", endpoint, state))
	}
	version, err := adm.KMSVersion(ctx)
	must(err)
	check(version.Version != "", "the KMS version")
	name := fmt.Sprintf("go-client-%d", time.Now().UnixNano())
	must(adm.CreateKey(ctx, name))
	keys, err := adm.ListKeys(ctx, "go-client-")
	must(err)
	found := false
	for _, key := range keys {
		found = found || key.Name == name
	}
	check(found, fmt.Sprintf("the new key in %+v", keys))
	keyStatus, err := adm.GetKeyStatus(ctx, name)
	must(err)
	check(keyStatus.KeyID == name && keyStatus.EncryptionErr == "" && keyStatus.DecryptionErr == "",
		fmt.Sprintf("the new key's status: %+v", keyStatus))
}

func idpConfig(ctx context.Context, adm *madmin.AdminClient) {
	step("identity provider configurations added, listed, read, changed and removed, as mc admin idp calls them")
	dex := "config_url=https://dex.example.com/.well-known/openid-configuration client_id=go-client client_secret=go-client-secret role_policy=readonly"
	restart, err := adm.AddOrUpdateIDPConfig(ctx, madmin.OpenidIDPCfg, "dex", dex, false)
	must(err)
	check(restart, "a restart is needed")
	_, err = adm.AddOrUpdateIDPConfig(ctx, madmin.OpenidIDPCfg, "dex", dex, false)
	check(err != nil && madmin.ToErrorResponse(err).Code == "XMinioAdminConfigIDPCfgNameAlreadyExists",
		fmt.Sprintf("a second add is refused: %v", err))
	list, err := adm.ListIDPConfig(ctx, madmin.OpenidIDPCfg)
	must(err)
	check(len(list) == 2 && list[1].Name == "dex" && list[1].Enabled && strings.HasPrefix(list[1].RoleARN, "arn:minio:iam:::role/"),
		fmt.Sprintf("the list: %+v", list))
	info, err := adm.GetIDPConfig(ctx, madmin.OpenidIDPCfg, "dex")
	must(err)
	values := map[string]string{}
	for _, i := range info.Info {
		values[i.Key] = i.Value
	}
	check(info.Name == "dex" && values["client_id"] == "go-client" && values["roleARN"] == list[1].RoleARN && values["client_secret"] == "",
		fmt.Sprintf("the configuration without its secret: %+v", info))
	_, err = adm.AddOrUpdateIDPConfig(ctx, madmin.OpenidIDPCfg, "dex", "enable=off", true)
	must(err)
	list, err = adm.ListIDPConfig(ctx, madmin.OpenidIDPCfg)
	must(err)
	check(!list[1].Enabled && list[1].RoleARN == "", fmt.Sprintf("turned off: %+v", list))
	_, err = adm.AddOrUpdateIDPConfig(ctx, madmin.LDAPIDPCfg, "corp", "server_addr=ldap.example.com:636", false)
	check(err != nil && madmin.ToErrorResponse(err).Code == "XMinioAdminConfigLDAPNonDefaultConfigName",
		fmt.Sprintf("LDAP has one configuration: %v", err))
	_, err = adm.DeleteIDPConfig(ctx, madmin.OpenidIDPCfg, "dex")
	must(err)
	_, err = adm.GetIDPConfig(ctx, madmin.OpenidIDPCfg, "dex")
	check(err != nil && madmin.ToErrorResponse(err).Code == "XMinioAdminNoSuchConfigTarget",
		fmt.Sprintf("removed: %v", err))
	must(adm.ClearConfigHistoryKV(ctx, "all"))
}

func configKV(ctx context.Context, adm *madmin.AdminClient) {
	step("settings set, read, reset, put back, exported and imported, as mc admin config calls them")
	line := `identity_ldap server_addr=ldap.example.com:636 lookup_bind_dn="cn=admin, dc=example" lookup_bind_password=go-client-pw`
	restart, err := adm.SetConfigKV(ctx, line)
	must(err)
	check(restart, "a restart is needed")
	got, err := adm.GetConfigKV(ctx, "identity_ldap")
	must(err)
	text := string(got)
	check(strings.Contains(text, "server_addr=ldap.example.com:636") && !strings.Contains(text, "go-client-pw"),
		"the settings without their secret: "+text)
	help, err := adm.HelpConfigKV(ctx, "identity_ldap", "", false)
	must(err)
	check(help.SubSys == "identity_ldap" && len(help.KeysHelp) > 0, fmt.Sprintf("the help: %+v", help))
	history, err := adm.ListConfigHistoryKV(ctx, 10)
	must(err)
	check(len(history) > 0 && history[len(history)-1].Data == line, fmt.Sprintf("the history: %+v", history))
	_, err = adm.DelConfigKV(ctx, "identity_ldap")
	must(err)
	got, err = adm.GetConfigKV(ctx, "identity_ldap")
	must(err)
	check(!strings.Contains(string(got), "ldap.example.com"), "reset: "+string(got))
	must(adm.RestoreConfigHistoryKV(ctx, history[len(history)-1].RestoreID))
	exported, err := adm.GetConfig(ctx)
	must(err)
	check(strings.Contains(string(exported), "lookup_bind_password=go-client-pw"), "the export has the secret")
	// madmin sends no empty configuration: one with only a comment sets nothing.
	must(adm.SetConfig(ctx, strings.NewReader("# nothing set\n")))
	must(adm.ClearConfigHistoryKV(ctx, "all"))
	got, err = adm.GetConfigKV(ctx, "identity_ldap")
	must(err)
	check(!strings.Contains(string(got), "ldap.example.com"), "imported nothing: "+string(got))
}
