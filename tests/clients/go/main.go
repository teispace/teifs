// The AWS SDK for Go v2 against TeiFS: what applications do with it; and madmin-go, the
// library `mc` calls MinIO's admin API with, for bucket quotas, users, groups and policies.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
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

	step("empty and remove the bucket")
	_, err = s3c.DeleteObjects(ctx, &s3.DeleteObjectsInput{Bucket: bucket, Delete: &types.Delete{Objects: ids}})
	must(err)
	_, err = s3c.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: bucket})
	must(err)
	fmt.Println("ok")
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
	check(account.AccountName == os.Getenv("AWS_ACCESS_KEY_ID") && len(account.Buckets) == 1 &&
		account.Buckets[0].Access.Read && account.Buckets[0].Access.Write,
		fmt.Sprintf("the account's info: %+v", account))

	must(adm.UpdateGroupMembers(ctx, madmin.GroupAddRemove{Group: "go-group", Members: []string{"go-user"}, IsRemove: true}))
	must(adm.UpdateGroupMembers(ctx, madmin.GroupAddRemove{Group: "go-group", IsRemove: true}))
	must(adm.RemoveCannedPolicy(ctx, "go-lister"))
	must(adm.RemoveUser(ctx, "go-user"))
	_, err = adm.GetUserInfo(ctx, "go-user")
	var gone madmin.ErrorResponse
	check(errors.As(err, &gone) && gone.Code == "XMinioAdminNoSuchUser", fmt.Sprintf("a removed user: %v", err))
}
