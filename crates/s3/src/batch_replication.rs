//! S3 Batch Replication: S3 Batch Operations' `S3ReplicateObject`. Each object the
//! manifest lists is replicated at once by the bucket's replication configuration, to
//! every destination its rules send it to, whatever it reached before (never
//! replicated, failed, or replicated already), as the bucket's own replication would
//! send it. The job's role needs only `s3:InitiateReplication` on the objects; what the
//! replication itself may do is the configuration's. A task fails with the reason AWS's
//! replication failure reasons name.

use std::sync::Arc;

use teifs_iam::Identity;
use teifs_policy::object_arn;

use crate::{
    access,
    batch_operations::{Failure, Operations, Task},
};

/// What a task is refused, without `s3:InitiateReplication`.
const NOT_PERMITTED: &str = "InitiateReplicationNotPermitted";

/// Replicates the task's object, if the job's role (`identity`) may.
pub(crate) async fn run(
    operations: &Operations,
    identity: &Arc<Identity>,
    task: &Task,
) -> Result<(), Failure> {
    if !may_initiate(operations, identity, task).await {
        return Err(Failure {
            status: Some(403),
            code: NOT_PERMITTED.to_owned(),
            message: "The job's role may not initiate replication of the object \
                      (s3:InitiateReplication)."
                .to_owned(),
        });
    }
    operations
        .replicator
        .replicate(&task.bucket, &task.key, task.version.as_deref())
        .await
        .map_err(|(code, message)| Failure {
            status: None,
            code: code.to_owned(),
            message,
        })
}

/// Whether the role may start replicating the object: its policies and the bucket's,
/// as for a request of the role's over TLS from no address (what tasks' requests are).
async fn may_initiate(operations: &Operations, identity: &Arc<Identity>, task: &Task) -> bool {
    // A bucket that's gone has no policy; the replicator then says it's gone.
    let rules = operations.rules.of(&task.bucket).await.ok();
    let context = access::base_context(
        identity,
        &http::HeaderMap::new(),
        crate::Client {
            ip: None,
            secure: true,
            tls: None,
        },
        &operations.iam.account(),
    );
    access::allows(
        identity,
        &context,
        "s3:InitiateReplication",
        &object_arn(&task.bucket, &task.key),
        rules.as_deref(),
    )
}
