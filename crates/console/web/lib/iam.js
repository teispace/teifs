// IAM, as AWS's Query API has it: users, access keys, groups and managed and inline
// policies. Parsers here are pure; `iam` makes the calls, paging through lists.

import { query } from "./api.js";
import { child, children, find, text } from "./xml.js";

/** The `<member>`s of `listName` in an action's `<…Result>`. */
export function members(root, listName) {
  const result = root?.name?.endsWith("Result") ? root : root?.children.find((c) => c.name.endsWith("Result"));
  return children(child(result, listName), "member");
}

/** Whether an action's list goes on, and the marker that continues it. */
export function nextMarker(root) {
  const truncated = find(root, "IsTruncated");
  return truncated?.text === "true" ? (find(root, "Marker")?.text ?? "") : "";
}

/** A user, a group or a role: `{ name, id, arn, path, created }`. */
function entity(m, nameTag) {
  return {
    name: text(m, nameTag),
    id: text(m, nameTag.replace("Name", "Id")),
    arn: text(m, "Arn"),
    path: text(m, "Path"),
    created: text(m, "CreateDate"),
  };
}

export const parse = {
  users: (root) => members(root, "Users").map((m) => entity(m, "UserName")),
  groups: (root) => members(root, "Groups").map((m) => entity(m, "GroupName")),
  accessKeys: (root) =>
    members(root, "AccessKeyMetadata").map((m) => ({ id: text(m, "AccessKeyId"), status: text(m, "Status"), created: text(m, "CreateDate") })),
  policies: (root) =>
    members(root, "Policies").map((m) => ({
      name: text(m, "PolicyName"),
      arn: text(m, "Arn"),
      defaultVersion: text(m, "DefaultVersionId"),
      attachments: Number(text(m, "AttachmentCount", "0")),
      description: text(m, "Description"),
      updated: text(m, "UpdateDate"),
    })),
  attached: (root) => members(root, "AttachedPolicies").map((m) => ({ name: text(m, "PolicyName"), arn: text(m, "PolicyArn") })),
  inlineNames: (root) => members(root, "PolicyNames").map((m) => m.text),
  /** `CreateAccessKey`'s key, the only time its secret is shown. */
  newKey: (root) => {
    const key = find(root, "AccessKey");
    return { id: text(key, "AccessKeyId"), secret: text(key, "SecretAccessKey"), status: text(key, "Status") };
  },
  /** A policy document (`GetUserPolicy`'s `PolicyDocument`, `GetPolicyVersion`'s `Document`): URL-encoded JSON. */
  document: (root) => decodeDocument((find(root, "PolicyDocument") ?? find(root, "Document"))?.text ?? ""),
  groupUsers: (root) => members(root, "Users").map((m) => entity(m, "UserName")),
  policy: (root) => {
    const p = find(root, "Policy");
    return { name: text(p, "PolicyName"), arn: text(p, "Arn"), defaultVersion: text(p, "DefaultVersionId"), attachments: Number(text(p, "AttachmentCount", "0")) };
  },
  versions: (root) => members(root, "Versions").map((m) => ({ id: text(m, "VersionId"), isDefault: text(m, "IsDefaultVersion") === "true", created: text(m, "CreateDate") })),
};

/** IAM's documents are URL-encoded JSON (RFC 3986); shown indented. */
export function decodeDocument(encoded) {
  let json = encoded;
  try {
    json = decodeURIComponent(encoded.replace(/\+/g, "%20"));
  } catch {
    // Not encoded: as it is.
  }
  try {
    return JSON.stringify(JSON.parse(json), null, 2);
  } catch {
    return json;
  }
}

/** Why `name` can't name a user, group or policy (IAM's characters and length), or "". */
export function nameProblem(name, max = 64) {
  if (!name) return "Give it a name.";
  if (name.length > max) return `At most ${max} characters.`;
  if (!/^[\w+=,.@-]+$/.test(name)) return "Use letters, digits and + = , . @ _ - only.";
  return "";
}

/** Calls `action`, following `Marker` until the list ends; the parsed items. */
async function all(action, params, parser) {
  const items = [];
  let marker = "";
  do {
    const root = await query("iam", action, { ...params, Marker: marker || undefined, MaxItems: "1000" });
    items.push(...parser(root));
    marker = nextMarker(root);
  } while (marker);
  return items;
}

export const iam = {
  users: () => all("ListUsers", {}, parse.users),
  createUser: (UserName) => query("iam", "CreateUser", { UserName }),
  groups: () => all("ListGroups", {}, parse.groups),
  createGroup: (GroupName) => query("iam", "CreateGroup", { GroupName }),
  groupUsers: (GroupName) => all("GetGroup", { GroupName }, parse.groupUsers),
  addToGroup: (GroupName, UserName) => query("iam", "AddUserToGroup", { GroupName, UserName }),
  removeFromGroup: (GroupName, UserName) => query("iam", "RemoveUserFromGroup", { GroupName, UserName }),
  groupsOf: (UserName) => all("ListGroupsForUser", { UserName }, parse.groups),
  accessKeys: (UserName) => all("ListAccessKeys", { UserName }, parse.accessKeys),
  createAccessKey: async (UserName) => parse.newKey(await query("iam", "CreateAccessKey", { UserName })),
  setKeyStatus: (UserName, AccessKeyId, Status) => query("iam", "UpdateAccessKey", { UserName, AccessKeyId, Status }),
  deleteAccessKey: (UserName, AccessKeyId) => query("iam", "DeleteAccessKey", { UserName, AccessKeyId }),
  policies: (scope = "Local") => all("ListPolicies", { Scope: scope }, parse.policies),
  policy: async (PolicyArn) => parse.policy(await query("iam", "GetPolicy", { PolicyArn })),
  policyDocument: async (PolicyArn, VersionId) => parse.document(await query("iam", "GetPolicyVersion", { PolicyArn, VersionId })),
  policyVersions: (PolicyArn) => all("ListPolicyVersions", { PolicyArn }, parse.versions),
  createPolicy: (PolicyName, PolicyDocument, Description) => query("iam", "CreatePolicy", { PolicyName, PolicyDocument, Description: Description || undefined }),
  /** A new default version; the oldest other version goes first when there are five (IAM's limit). */
  updatePolicy: async (PolicyArn, PolicyDocument) => {
    const versions = await iam.policyVersions(PolicyArn);
    if (versions.length >= 5) {
      const oldest = versions.filter((v) => !v.isDefault).sort((a, b) => (a.created < b.created ? -1 : 1))[0];
      if (oldest) await query("iam", "DeletePolicyVersion", { PolicyArn, VersionId: oldest.id });
    }
    return query("iam", "CreatePolicyVersion", { PolicyArn, PolicyDocument, SetAsDefault: "true" });
  },
  /** Deletes a managed policy: its other versions first, as IAM asks. */
  deletePolicy: async (PolicyArn) => {
    for (const v of await iam.policyVersions(PolicyArn)) {
      if (!v.isDefault) await query("iam", "DeletePolicyVersion", { PolicyArn, VersionId: v.id });
    }
    return query("iam", "DeletePolicy", { PolicyArn });
  },
  attached: (kind, name) => all(`ListAttached${kind}Policies`, { [`${kind}Name`]: name }, parse.attached),
  attach: (kind, name, PolicyArn) => query("iam", `Attach${kind}Policy`, { [`${kind}Name`]: name, PolicyArn }),
  detach: (kind, name, PolicyArn) => query("iam", `Detach${kind}Policy`, { [`${kind}Name`]: name, PolicyArn }),
  inline: (kind, name) => all(`List${kind}Policies`, { [`${kind}Name`]: name }, parse.inlineNames),
  inlineDocument: async (kind, name, PolicyName) => parse.document(await query("iam", `Get${kind}Policy`, { [`${kind}Name`]: name, PolicyName })),
  putInline: (kind, name, PolicyName, PolicyDocument) => query("iam", `Put${kind}Policy`, { [`${kind}Name`]: name, PolicyName, PolicyDocument }),
  deleteInline: (kind, name, PolicyName) => query("iam", `Delete${kind}Policy`, { [`${kind}Name`]: name, PolicyName }),
  /** Deletes a user and what IAM asks to remove first: keys, policies, groups. */
  deleteUser: async (UserName) => {
    for (const k of await iam.accessKeys(UserName)) await iam.deleteAccessKey(UserName, k.id);
    for (const p of await iam.attached("User", UserName)) await iam.detach("User", UserName, p.arn);
    for (const p of await iam.inline("User", UserName)) await iam.deleteInline("User", UserName, p);
    for (const g of await iam.groupsOf(UserName)) await iam.removeFromGroup(g.name, UserName);
    return query("iam", "DeleteUser", { UserName });
  },
  /** Deletes a group and what IAM asks to remove first: members and policies. */
  deleteGroup: async (GroupName) => {
    for (const u of await iam.groupUsers(GroupName)) await iam.removeFromGroup(GroupName, u.name);
    for (const p of await iam.attached("Group", GroupName)) await iam.detach("Group", GroupName, p.arn);
    for (const p of await iam.inline("Group", GroupName)) await iam.deleteInline("Group", GroupName, p);
    return query("iam", "DeleteGroup", { GroupName });
  },
};
