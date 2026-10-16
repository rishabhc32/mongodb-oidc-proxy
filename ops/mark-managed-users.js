// One-time migration when upgrading from a proxy version that did not mark the
// MongoDB users it creates. Without the mark, the proxy refuses to log those
// users in ("exists and is not managed by the proxy").
//
// Marks every admin user whose only role is the same-named role in admin, which
// is the shape the proxy creates. Preview first, then apply:
//
//   DRY_RUN=1 mongosh "<admin connection string>" ops/mark-managed-users.js
//   mongosh "<admin connection string>" ops/mark-managed-users.js
//
// Check the preview: a listed user that the proxy did not create would have its
// password and roles reset by the proxy on that user's next login.

const MANAGED_USER_MARKER = 'mongodb-oidc-proxy';
const dryRun = process.env.DRY_RUN === '1';
const admin = db.getSiblingDB('admin');

const candidates = admin
  .runCommand({ usersInfo: 1 })
  .users.filter(
    (user) =>
      user.customData === undefined &&
      user.roles.length === 1 &&
      user.roles[0].role === user.user &&
      user.roles[0].db === 'admin'
  );

for (const user of candidates) {
  if (!dryRun) {
    const result = admin.runCommand({ updateUser: user.user, customData: { managedBy: MANAGED_USER_MARKER } });
    if (result.ok !== 1) {
      throw new Error(`Failed to mark ${user.user}: ${result.errmsg}`);
    }
  }
  print(`${dryRun ? 'would mark' : 'marked'} ${user.user}`);
}

print(`${candidates.length} user(s) ${dryRun ? 'would be marked' : 'marked'} as managed by ${MANAGED_USER_MARKER}`);
