// github-branch-protection.js — Prevent merges and force-pushes to main/master.
// Allows all other branch operations (create, delete, merge between feature branches).
//
// Tool names follow the ToolMesh convention "<backend>_<tool>" (snake_case,
// underscore separator) — the MCP spec restricts names to [a-zA-Z0-9_-].
if (ctx.phase === "pre") {
  var tool = ctx.tool;
  var params = ctx.params;

  // Block merging a pull request into main/master
  if (tool === "github_merge_pull") {
    // merge_pull identifies the target via pull_number; the base branch must
    // be looked up by the caller. As a conservative default, block any merge
    // call and require explicit policy opt-in for non-protected branches.
    throw new Error("Merging pull requests is not allowed via ToolMesh. Use the GitHub PR review flow.");
  }

  // Block force-push to main/master via update_ref
  if (tool === "github_update_ref") {
    var ref = params.ref || "";
    if (params.force && (ref === "heads/main" || ref === "heads/master")) {
      throw new Error("Force-pushing to " + ref + " is not allowed.");
    }
  }

  // Block deleting main/master branch
  if (tool === "github_delete_ref") {
    var ref = params.ref || "";
    if (ref === "heads/main" || ref === "heads/master") {
      throw new Error("Deleting " + ref + " is not allowed.");
    }
  }
}
