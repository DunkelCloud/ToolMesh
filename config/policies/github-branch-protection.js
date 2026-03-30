// github-branch-protection.js — Prevent merges and force-pushes to main/master.
// Allows all other branch operations (create, delete, merge between feature branches).
if (ctx.phase === "pre") {
  var tool = ctx.tool;
  var params = ctx.params;

  // Block merge_branch when base is main or master
  if (tool === "github:merge_branch" || tool === "github:merge_pull_request") {
    var base = params.base || params.branch || "";
    if (base === "main" || base === "master") {
      throw new Error("Merging into " + base + " is not allowed via ToolMesh. Use GitHub PR review flow.");
    }
  }

  // Block force-push to main/master via update_ref
  if (tool === "github:update_ref") {
    var ref = params.ref || "";
    if (params.force && (ref === "heads/main" || ref === "heads/master")) {
      throw new Error("Force-pushing to " + ref + " is not allowed.");
    }
  }

  // Block deleting main/master branch
  if (tool === "github:delete_ref") {
    var ref = params.ref || "";
    if (ref === "heads/main" || ref === "heads/master") {
      throw new Error("Deleting " + ref + " is not allowed.");
    }
  }
}
