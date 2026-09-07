// Benchmark PR comment upsert for actions/github-script.
//   await require(`${process.env.GITHUB_WORKSPACE}/contrib/ci/bench/upsert.js`)({github, context, core, exec}, {rowsFile})
'use strict';
const fs   = require('fs');
const os   = require('os');
const path = require('path');

const MARKER    = '<!-- fd-benchmark-comment:v1 -->';
const STATE_TAG = '<!-- fd-benchmark-state ';
const BOT_LOGIN = 'github-actions[bot]';  // author of comments made with github.token

function stateOf(body) {
  const last = (body || '').replace(/\r\n/g, '\n').trimEnd().split('\n').pop();
  if (!last.startsWith(STATE_TAG) || !last.endsWith(' -->')) return null;
  try { return JSON.parse(last.slice(STATE_TAG.length, -4)); }
  catch (e) { return null; }
}

const visible = b => (b || '').replace(/\r\n/g, '\n').trimEnd().split('\n').filter(l => !l.startsWith(STATE_TAG)).join('\n');
function same(a, b) { return visible(a) === visible(b); }  // the state line's seq differs on every render

module.exports = async ({github, context, core, exec}, opts) => {
  const rowsFile = opts.rowsFile;
  const renderer = opts.renderer || path.join(__dirname, 'benchmark_comment.py');
  const rows = JSON.parse(fs.readFileSync(rowsFile, 'utf8'));
  const job  = rows.job;
  const tmp  = fs.mkdtempSync(path.join(os.tmpdir(), 'fd-bench-'));
  const f    = n => path.join(tmp, n);

  const spinner = `https://raw.githubusercontent.com/${context.repo.owner}/${context.repo.repo}/${rows.head}/contrib/ci/bench/spinner.svg`;
  const render = async (oldState) => {
    fs.writeFileSync(f('state_in.json'), oldState ? JSON.stringify(oldState) : '');  // empty file → fresh state
    await exec.exec('python3', [renderer, 'render', '--state', f('state_in.json'), '--rows', rowsFile, '--spinner', spinner,
                                '--out-body', f('body.md'), '--out-state', f('state.json'), '--out-summary', f('summary.md')]);
    return {body: fs.readFileSync(f('body.md'), 'utf8'), summary: fs.readFileSync(f('summary.md'), 'utf8')};
  };
  const hasOurRows = (body) => {
    const s = stateOf(body);
    if (!s || s.head !== rows.head || !s.runs[job]) return false;
    return Object.keys(rows.rows).every(k => k in s.runs[job].rows);
  };
  const finish = async (summary, why) => {
    core.info(`benchmark comment [${job}]: ${why}`);
    await core.summary.addRaw(summary).write();
  };

  const pr = context.payload && context.payload.pull_request;
  if (!pr) return finish((await render(null)).summary, 'not a pull_request event, summary only');
  if (!pr.head || !pr.head.repo || pr.head.repo.fork) return finish((await render(null)).summary, 'fork PR, summary only');

  const {owner, repo} = context.repo;
  const issue_number = pr.number;

  // Oldest marker comment by the workflow's own identity wins (anyone can post the marker text; only our
  // comments carry trusted state); extras come from jobs that raced on the first create.
  const markerComments = async () => {
    const all = await github.paginate(github.rest.issues.listComments, {owner, repo, issue_number, per_page: 100});
    return all.filter(c => c.user && c.user.login === BOT_LOGIN && (c.body || '').startsWith(MARKER)).sort((a, b) => a.id - b.id);
  };
  const dedupe = async () => {  // also sweeps orphans left by an older run
    const all = await markerComments();
    for (const c of all.slice(1)) await github.rest.issues.deleteComment({owner, repo, comment_id: c.id});
    return all[0] || null;
  };
  const cur = await github.rest.pulls.get({owner, repo, pull_number: issue_number});
  if (cur.data.head.sha !== rows.head) return finish((await render(null)).summary, `stale: PR head ${cur.data.head.sha.slice(0, 7)} != ${rows.head.slice(0, 7)}, skipped write`);

  // Three jobs update the same comment concurrently: render from the state we read, then write only if the
  // comment still carries that state's seq (re-fetched just before the write) and re-read to confirm it stuck.
  const seqOf = s => (s && s.seq) || 0;
  let out;
  for (let attempt = 1; attempt <= 5; attempt++) {
    const found = await dedupe();
    const seen  = found ? stateOf(found.body) : null;
    out = await render(seen);
    if (!found) {
      const id = (await github.rest.issues.createComment({owner, repo, issue_number, body: out.body})).data.id;
      if ((await dedupe()).id === id) return finish(out.summary, `created comment ${id}`);
      continue;  // another job created first and ours was deleted: fold our rows into the survivor
    }
    if (same(found.body, out.body)) return finish(out.summary, `comment ${found.id} unchanged`);
    const now = await github.rest.issues.getComment({owner, repo, comment_id: found.id});
    if (seqOf(stateOf(now.data.body)) !== seqOf(seen)) { core.info(`benchmark comment [${job}]: comment ${found.id} moved, retry ${attempt}`); continue; }
    await github.rest.issues.updateComment({owner, repo, comment_id: found.id, body: out.body});
    const back = await github.rest.issues.getComment({owner, repo, comment_id: found.id});
    if (hasOurRows(back.data.body)) return finish(out.summary, `updated comment ${found.id} (verified, attempt ${attempt})`);
    core.info(`benchmark comment [${job}]: comment ${found.id} overwritten under us, retry ${attempt}`);
  }
  return finish(out.summary, 'gave up after 5 attempts');
};
