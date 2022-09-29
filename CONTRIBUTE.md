# How to contribute

Firedancer uses a Gerrit instance on [
git.firedancer.io/](https://git.firedancer.io/) for code review. Gerrit has a bit of a
learning curve, but its back-and-forth review workflow is much nicer than GitHub's.

Using Gerrit also avoids sharing a single point of failure with the Solana Labs implementation - we only use
GitHub for issue tracking and as a read-only mirror of the repository.

In order to upload changes to Gerrit, you must clone the repository from Gerrit
with authentication, either via SSH or HTTPS.

We do not actively use GitHub pull requests, but if there is demand for community contributions via
GitHub PRs, we will be happy to accept them.

## Clone repository

First, log into Gerrit using your GitHub account. Enable 2FA authentication in your GitHub account if you
haven't already. If you have a @jumptrading.com email address, log in using company SSO instead.

### Via SSH

First, [configure your SSH public key(s)](https://git.firedancer.io//settings/#SSHKeys) in Gerrit.
Then, navigate to
the [firedancer repo overview](https://git.firedancer.io//admin/repos/firedancer,general),
select "SSH" and copy and run the *"Clone with commit-msg hook"* command.

The commit hook will automatically add a `Change-Id` tag to each commit message, which allows Gerrit
to uniquely identify changes across rebases.

*Tip:* If you configured your SSH keys on GitHub, you can quickly copy them on
`https://github.com/<your_username>.keys`.

### Via HTTPS

If you are behind certain corporate firewalls or otherwise unable to use SSH, you can use instead use HTTPS
token authentication to clone the repository. If you can, we recommend using SSH.

First, [generate a HTTP password](https://git.firedancer.io//settings/#HTTPCredentials) and store
it in your password manager (you can only have one, generating a new one will invalidate the old one). Keep
it safe - anyone in possession of it can push and review code on your behalf!

Then, select "HTTPS" on
the [firedancer repo overview](https://git.firedancer.io//admin/repos/firedancer,general) and copy and
run the *"Clone with commit-msg hook"* command. When
prompted for credentials, use your Gerrit username (usually your GitHub username or SSO name - it's also in
the clone URL you just copied) and the generated HTTP password.

**Never use your real GitHub or SSO password to authenticate!**

In order to avoid having to re-enter your password every time you interact with the repository, we recommend
[setting up a credential helper](https://stackoverflow.com/questions/5343068/is-there-a-way-to-cache-https-credentials-for-pushing-commits)
. For instance, on **MacOS** you would use this to use the native keychain:

    git config --global credential.helper osxkeychain

For **Windows**:

    git config --global credential.helper manager

For Linux, it depends on the distro - refer to the link above.

## Using Gerrit

The basic Gerrit development workflow does not differ a lot from using GitHub - most users generally
develop on branches, with one branch per independent change.

However, there is an important difference: Rather than reviewing the whole branch, **each commit on the branch
becomes one review** (called "changelist"/CL in Gerrit). The commit message is used as the CL description.

This has a number of advantages:

- It enforces a clean commit history where each commit is self-contained and has a meaningful commit message
  (which can be reviewed along with the code change).
- It allows for **dependent changes to be stacked** by simply having multiple commits on the same branch.
- CI runs independently on each commit.

<img src="https://i.imgur.com/TEGaIky.png" width="60%"/>

In order to submit one or multiple commits to Gerrit, simply push them to a special Git ref:

    git push origin HEAD:refs/for/main

This asks Gerrit to create a new CL against `main` for each commit you pushed. Normally, CLs are always made
against the `main` branch, but rarely, you may want to submit a change to a feature or release branch instead.

In order to ask for review, simply add reviewers using the Gerrit UI. You can also add CCs or reviewers
directly when pushing by appending
a [push option](https://gerrit-review.googlesource.com/Documentation/user-upload.html#push_options) to the
name of the branch. Common options are `cc` and `r` (for reviewers):

    git push origin HEAD:refs/for/main%r=kevin,cc=anthony

Commonly used CLI helpers for Gerrit
are [git-review](https://docs.opendev.org/opendev/git-review/latest/usage.html)
and [git-codereview](https://pkg.go.dev/golang.org/x/review/git-codereview), but those aren't required and
many Gerrit users only ever use the plain Git push command.

### Review changes

After reviewing someone else's CL, you can either add a **Code-Review +1 or +2 vote**. A +1 vote signals
that the code looks good to you, but someone else must approve the change. A +2 vote approves the CL for
merging. Typically, +2 votes are added by the code owner of a given component.

Code review votes are invalidated when a change is updated, unless the update was a trivial rebase that
didn't introduce new changes, or changes only the commit message.

There are no negative votes, but before a change can be submitted, all **comments must be marked resolved**.
Comments can be marked resolve either by the reviewer or by the author.

Reviewers sometimes leave both a +2
vote _and_ a comment, in which case the author is free to mark them resolved and merge the change without
having to get another approval. This is typically done for "nits", stylistic complaints or other comments
that are optional to resolve.

### Updates changes

When updating an existing change, instead of adding new commits to a branch, **update the existing commits**
(exception: sometimes a reviewer suggests optional or complex changes to a CL, in which case it may be wiser
to merge the existing CL as-is and address the suggested changes in a separate follow-up CL).

Typically, you'd use `git commit --amend` (for the top commit on a stack) or `git rebase -i`.

[git-absorb](https://github.com/tummychow/git-absorb) is particularly useful when dealing with stacks
of changes, as
is [git commit --fixup](https://blog.sebastian-daschner.com/entries/git-commit-fixup-autosquash).

All of this is plain Git usage, so there's very good editor support - IntelliJ/CLion can
conveniently create fixup commits and do an interactive rebase by selecting
a previous commit in the commit log. Other recommended tools are [Magit](https://magit.vc/) for Emacs
and [GitLens](https://marketplace.visualstudio.com/items?itemName=eamodio.gitlens) for VSCode.

Make sure not to modify or remove the `Change-Id` tag, since this is how Gerrit associates commits to CLs.

After updating a change or stack of changes, simply push it to the `refs/for/main` ref again.

### Tips and tricks

- Gerrit's dashboard shows you a list of all CLs that require your attention.

- Use `git pull --rebase` to update your working copy. It will automatically skip over any local commits.
  **Consider setting it as the default pull strategy in your Git config**:

        git config --global pull.rebase true

- Never push to another author's change. Instead, push your own change that is based on theirs. Generally,
  this is tricky business - **avoid working on top of other people's in-flight changes**. Gerrit's workflow
  is geared towards very short review cycles. If you find yourself wanting to build on an in-flight change,
  this probably means that something is wrong with the review process.

- **Avoid deep stacks of changes**. Just because you can, doesn't mean you should! They get more unwieldy the
  deeper they go. Stacking more than two larger changes is generally a bad idea - if you find yourself needing
  to do this, consider working with your reviewers to get the lower changes on the stack merged first. Stacks
  are meant for splitting large changes into smaller pieces, rather than stacking multiple large changes.

- There's a
  very [powerful search feature](https://gerrit-review.googlesource.com/Documentation/user-search.html) which
  supports complex queries.

- Related changes can be grouped together using hashtags and topics. A change can have multiple hashtags,
  but only one topic. Hashtags are usually generic, while a topic uniquely identifies a certain feature.

- Configure your editor to hard-wrap commit messages at 72 characters like Gerrit does.

- The markup for comments is rather rudimentary - it only supports `*`/`-` for lists, `>` for
  blockquotes, `[link](url)` for links, and <code>```</code> or leading spaces for code blocks.

- Like with GitHub, **reviews are transactional** - by default, all comments are drafts and won't be submitted
  until you reply to the change by clicking "Reply" or pressing `a`.

- Comments can be either added to entire lines or to arbitrary ranges - including individual words or multiple
  lines - by simply selecting the text and pressing `c`.

- Attention sets are a fine-grained way of ensuring only actionable notifications are sent. When you expect
  someone to do something, make sure they're added to the attention set. When no action is required by
  a team member, you can simply remove them from the attention set to avoid sending a notification.

- Gerrit is fully keyboard-driven and almost all actions can be performed used shortcuts. Press `?` for help.
  Some particularly useful ones are `Shift+i` to expand all files, `a` to reply, `Ctrl-Return` to submit the
  reply modal, `c` for adding comments and `j`/`k` for moving the cursor.

- Use the shortened Change-Id ("`I093d30c2`") rather than commit hashes when cross-referencing changes since
  it remains stable across rebases and backports.

- `git review -d <number>` will automatically check out the given CL on a branch (you'll need to
  install `git-review`, which should be packaged in almost every Linux distribution).

- The *Download* button shows you a list of Git commands to checkout, cherry-pick or rebase a given CL.

- There's an excellent [plugin](https://plugins.jetbrains.com/plugin/7272-gerrit) for IntelliJ and CLion
  which allows you to do code review within the IDE.
