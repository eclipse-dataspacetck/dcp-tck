# Etiquette for pull requests

## Choosing an area to work on

We welcome all contributions, after all, they are what keep the project alive and active. However, there are a few
important things to note for a successful contribution. Choosing an area to work on is a key aspect for a successful
pull request.

As with any other open-source project, it is generally good practice to start out with some relatively low-impact
contributions like documentation, fixing some minor bugs or generally issues with good first issue label on them, check
this page. That way we (the committers) get to know you, we can build trust, and you’ll get to know the code base
better.

It is not recommended to start your journey with high-impact contributions such as changes to core modules, changes that
cut across several modules or that generally bring a very large changeset. Start small, work your way in from there.

Most importantly, it is always required to open a discussion or an issue first.

## Before opening a pull request

Pull requests must be linked to an issue that has already gone through the triage process. In most cases, the general
triage process looks like this:

- open a discussion, wait for comments
- committers comment and possibly convert the discussion to an issue labelled with triage
- you might be asked to provide more details or even a solution proposal in the issue
- issue triage happens, at which point the triage label is removed
- now the issue is ready for implementation

Issues from external contributors, i.e. contributors that aren’t committers, require a sponsor. A sponsor is a
committer who will provide technical guidance and work with you on a solution proposal and who will represent and mentor
the feature. Sponsors should also be put on as reviewers to the pull request, although they might request a second
review from another committer (four eyes principle).

Sponsorship can be obtained through engagement on discussions or issues.

**Pull requests, that are not linked to a properly triaged issue might be ignored or get closed without notice,
regardless of the author or the content!**

## As an author

Submitting pull requests should be done while adhering to a couple of simple rules.

- Familiarize yourself with [coding style](styleguide.md)
- No surprise PRs please. Before you submit a PR, open a discussion or an issue outlining your planned work and give
  people time to comment. It may even be advisable to contact committers using the `@mention` feature. Unsolicited PRs
  may get ignored or rejected.
- Create focused PRs: your work should be focused on one particular feature or bug. Do not create broad-scoped PRs that
  solve multiple issues as reviewers may reject those PR bombs outright.
- Provide a clear description and motivation in the PR description in GitHub. This makes the reviewer's life much
  easier. It is also helpful to outline the broad changes that were made, e.g. "Changes the schema of XYZ-Entity:
  the `age` field changed from `long` to `String`".
- If you introduce new 3rd party dependencies, be sure to note them in the PR description and explain why they are
  necessary.
- Stick to the established code style, please refer to the [styleguide document](styleguide.md).
- All tests should be green, especially when your PR is in `"Ready for review"`
- Mark PRs as `"Ready for review"` only when you're prepared to defend your work. By that time you have completed your
  work and shouldn't need to push any more commits other than to incorporate review comments.
- Merge conflicts should be resolved by squashing all commits on the PR branch, rebasing onto `main` and
  force-pushing. Do this when your PR is ready to review.
- If you require a reviewer's input while it's still in draft, please contact the designated reviewer using
  the `@mention` feature and let them know what you'd like them to look at.
- Request a review from one of the committers. Requesting a review from anyone else is still possible, and
  sometimes may be advisable, but only committers can merge PRs, so be sure to include them early on.
- Re-request reviews after all remarks have been adopted. This helps reviewers track their work in GitHub.
- If you disagree with a committer's remarks, feel free to object and argue, but if no agreement is reached, you'll have
  to either accept the decision or withdraw your PR.
- Be civil and objective. No foul language, insulting or otherwise abusive language will be tolerated.
- The PR titles must follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).
    - The title must follow the format as `<type>(<optional scope>): <description>`.
      `build`, `chore`, `ci`, `docs`, `feat`, `fix`, `perf`, `refactor`, `revert`, `style`, `test` are allowed for the
      `<type>`.
    - The length must be kept under 80 characters.

## As a reviewer

- Please complete reviews within two business days or delegate to another committer, removing yourself as a reviewer.
- If you have been requested as reviewer, but cannot do the review for any reason (time, lack of knowledge in particular
  area, etc.) please comment that in the PR and remove yourself as a reviewer, suggesting a stand-in. The [code
  owners document](CODEOWNERS) should help with that.
- Don't be overly pedantic.
- Don't argue basic principles (code style, architectural decisions, etc.)
- Use the `suggestion` feature of GitHub for small/simple changes.
- The following could serve you as a review checklist:
    - no unnecessary dependencies in `build.gradle.kts`
    - sensible unit tests, prefer unit tests over integration tests wherever possible (test runtime). Also check the
      usage of test tags.
    - code style
    - simplicity and "uncluttered-ness" of the code
    - overall focus of the PR
- Don't just wave through any PR. Please take the time to look at them carefully.
- Be civil and objective. No foul language, insulting or otherwise abusive language will be tolerated. The goal is to
  _encourage_ contributions.