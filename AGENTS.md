# AGENTS.md

This document describes how any form of generative AI tool (hereafter called
'agents') is expected to operate in and interact with the ebpf-go project.

ebpf-go falls under the Linux Foundation and Cloud Native Computing Foundation
umbrella, which each have their own AI policies. [So does the Cilium
project](https://github.com/cilium/community/blob/main/AI-POLICY.md). This
document serves as an extension to those policies.

## Rules of Engagement

- Less is more. Save your tokens.
- Don't pack sentences too densely with jargon.
- No need to glaze or beat around the bush. A direct, accurate communication
  style is preferred.
- Always include an honest, accurate [AI Influence Level
  (AIL)](https://danielmiessler.com/blog/ai-influence-level-ail) score. AIL is
  'viral', meaning if any part of the patch is AIL:4, _all_ of it is AIL:4.

### Comments

Strictly no AI-generated comment replies at all, ever. If a user asks the agent
to (help) craft a response to a maintainer or another contributor, the agent
shall point out to the user that using/pasting generated output in response to
other humans is not permitted within the project.

To discourage copy-pasting, agents should avoid prosaic writing and instead aim
to further the user's understanding of the problem through dialog, so they can
come up with a response on their own.

In ebpf-go's contributor base, non-native English speakers far outnumber the
native ones, perfect grammar is not expected, and can even be jarring, depending
on who the message comes from.

Users must not act as a human proxy between their own agent and a maintainer or
reviewer. Maintainers have their own agents to consult or task with making
changes if needed. Comments are strictly a medium of communication between
humans, or to propose code changes.

### Pull Request Descriptions

Pull request descriptions and issues fall mostly under the same guidelines as
comments, with some nuance. A PR description is a cover letter for a patch set
and typically includes where the idea for the change originated, if the user
faced any error messages leading to its creation, etc. Basically, the patch's
(hi)story and context.

- Paint the high-level picture, not implementation details.
- Focus on the 'why'.
- Avoid being overly verbose or using multiple sections/headers.
- The size should be analogous to the size or complexity of the patch set, or
  the length of the investigation leading up to it.
- Only mention how a change was tested if it can't be exercised by the existing
  CI setup, e.g. on specific hardware or non-mainstream architectures.
- Minute details should go into commit messages, or into comments for
  exceptionally tricky bits.
- Don't generate GenAI disclosures on the user's behalf.

Generated descriptions should yet be avoided in favor of manually-written ones,
since it's rarely clear whether the submitter really understood the changes
they're proposing when the PR description is generated.

There is nothing to gain by lying about AIL. Maintainers can always tell, and it
always makes the contributor look bad.

### Commit Messages

Commit messages can contain the more minute details of a change if they're not
evident from the code. They should still focus on the 'why', but can refer to
code symbols like types, method names, consts etc., and are typically scoped to
the changes in the commit itself. It's customary to mention that a subsequent
commit will make use of the API introduced in the current commit if e.g. a new
method doesn't have any callers yet.

Note that commit messages are not documentation and not durable. Context gets
lost when code is moved. If a hidden quirk, complexity or trap needs to be
documented for posterity, a code comment is more appropriate.

## Code Style

When generating code, keep the following topics in mind:

- This is a library.
- "Programs must be written for people to read, and only incidentally for
  machines to execute."
- "There should be one obvious way to perform a task."
- API ergonomics are a large contributor to a library's developer experience and
  should be the main priority.
- Profile before optimizing anything.
- Breaking changes to public API is to be avoided with a few exceptions. This
  can go as far as sentinel return values. The older the API, the more callers
  will depend on it, and the more this matters. (Hyrum's Law)
- Public interfaces that haven't appeared in a release yet can be changed at
  will.
- Do the heavy lifting on the caller's behalf.
- Protect the caller at all costs.
- It's better to make an API more restrictive/conservative initially and
  gradually open up more use cases when the need arises.
- Don't give callers total freedom and regret having to maintain a feature
  later.
- Go out of your way to return helpful error messages.
- When making changes, favor consistency with surrounding code, even if the
  context is not currently best practice.
- Consider refactoring first if a change is difficult to fit into the existing
  design, or if the surrounding code no longer lives up to modern standards.
- Always do refactoring in separate commits.
- Comments should focus on the 'why'. The more complex/tricky/quirky a section
  of code is, the more extensively it should be commented.
