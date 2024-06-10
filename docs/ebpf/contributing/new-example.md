# Adding a new example

The library includes some examples to make getting started easier.
The aim of the examples is to __show how the library works, not how to implement a specific thing in eBPF__.
This is because the scope of eBPF is simply too large for us to cover.

Please consider the following before proposing a new example:

1. What feature __of the library__ does it showcase?
2. Is there already an existing example for that feature? If yes, could it be extended without making it harder to understand?
3. How complicated is the eBPF code required to make it work? How could the amount of eBPF be minimised?

Please contact the maintainers on Slack if you are in doubt about any of
these points.

## What makes a good example?

* It should be concise. The less code the better.
* It should show a single thing. The less configurable the better.
* It should be well documented. Even a novice user must be able to follow
  along.
* It should produce meaningful output or have an easily testable effect.
* It should have as few requirements on software / hardware as possible.
