# Adding a new feature

We're very much looking for contributions which flesh out the functionality of
the library.

1. Have a look at the [architecture](architecture.md) of the library if you
   haven't already.
2. [Join](https://ebpf.io/slack) the
   [#ebpf-go-dev](https://cilium.slack.com/messages/ebpf-go-dev) channel to
   discuss your requirements and how the feature can be implemented.
   Alternatively open a new Discussion if you prefer to not use Slack.
   The most important part is figuring out how much new exported API is necessary.
   **The less new API is required the easier it will be to land the feature.**
   Also see [API stability](#api-stability).
3. (*optional*) Create a draft PR if you want to discuss the implementation or have hit a problem. It's fine if this doesn't compile or contains debug statements.
4. Create a PR that is ready to merge. This must pass CI and have tests.

## API stability

There is an emphasis on compatibility even though the library doesn't guarantee
the stability of its API at the moment.

1. If possible, avoid breakage by introducing new API and deprecating the old one
   at the same time. If an API was deprecated in v0.x it can be removed in v0.x+1.
   This is especially important if there is no straighforward way to convert
   from the old to the new API.
2. Breaking API in a way that causes compilation failures is acceptable but must
   have good reasons.
3. Changing the semantics of the API without causing compilation failures is
   heavily discouraged.
