# Claude Code 2.1.300 local capture fixtures

`cli-2.1.300.json` contains fixtures derived from 14 Messages requests produced by
the installed native Windows CLI against a loopback capture server, using isolated configuration and
dummy Bearer/API credentials. Scenarios: repeated/fresh configuration, API key,
request hints, a tool loop, a 429 retry, manual permission mode, two prompts in
one session, and an interactive session.

Credentials and transport-specific headers were removed. Workspace paths and
the host username were replaced with synthetic fixture values. Long prompt text
and tool descriptions were replaced with short synthetic text; request structure,
identity fields, protocol headers, tool schemas and safeguards were retained.
No live provider was contacted. Tests assert only the protocol properties observed here, not
OAuth acceptance, transport fingerprints or account enforcement outcomes.

Eight requests contain permission safeguards and must be rejected by privacy
v1. The other six preserve their system/messages/tools and optional-header
absence through both request builders. Count-token tests reuse these bodies
synthetically; no native count_tokens request was captured in this run.
