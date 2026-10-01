# Node rate-limit storage

Each published site reserves a separate OpenResty shared dictionary before its
first rate-limit rule is enabled. All workers on the node use that site's
partition, preserving exact fixed-window counters across ordinary rule and list
updates. Counters remain local to each node.

Each site receives a partition of the same size, 256 KiB unless
`--rate-limit-dict-kb` sets another size (64-65536 KiB). At the default size, at
most 512 published sites allocate 128 MiB of counter storage in total; smaller
site sets allocate less. Adding a site cannot shrink another site's capacity.
Capacity cannot be borrowed from another site.

A counter is keyed by a 16-byte MD5 digest of the scope, rule id and key value
plus the window number, so it fits nginx's 128-byte slab class: a 256 KiB
partition holds about 1980 counters. Counters are never evicted. When a
partition cannot accept a new counter, the request passes uncounted while
clients that already have a counter stay limited; the node logs this at most
once a minute per site with the running total. A missing partition returns 503
with `X-Edgeweir-Error: rate-limit-unavailable`. WAF log deduplication and these
totals use a separate bounded dictionary.

Changing the set of served sites requires an OpenResty reload. Existing site
dictionaries retain their names and fixed sizes, so OpenResty reuses their
active counters when another site is added or removed. Rules and lists for the
same site set remain hot updates. A process restart, or a software upgrade that
changes the partition format, starts fresh counters. Old workers can temporarily
retain removed partitions while a graceful reload drains them.

The default partition size, its counter capacity and a full partition are
exercised by the counter tests in the pinned image. Node configuration validation rejects payloads containing more than 512
sites rather than reallocating existing partitions. The control plane must
reject publication beyond the same capacity.
