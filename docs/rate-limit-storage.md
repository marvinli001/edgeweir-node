# Node rate-limit storage

Each published site reserves a separate OpenResty shared dictionary before its
first rate-limit rule is enabled. All workers on the node use that site's
partition, preserving exact fixed-window counters across ordinary rule and list
updates. Counters remain local to each node.

Each site receives a fixed 256 KiB partition. At most 512 published sites can
allocate 128 MiB of counter storage in total; smaller site sets allocate less.
Adding a site cannot shrink another site's capacity. Capacity cannot be borrowed
from another site. If a partition is missing or cannot accept a new counter,
its rate-limited request returns 503. WAF log deduplication uses a separate
bounded dictionary.

Changing the set of served sites requires an OpenResty reload. Existing site
dictionaries retain their names and fixed sizes, so OpenResty reuses their
active counters when another site is added or removed. Rules and lists for the
same site set remain hot updates. A process restart, or a software upgrade that
changes the partition format, starts fresh counters. Old workers can temporarily
retain removed partitions while a graceful reload drains them.

The fixed partition size is exercised by ordinary counter tests in the pinned
image. Node configuration validation rejects payloads containing more than 512
sites rather than reallocating existing partitions. The control plane must
reject publication beyond the same capacity.
