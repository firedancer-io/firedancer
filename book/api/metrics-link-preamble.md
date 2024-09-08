There are some metrics reported for links, which are data queues between
tiles. Links are single-producer multi-consumer, so the same link
(identified by a `link_kind` and `link_kind_id`) will potentially have
multiple consumers reporting the metric, one per consumer (identified by
a `kind` and `kind_id`).

```sh [bash]
# HELP link_published_size_bytes The total number of bytes read by the link consumer.
# TYPE link_published_size_bytes counter
link_published_size_bytes{kind="net",kind_id="0",link_kind="quic_net",link_kind_id="0"} 0
link_published_size_bytes{kind="net",kind_id="0",link_kind="shred_net",link_kind_id="0"} 0
```

These link related metrics have four labels, which are to identify the
link the metric is for:

- `kind` &mdash; The name of the tile consuming from the link.
- `kind_id` &mdash; The tile index of the tile which is consuming from the link.
- `link_kind` &mdash; The name of the link being consumed.
- `link_kind_id` &mdash; The link index of the link which is being consumed.
