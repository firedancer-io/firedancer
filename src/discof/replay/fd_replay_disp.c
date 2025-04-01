
/* The conflict graph that this file builds is not a general DAG, but
   the union of several special account-conflict graphs.  Each
   account-conflict graph has special structure:
                           ---> 3 --
                          /          \
                         /            v
               1  ---> 2 -----> 4 --> 6 ----> 7
                        \             ^
                         \           /
                          ----> 5 --

   That is, the graph is almost a line, but may have fan-out and fan-in
   regions.  The tricky part about representing a graph like this
   without dynamic memory allocation is that nodes may have arbitrary
   in-degree and out-degree.  Thus, we use a pretty standard trick and
   use sibling pointers, denoted with dotted lines.  Each node maintains
   at most one successor pointer and at most one sibling pointer.
   Although not shown below, the sibling pointers are circularly linked,
   so 5's sibling is 3.

                             ---> 3 --
                            /     :    \
                           /      V     v
                 1  ---> 2        4 --> 6 ----> 7
                                  :     ^
                                  V    /
                                  5 --

   The normal edge 2->3 along with the sibling edge 3..>4 implies a
   normal edge 2->4.  That then transitively implies an edge 2->5.

   We want each node to maintain a count of its in-degree so that we
   know when it can be executed.  The implied edges also count for the
   in-degree.  In this example, node 1 has in-degree 0, node 6 has
   in-degree 3, and the rest have in-degree 1.

   Maintaining each account-conflict graph is relatively easy given the
   operations we want to support.  Only the details about sibling edges
   are worth mentioning.  For example, when deleting node 2, we
   decrement the in-degree count for its successor, and then follow the
   sibling pointers, decrementing all the in-degree counts as we go to
   mark the deletion of the implied edges.

   When building the graph, we maintain a map of account to the last
   node that references it, whether that was a read or write, and
   whether there are any writers to that account in the graph right now.
   If the new node reads from an account that was last read, the new
   node becomes a sibling of the last read, with in-degree increased if
   there are any writers.  Otherwise, it becomes a successor of the node
   that last referenced the account. */



e = 2*( 1 bit is last, 23 bits txn idx, 8 bits edge num )

base_ptr + (129*8)*(x>>8) + 8 + 8*(x&0xFF)

If high bit set for child, then 31 bits are index in map

struct acct_info {
  pubkey key;
  chaining fields;
  e last_reference;
  bool last_reference_was_write;
  bool any_writers;
};

struct txn {
  uint in_degree;
  uint edge_cnt;
  e edges[128];
};


Adding:

iterate over all accounts. Look up in map.
If account in map:
  them-me

  r-r:
    copy their child, sibling to my child field, sibling field
    clear their child field
    set their sibling to me

  w-r:
    copy their child to my child field
    set their child to me
    set my sibling field to myself
    clear last_reference_was_write

  w-w:
    copy their child to my child field
    set my sibling to 0
    set their child to me

  r-w:
    copy their child to my child field
    set my sibling to 0
    set last_reference_was_write
    set any_writers
    increment writer_cnt
    inital_them = them
    while true {
      set their child to me
      increment my in_degree
      if their sibling is initial_them, break
      them = their sibling
    }

 set last_reference to me
 increment my in_degree unless any_writers==0 and r-r

If account not in map:
 insert into map
 set my child to 1<<31 | map slot id
 if read, set sibling to myself
 if write, set sibling to 0
 set any_writers, last_reference_was_write

If in_degree is 0 in the end, add to ready queue



Scheduling:
Pop something from ready list if anything


Completing:
iterate over all edges

If I have a child, decrement their in_degree
Do the same for any siblings of child
If my child's "child" is the map field, set any_writers to last_reference_was_write

If I don't have a child, delete from map
