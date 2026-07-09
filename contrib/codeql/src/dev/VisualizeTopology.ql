import cpp

  /* Point this predicate to the topology to be visualized */
predicate inTopology(Location loc) {
  loc.getFile().getRelativePath() = "src/app/firedancer/topology.c" or
  loc.getFile().getRelativePath() = "src/disco/net/fd_net_tile_topo.c"
}


class Tile extends FunctionCall {
  string name;

  Tile() {
    (this.getTarget().hasName("fd_topob_tile") and
    name = this.getArgument(1).(StringLiteral).getValue() and
    inTopology(this.getLocation())) and
    not name = "sock" /* we only consider the non-DZ net alternative */
  }

  string getJsonRepr() {
    result = "{\"name\": \"" + name + "\", \"isMultiTile\": " + this.isMultiTile() + "}"
  }

  string isMultiTile() {
    if exists(ForStmt f | f.getAChild+() = this) then result = "true" else result = "false"
  }

  string getMermaidShape() {
    if this.isMultiTile() = "true" then result = "processes" else result = "rect"
  }

  string getMermaidRepr() { result = "  " + name + "@{ shape: " + this.getMermaidShape() + " }" }
}

class InLink extends FunctionCall {
  string name;
  string in_tile;

  InLink() {
    (
    this.getTarget().hasName("fd_topob_tile_in") and
    name = this.getArgument(4).(StringLiteral).getValue() and
    in_tile = this.getArgument(1).(StringLiteral).getValue() and
    inTopology(this.getLocation())
    )
    or
    (
    this.getTarget().hasName("fd_topos_tile_in_net") and
    name = this.getArgument(2).(StringLiteral).getValue() and
    in_tile = "net" and /* leaving aside the sock alternative */
    inTopology(this.getLocation())
    )
  }

  string getName() { result = name }
  string getInTile() { result = in_tile }
}

class OutLink extends FunctionCall {
  string name;
  string out_tile;

  OutLink() {
    (
    this.getTarget().hasName("fd_topob_tile_out") and
    name = this.getArgument(3).(StringLiteral).getValue() and
    out_tile = this.getArgument(1).(StringLiteral).getValue() and
    inTopology(this.getLocation())
    )
    or
    (
    this.getTarget().hasName("fd_topos_net_rx_link") and
    name = this.getArgument(1).(StringLiteral).getValue() and
    out_tile = "net" and /* leaving aside the sock alternative */
    inTopology(this.getLocation())
    )
  }

  string getName() { result = name }
  string getOutTile() { result = out_tile }
}

class Link extends string {
  string name;
  string out_tile;
  string in_tile;

  Link() {
    exists(OutLink ol |
      name = ol.getName() and
      out_tile = ol.getOutTile() and
      exists(InLink il |
        name = il.getName() and
        in_tile = il.getInTile()
      )
    ) and
    this = "Link: " + name + ", out_tile: " + out_tile + ", in_tile: " + in_tile
  }

  string getJsonRepr() {
    result =
      "{\"name\": \"" + name + "\", \"out_tile\": \"" + out_tile + "\", \"in_tile\": \"" + in_tile +
        "\"}"
  }


  string getMermaidRepr() { result = "  " + out_tile + "-->|" + name + "|" + in_tile }
}

// strip last ", " from string
bindingset[str]
string truncate(string str) { result = str.prefix(str.length() - 2) }

string allTiles() {
  result = concat(Tile t | | t.getJsonRepr() + ", " order by t.getJsonRepr() desc)
}

string allLinks() {
  result = concat(Link l | | unique(string s | s = l.getJsonRepr() + ", " | s) )
}

string getJson() {
    result = "{\"tiles\": [" + truncate(allTiles()) + "], \"links\": [" + truncate(allLinks()) + "]}"
}

string allTilesMermaid() {
  result = concat(Tile t | | t.getMermaidRepr() + "\n" order by t.getMermaidRepr() desc)
}

string allLinksMermaid() {
  result = concat(Link l | | unique(string s | s = l.getMermaidRepr() + "\n" | s) )
}

string getMermaid() { result = "flowchart LR\n" + allTilesMermaid() + allLinksMermaid() }

// Select it just like getJson
from string output
where output = getMermaid()
select output
