from __future__ import annotations

from dataclasses import dataclass
from math import inf
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


Node = int
Edge = Tuple[Node, Node]


@dataclass
class TopologySnapshot:
    kind: str
    n_nodes: int
    n_edges: int
    avg_degree: float
    max_degree: int
    min_degree: int


class BaseTopology:
    """
    Shared topology interface for GVAI runtime monitoring.

    This abstraction is meant to let the same monitor / sentinel logic run over:
    - 2D grids
    - irregular graphs
    - service dependency graphs
    - training shard graphs

    The key idea is that every topology should expose:
    - neighbors(node)
    - degree(node)
    - adjacency_matrix()
    - laplacian_matrix()

    That gives the rest of the system one common surface.
    """

    def __init__(self, n_nodes: int) -> None:
        if n_nodes <= 0:
            raise ValueError("n_nodes must be > 0")
        self.n_nodes = n_nodes
        self._adj: Dict[Node, set[Node]] = {i: set() for i in range(n_nodes)}

    def add_edge(self, u: Node, v: Node) -> None:
        self._validate_node(u)
        self._validate_node(v)
        if u == v:
            return
        self._adj[u].add(v)
        self._adj[v].add(u)

    def remove_edge(self, u: Node, v: Node) -> None:
        self._validate_node(u)
        self._validate_node(v)
        self._adj[u].discard(v)
        self._adj[v].discard(u)

    def has_edge(self, u: Node, v: Node) -> bool:
        self._validate_node(u)
        self._validate_node(v)
        return v in self._adj[u]

    def neighbors(self, node: Node) -> List[Node]:
        self._validate_node(node)
        return sorted(self._adj[node])

    def degree(self, node: Node) -> int:
        self._validate_node(node)
        return len(self._adj[node])

    def degrees(self) -> List[int]:
        return [self.degree(i) for i in range(self.n_nodes)]

    def edges(self) -> List[Edge]:
        result: List[Edge] = []
        for u in range(self.n_nodes):
            for v in self._adj[u]:
                if u < v:
                    result.append((u, v))
        return result

    def n_edges(self) -> int:
        return len(self.edges())

    def adjacency_matrix(self) -> List[List[float]]:
        mat = [[0.0 for _ in range(self.n_nodes)] for _ in range(self.n_nodes)]
        for u in range(self.n_nodes):
            for v in self._adj[u]:
                mat[u][v] = 1.0
        return mat

    def degree_matrix(self) -> List[List[float]]:
        mat = [[0.0 for _ in range(self.n_nodes)] for _ in range(self.n_nodes)]
        for i in range(self.n_nodes):
            mat[i][i] = float(self.degree(i))
        return mat

    def laplacian_matrix(self) -> List[List[float]]:
        """
        Unnormalized graph Laplacian: L = D - A
        """
        a = self.adjacency_matrix()
        d = self.degree_matrix()
        out = [[0.0 for _ in range(self.n_nodes)] for _ in range(self.n_nodes)]
        for i in range(self.n_nodes):
            for j in range(self.n_nodes):
                out[i][j] = d[i][j] - a[i][j]
        return out

    def shortest_path_lengths(self, source: Node) -> List[float]:
        """
        Simple BFS distances for unweighted graphs.
        Unreachable nodes remain inf.
        """
        self._validate_node(source)
        dist = [inf] * self.n_nodes
        dist[source] = 0.0
        queue: List[Node] = [source]
        head = 0

        while head < len(queue):
            u = queue[head]
            head += 1
            for v in self._adj[u]:
                if dist[v] == inf:
                    dist[v] = dist[u] + 1.0
                    queue.append(v)

        return dist

    def mean_path_length(self) -> Optional[float]:
        total = 0.0
        count = 0
        for src in range(self.n_nodes):
            dists = self.shortest_path_lengths(src)
            for dst, d in enumerate(dists):
                if src != dst and d != inf:
                    total += d
                    count += 1
        if count == 0:
            return None
        return total / count

    def snapshot(self, kind: str = "graph") -> TopologySnapshot:
        deg = self.degrees()
        return TopologySnapshot(
            kind=kind,
            n_nodes=self.n_nodes,
            n_edges=self.n_edges(),
            avg_degree=sum(deg) / len(deg),
            max_degree=max(deg),
            min_degree=min(deg),
        )

    def _validate_node(self, node: Node) -> None:
        if not (0 <= node < self.n_nodes):
            raise IndexError(f"node {node} out of range for topology of size {self.n_nodes}")


class GridTopology(BaseTopology):
    """
    2D 4-neighbor grid topology.

    Nodes are indexed row-major:
        node_id = r * cols + c
    """

    def __init__(self, rows: int, cols: int) -> None:
        if rows <= 0 or cols <= 0:
            raise ValueError("rows and cols must be > 0")
        self.rows = rows
        self.cols = cols
        super().__init__(rows * cols)
        self._build()

    def node_id(self, row: int, col: int) -> Node:
        if not (0 <= row < self.rows and 0 <= col < self.cols):
            raise IndexError(f"grid coordinate {(row, col)} out of bounds")
        return row * self.cols + col

    def coords(self, node: Node) -> Tuple[int, int]:
        self._validate_node(node)
        return divmod(node, self.cols)

    def _build(self) -> None:
        for r in range(self.rows):
            for c in range(self.cols):
                u = self.node_id(r, c)
                if r + 1 < self.rows:
                    self.add_edge(u, self.node_id(r + 1, c))
                if c + 1 < self.cols:
                    self.add_edge(u, self.node_id(r, c + 1))

    def snapshot(self, kind: str = "grid") -> TopologySnapshot:
        return super().snapshot(kind=kind)


class GraphTopology(BaseTopology):
    """
    Generic graph topology from:
    - edge list
    - adjacency dict
    """

    @classmethod
    def from_edges(cls, n_nodes: int, edges: Iterable[Edge]) -> "GraphTopology":
        topo = cls(n_nodes)
        for u, v in edges:
            topo.add_edge(u, v)
        return topo

    @classmethod
    def from_adjacency(cls, adjacency: Dict[Node, Sequence[Node]]) -> "GraphTopology":
        n_nodes = max(adjacency.keys()) + 1 if adjacency else 0
        topo = cls(n_nodes)
        for u, nbrs in adjacency.items():
            for v in nbrs:
                topo.add_edge(u, v)
        return topo

    def snapshot(self, kind: str = "graph") -> TopologySnapshot:
        return super().snapshot(kind=kind)


def line_topology(n_nodes: int) -> GraphTopology:
    if n_nodes <= 0:
        raise ValueError("n_nodes must be > 0")
    edges = [(i, i + 1) for i in range(n_nodes - 1)]
    return GraphTopology.from_edges(n_nodes, edges)


def ring_topology(n_nodes: int) -> GraphTopology:
    if n_nodes <= 2:
        raise ValueError("ring_topology requires at least 3 nodes")
    edges = [(i, (i + 1) % n_nodes) for i in range(n_nodes)]
    return GraphTopology.from_edges(n_nodes, edges)


def star_topology(n_nodes: int, hub: int = 0) -> GraphTopology:
    if n_nodes <= 1:
        raise ValueError("star_topology requires at least 2 nodes")
    if not (0 <= hub < n_nodes):
        raise ValueError("hub out of range")
    edges = [(hub, i) for i in range(n_nodes) if i != hub]
    return GraphTopology.from_edges(n_nodes, edges)


def complete_topology(n_nodes: int) -> GraphTopology:
    if n_nodes <= 0:
        raise ValueError("n_nodes must be > 0")
    edges: List[Edge] = []
    for i in range(n_nodes):
        for j in range(i + 1, n_nodes):
            edges.append((i, j))
    return GraphTopology.from_edges(n_nodes, edges)


def load_skew(loads: Sequence[float]) -> float:
    """
    Simple skew metric for a per-node load vector.

    Returns:
        (max(load) - mean(load)) / mean(load)

    If mean(load) == 0, returns 0.0
    """
    if not loads:
        return 0.0
    mean_load = sum(loads) / len(loads)
    if mean_load == 0:
        return 0.0
    return (max(loads) - mean_load) / mean_load


def latency_skew(latencies: Sequence[float]) -> float:
    """
    Same skew structure as load_skew, but for latency.
    """
    if not latencies:
        return 0.0
    mean_latency = sum(latencies) / len(latencies)
    if mean_latency == 0:
        return 0.0
    return (max(latencies) - mean_latency) / mean_latency


if __name__ == "__main__":
    grid = GridTopology(3, 3)
    print("GRID SNAPSHOT:", grid.snapshot())
    print("GRID NEIGHBORS(4):", grid.neighbors(4))
    print("GRID MEAN PATH:", grid.mean_path_length())

    star = star_topology(6, hub=0)
    print("STAR SNAPSHOT:", star.snapshot())
    print("STAR NEIGHBORS(0):", star.neighbors(0))
    print("STAR LAPLACIAN:")
    for row in star.laplacian_matrix():
        print(row)
