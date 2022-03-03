from dataclasses import dataclass
from typing import Dict
import random


@dataclass
class Node:
    """Model our graph nodes."""
    num: int
    val: int
    left: int
    right: int


def read_in_graph():
    """Used to read our graph and nodes from the text file and print them as a dict."""
    store_graph = {}
    with open("./working/graph") as graph:
        for i in range(0, 16):
            num = int(graph.readline().strip('\n'))
            left = int(graph.readline().strip('\n'))
            val = int(graph.readline().strip('\n'), 16)
            right = int(graph.readline().strip('\n'))
            store_graph[i] = Node(num=num, left=left, val=val, right=right)
    from pprint import pprint
    pprint(store_graph)


def find_path(graph: Dict) -> str:
    equalizer = 0x47BBFA96 ^ 0x40475194
    while equalizer != 0:
        current_node = 0
        equalizer = 0x47BBFA96 ^ 0x40475194
        path = []
        for i in range(0, 16):
            choice = random.choice(['L', 'R'])
            path.append(choice)
            if choice == 'L':
                current_node = graph[graph[current_node].left].num
                equalizer = equalizer ^ graph[current_node].val
            else:
                current_node = graph[graph[current_node].right].num
                equalizer = equalizer ^ graph[current_node].val

            if equalizer == 0:
                break

        print(f"Final path: {path}")
    print(f"Solution path: {path}")


if __name__ == '__main__':
    graph = {0: Node(num=0, val=1203501718, left=5, right=2),
             1: Node(num=1, val=1343691374, left=15, right=7),
             2: Node(num=2, val=601551857, left=10, right=6),
             3: Node(num=3, val=1665303763, left=5, right=8),
             4: Node(num=4, val=877416113, left=12, right=13),
             5: Node(num=5, val=205552111, left=9, right=15),
             6: Node(num=6, val=1113505173, left=2, right=3),
             7: Node(num=7, val=128771913, left=9, right=6),
             8: Node(num=8, val=595212936, left=11, right=3),
             9: Node(num=9, val=1266969782, left=12, right=3),
             10: Node(num=10, val=532322968, left=15, right=8),
             11: Node(num=11, val=977982463, left=5, right=8),
             12: Node(num=12, val=377785366, left=3, right=2),
             13: Node(num=13, val=1235150030, left=4, right=7),
             14: Node(num=14, val=639301883, left=8, right=3),
             15: Node(num=15, val=1997449258, left=9, right=13)}

    find_path(graph)

"""
$ python3 working/graph_traverser.py
$ python3 working/graph_traverser.py
Final path: ['R', 'L', 'R', 'L', 'L', 'R', 'L', 'L', 'L', 'L', 'L', 'L', 'R', 'L', 'R', 'L']
Final path: ['R', 'L', 'R', 'R', 'R', 'R', 'L', 'L', 'R', 'L', 'L', 'L', 'L', 'R', 'L', 'R']
Final path: ['L', 'R', 'L', 'R', 'R', 'L', 'L', 'L', 'R', 'L', 'R', 'L', 'R', 'L', 'R', 'L']
Final path: ['L', 'L', 'R', 'R']
Solution path: ['L', 'L', 'R', 'R']
"""
