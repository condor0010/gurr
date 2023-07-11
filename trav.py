import argparse
import angr

# Create an argument parser
parser = argparse.ArgumentParser(description='CFG traversal with entry and exit nodes')
parser.add_argument('binary', type=str, help='Path to the binary file to analyze')
parser.add_argument('--start', type=str, help='Start node address in hex')
parser.add_argument('--end', type=str, help='End node address in hex')

# Parse the command-line arguments
args = parser.parse_args()

# Specify the binary file to analyze
binary = args.binary

# Create an angr project
proj = angr.Project(binary, auto_load_libs=False)

# Perform the CFG analysis
cfg = proj.analyses.CFG()

# Check if start address is specified, otherwise use the entry point
if args.start:
    start_node = int(args.start, 16)
else:
    start_node = proj.entry

# Get the start node of the CFG
start_node = cfg.get_any_node(start_node)

# Check if end address is specified
if args.end:
    end_node = int(args.end, 16)
    end_node = cfg.get_any_node(end_node)
else:
    end_node = None

# ANSI color codes
COLOR_ENTRY = '\033[92m'
COLOR_EXIT = '\033[91m'
COLOR_VISITED = '\033[94m'
COLOR_RESET = '\033[0m'

def traverse(node=start_node, visited=set(), indent_level=0):
    if node in visited:
        return

    visited.add(node)
    addr = hex(node.addr)

    # Apply color based on node type
    if node.addr == start_node.addr:
        addr = COLOR_ENTRY + addr + COLOR_RESET
    elif node == end_node:
        addr = COLOR_EXIT + addr + COLOR_RESET
    elif node in visited:
        addr = COLOR_VISITED + addr + COLOR_RESET

    print(" " * indent_level, addr)

    if node == end_node:
        return

    if node.successors:
        for suc in node.successors:
            traverse(suc, visited, indent_level + 1)

traverse()


