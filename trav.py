import argparse
import angr

# Specify the binary file to analyze
binary = './a.out'

# Create an angr project
proj = angr.Project(binary, auto_load_libs=False)

# Perform the CFG analysis
cfg = proj.analyses.CFG()

# Create an argument parser
parser = argparse.ArgumentParser(description='CFG traversal with entry and exit nodes')
parser.add_argument('entry_node', type=str, help='Entry node address in hex')
parser.add_argument('exit_node', type=str, help='Exit node address in hex')

# Parse the command-line arguments
args = parser.parse_args()

# Convert hexadecimal input to integer
entry_node = int(args.entry_node, 16)
exit_node = int(args.exit_node, 16)

# Get the entry node of the CFG
entry_node = cfg.get_any_node(entry_node)

def traverse(node=entry_node, visited=set(), indent_level=0):
    if node in visited:
        return

    visited.add(node)
    symbol = proj.loader.find_symbol(node.addr)
    symbol_name = symbol.name if symbol else ""
    print(" " * indent_level, hex(node.addr), symbol_name)

    if node.addr == exit_node:
        return

    if node.successors:
        for suc in node.successors:
            traverse(suc, visited, indent_level + 1)

traverse()
