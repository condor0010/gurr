import angr

# Specify the binary file to analyze
binary = './a.out'

# Create an angr project
proj = angr.Project(binary, auto_load_libs=False)

# Perform the CFG analysis
cfg = proj.analyses.CFG()

# Get the entry node of the CFG
entry_node = cfg.get_any_node(proj.entry)

def traverse(node=entry_node, visited=set(), indent_level=0):
    if node in visited:
        return

    visited.add(node)
    symbol = proj.loader.find_symbol(node.addr)
    symbol_name = symbol.name if symbol else ""
    print(" " * indent_level, hex(node.addr), symbol_name)

    if node.successors:
        for suc in node.successors:
            traverse(suc, visited, indent_level + 1)

traverse()

