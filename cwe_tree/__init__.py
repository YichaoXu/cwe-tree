import csv, os
from .cwe_node import CweNode  # Import the CweNode class (represents a CWE node)
from .cwe_tree import CweTree  # Import the CweTree class (represents the entire CWE tree)

# Get the absolute path of the current file and locate the `data/` directory containing CSV files
base_path = os.path.dirname(os.path.abspath(__file__))  # Get the module's directory path
nodes_csv = os.path.join(base_path, "data", "nodes.csv")  # Path to the nodes CSV file
rels_csv = os.path.join(base_path, "data", "rels.csv")  # Path to the relationships CSV file

def _load_data(cwe_tree: CweTree) -> CweTree:
    """
    Loads data from `nodes.csv` and `rels.csv` in the `data/` directory and populates the CweTree instance.

    Args:
        cwe_tree (CweTree): An instance of CweTree to be populated with data.

    Returns:
        CweTree: A fully populated CweTree instance containing all CWE nodes and relationships.
    """
    base_path = os.path.dirname(os.path.abspath(__file__))  # Get module's directory path
    nodes_csv = os.path.join(base_path, "data", "nodes.csv")  # Path to the nodes CSV file
    rels_csv = os.path.join(base_path, "data", "rels.csv")  # Path to the relationships CSV file

    # Read `nodes.csv` and add nodes to the CweTree
    with open(nodes_csv, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)  # Read CSV as a dictionary
        for row in reader:
            cwe_id = row["id"]  # Retrieve CWE ID
            name = row["name"]  # Retrieve CWE name
            abstract = row["abstract"]  # Retrieve CWE abstraction type
            layer = row["layer"]  # Retrieve layer information
            cwe_tree._add_node(cwe_id, name, abstract, layer)  # Add node to CweTree

    # Read `rels.csv` and add relationships (edges)
    with open(rels_csv, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)  # Read CSV as a dictionary
        for row in reader:
            parent_id = row["source"]  # Retrieve source (parent) CWE ID
            child_id = row["target"]  # Retrieve target (child) CWE ID
            cwe_tree._add_edge(parent_id, child_id)  # Add edge (parent-child relationship) in CweTree

    return cwe_tree  # Return the populated CweTree instance

# Create a `CweTree` instance and load data immediately when the module is imported
query: CweTree = _load_data(CweTree())

# Define `__all__` to specify the public API of the module
__all__ = ["query", "CweTree", "CweNode"]  # Allows users to import `query`, `CweTree`, and `CweNode`
