# CWE Tree Python Package

## Overview

This package provides a structured representation of the [Common Weakness Enumeration (CWE)](https://cwe.mitre.org/) hierarchy using a tree-based data model. It allows users to query CWE nodes, understand parent-child relationships, and extract metadata for each CWE entry.

## Features
- Load CWE nodes and relationships from CSV files (`nodes.csv` and `rels.csv`).
- Represent CWE entries as `CweNode` objects.
- Store and manage the entire CWE structure as a `CweTree`.
- Query CWE metadata, parent-child relationships, and tree layers.

## Installation

Clone this repository and install dependencies if required:

```sh
pip install -e . 
```

or using pip repo

```sh
pip install cwe_tree 
```

## Usage

### Import the package
```python
from cwe_tree import query, CweTree, CweNode
```

### Querying CWE nodes

```python
# Retrieve a CWE node by ID
cwe_node = query.get_node("CWE-732")
if cwe_node:
    print(cwe_node.get_metadata())
```

### Fetching parent-child relationships

```python
# Get parent CWEs
parents = query.get_parents("CWE-732")
print("Parent CWE IDs:", parents)

# Get child CWEs
children = query.get_children("CWE-732")
print("Child CWE IDs:", children)
```

### Retrieving metadata

```python
metadata = query.get_metadata("CWE-732")
print("CWE Metadata:", metadata)
```

### Getting root nodes
```python
roots = query.get_roots()
print("Root CWE nodes:", [node.cwe_id for node in roots])
```

## API Reference

### `CweNode`
Represents a single CWE entry.

#### Properties:
- `cwe_id`: The unique CWE identifier.
- `name`: The CWE name/description.
- `abstract`: The abstraction type (e.g., Class, Base, Variant).
- `layer`: A dictionary representing the depth in various CWE trees.
- `parents`: A set of parent CWE IDs.
- `children`: A set of child CWE IDs.

#### Methods:
- `get_metadata() -> dict`: Returns CWE node metadata.

### `CweTree`
Manages the CWE hierarchy and provides querying capabilities.

#### Methods:
- `get_node(cwe_id: str) -> CweNode`: Retrieves a CWE node by ID.
- `get_parents(cwe_id: str) -> set`: Returns parent CWE IDs.
- `get_children(cwe_id: str) -> set`: Returns child CWE IDs.
- `get_layer(cwe_id: str) -> dict`: Returns the CWE's layer mapping.
- `get_metadata(cwe_id: str) -> dict`: Returns CWE metadata.
- `get_roots() -> list`: Returns a list of root CWE nodes.

## Data Format

The package loads CWE data from CSV files:
- `nodes.csv`: Contains CWE nodes with columns: `id`, `name`, `abstract`, `layer`
- `rels.csv`: Contains relationships with columns: `source`, `target`

## License
This package is released under the MIT License.

## Contributing
Contributions are welcome! Please submit a pull request or open an issue for discussions.

