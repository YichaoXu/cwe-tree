class CweNode:
    """
    Represents a single CWE (Common Weakness Enumeration) node in the CWE hierarchy.

    A CWE node contains:
    - A unique CWE ID.
    - A name describing the weakness.
    - An abstract type (e.g., Class, Base, Variant).
    - A layer mapping indicating its depth in different root trees.
    - Parent-child relationships to track CWE dependencies.
    """

    def __init__(self, cwe_id: str, name: str, abstract: str):
        """
        Initializes a CWE node with its unique ID, name, and type.

        Args:
            cwe_id (str): The unique CWE identifier (e.g., "CWE-732").
            name (str): The name/description of the CWE.
            abstract (str): The abstraction type (e.g., "Class", "Base", "Variant").
        """
        self._cwe_id = cwe_id  # CWE ID (e.g., "CWE-732")
        self._name = name  # CWE Name (e.g., "Incorrect Permission Assignment for Critical Resource")
        self._abstract = abstract  # CWE Type (e.g., "Class", "Base", "Variant")
        self._layer = {}  # Dictionary to store layer levels in different trees { "CWE-284": 2 }
        self._parents = set()  # Set of parent nodes (other CWEs this node is derived from)
        self._children = set()  # Set of child nodes (other CWEs that depend on this node)

    @property
    def cwe_id(self) -> str:
        """Returns the CWE ID (read-only)."""
        return self._cwe_id

    @property
    def name(self) -> str:
        """Returns the CWE name (read-only)."""
        return self._name

    @property
    def abstract(self) -> str:
        """Returns the CWE abstraction type (read-only)."""
        return self._abstract

    @property
    def layer(self) -> dict:
        """
        Returns a copy of the layer mapping.

        The layer mapping stores the depth level of this node in different root CWE trees.
        Example:
            { "CWE-284": 2 } means this node is at level 2 in the CWE-284 hierarchy.
        """
        return self._layer.copy()  # Return a copy to prevent modification

    @property
    def parents(self) -> set:
        """
        Returns a copy of the set of parent CWE nodes.

        Parents are CWEs from which this node is derived.
        """
        return self._parents.copy()  # Return a copy to prevent modification

    @property
    def children(self) -> set:
        """
        Returns a copy of the set of child CWE nodes.

        Children are CWEs that depend on this node.
        """
        return self._children.copy()  # Return a copy to prevent modification

    def _add_layer(self, root_id: str, level: int):
        """
        Adds or updates the layer mapping for this node.

        Args:
            root_id (str): The root CWE ID representing the tree.
            level (int): The depth level of this node in the specified CWE tree.
        """
        self._layer[root_id] = level

    def _add_parent(self, parent_id: str):
        """
        Adds a parent CWE ID to this node.

        Args:
            parent_id (str): The CWE ID of the parent node.
        """
        self._parents.add(parent_id)

    def _add_child(self, child_id: str):
        """
        Adds a child CWE ID to this node.

        Args:
            child_id (str): The CWE ID of the child node.
        """
        self._children.add(child_id)

    def get_metadata(self) -> dict:
        """
        Returns metadata of this CWE node, including its ID, name, abstraction type, layer mapping,
        and relationships (parents and children).

        Returns:
            dict: A dictionary containing CWE node information.
        """
        return {
            "id": self.cwe_id,
            "name": self.name,
            "abstract": self.abstract,
            "layer": self.layer,  # Layer mapping in different root trees
            "parents": list(self.parents),  # Convert set to list for serialization
            "children": list(self.children),  # Convert set to list for serialization
        }
