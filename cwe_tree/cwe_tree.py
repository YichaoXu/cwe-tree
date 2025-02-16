import json
from .cwe_node import CweNode

class CweTree:
    """
    Represents a CWE Tree, which contains CWE nodes and their relationships.

    This class manages:
    - Creating and storing CWE nodes.
    - Establishing parent-child relationships between CWE nodes.
    - Providing utility functions for retrieving metadata and relationships.
    """

    def __init__(self):
        """ Initializes an empty CWE Tree. """
        self._nodes = {}  # Dictionary to store CWE nodes { "CWE-732": CweNode, ... }

    def _normalize_cwe(self, cwe_id: str) -> str:
        """
        Normalizes a CWE ID to ensure consistency.

        If the CWE ID does not start with "CWE-", it adds the prefix.
        This allows users to query using either "732" or "CWE-732".

        Args:
            cwe_id (str): The CWE ID to normalize.

        Returns:
            str: Normalized CWE ID (e.g., "CWE-732").
        """
        return f"CWE-{cwe_id}" if not cwe_id.startswith("CWE-") else cwe_id

    def _add_node(self, cwe_id: str, name: str, abstract: str, layer: str):
        """
        Adds a CWE node to the tree.

        Args:
            cwe_id (str): The unique CWE identifier.
            name (str): The name/description of the CWE.
            abstract (str): The abstraction type (e.g., "Class", "Base", "Variant").
            layer (str): A JSON string or dictionary representing the node's layer levels.
        """
        cwe_id = self._normalize_cwe(cwe_id)

        # Create node if it doesn't already exist
        if cwe_id not in self._nodes:
            self._nodes[cwe_id] = CweNode(cwe_id, name, abstract)

        # Parse and store layer data (JSON format)
        try:
            layer_data = json.loads(layer) if isinstance(layer, str) else layer
            if isinstance(layer_data, dict):
                for root, level in layer_data.items():
                    self._nodes[cwe_id]._add_layer(root, level)
        except json.JSONDecodeError:
            pass  # Ignore invalid layer data

    def _add_edge(self, parent_id: str, child_id: str):
        """
        Establishes a parent-child relationship between two CWE nodes.

        Args:
            parent_id (str): The CWE ID of the parent node.
            child_id (str): The CWE ID of the child node.
        """
        parent_id, child_id = self._normalize_cwe(parent_id), self._normalize_cwe(child_id)

        # Ensure both nodes exist before creating a relationship
        if parent_id in self._nodes and child_id in self._nodes:
            self._nodes[parent_id]._add_child(child_id)
            self._nodes[child_id]._add_parent(parent_id)

    def get_node(self, cwe_id: str) -> CweNode:
        """
        Retrieves a CWE node by its ID.

        Args:
            cwe_id (str): The CWE ID to retrieve.

        Returns:
            CweNode: The requested CWE node, or None if it does not exist.
        """
        cwe_id = self._normalize_cwe(cwe_id)
        return self._nodes.get(cwe_id)

    def get_parents(self, cwe_id: str) -> set:
        """
        Retrieves the parents of a given CWE node.

        Args:
            cwe_id (str): The CWE ID whose parents should be retrieved.

        Returns:
            set: A set of parent CWE IDs.
        """
        node = self.get_node(cwe_id)
        return node.parents if node else set()

    def get_children(self, cwe_id: str) -> set:
        """
        Retrieves the children of a given CWE node.

        Args:
            cwe_id (str): The CWE ID whose children should be retrieved.

        Returns:
            set: A set of child CWE IDs.
        """
        node = self.get_node(cwe_id)
        return node.children if node else set()

    def get_layer(self, cwe_id: str) -> dict:
        """
        Retrieves the layer information for a given CWE node.

        Args:
            cwe_id (str): The CWE ID whose layer should be retrieved.

        Returns:
            dict: A dictionary representing the layer mapping (e.g., { "CWE-284": 2 }).
        """
        node = self.get_node(cwe_id)
        return node.layer if node else {}

    def get_metadata(self, cwe_id: str) -> dict:
        """
        Retrieves metadata for a given CWE node.

        Args:
            cwe_id (str): The CWE ID whose metadata should be retrieved.

        Returns:
            dict: A dictionary containing metadata about the CWE node.
        """
        node = self.get_node(cwe_id)
        return node.get_metadata() if node else None

    def get_roots(self) -> list:
        """
        Retrieves all root nodes in the CWE tree.

        Root nodes are nodes that have no parents.

        Returns:
            list: A list of CweNode instances that have no parents.
        """
        return [node for node in self._nodes.values() if not node.parents]
