from cwe_tree import query

cwe_id = "CWE-732"
cwe_node = query.get_node(cwe_id)
print(f"Metadata of {cwe_id}: {cwe_node.get_metadata()}")
