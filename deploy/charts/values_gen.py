import yaml
import json

data = None
with open("values.truth.yaml", 'r') as stream:
    try:
        data = yaml.safe_load(stream)
    except yaml.YAMLError as exc:
        print(exc)

def transformNode(node):
    new_node = {}
    # if node.ca.comment:
    #     new_node['$comment'] = str(node.ca.comment)

    for key, value in node.items():
        if key[0] == "$":
            new_node[key] = value
            continue
        
        if key[0] == "_":
            k = key[1:]

            if k == "items":
                new_node[k] = transformNode(value)
            else:
                new_node[k] = value
            
            continue

        if "properties" not in new_node:
            new_node["type"] = "object"
            new_node["properties"] = {}

        new_node["properties"][key] = transformNode(value)
    
    return new_node

def postTransform(node):
    if node["type"] == "object":
        required = []
        for key, value in node["properties"].items():
            if "$optional" not in value:
                required.append(key)
            else:
                del node["properties"][key]["$optional"]

        node["required"] = required
    return node


transformed = transformNode(data["$properties"])
transformed = postTransform(transformed)

with open('values.schema.json', 'w') as outfile:
    print(json.dump(transformed, outfile))
