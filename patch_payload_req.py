import re

with open("c2_server/server.py", "r") as f:
    content = f.read()

# Replace the specific malformed docstring string
content = content.replace('def _handle_payload_req(self, data):', '    def _handle_payload_req(self, data):')

with open("c2_server/server.py", "w") as f:
    f.write(content)
print("Patch applied.")
