with open("c2_server/server.py", "r") as f:
    content = f.read()

content = content.replace('def _handle_payload_req(self, data):', '    def _handle_payload_req(self, data):')
content = content.replace('    def _handle_exfil(self, data):', '    def _handle_exfil(self, data):')

with open("c2_server/server.py", "w") as f:
    f.write(content)
