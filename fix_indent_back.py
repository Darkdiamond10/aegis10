with open("c2_server/server.py", "r") as f:
    content = f.read()

content = content.replace('        def _handle_stage_req(self, data):', '    def _handle_stage_req(self, data):')

with open("c2_server/server.py", "w") as f:
    f.write(content)
