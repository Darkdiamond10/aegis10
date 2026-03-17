with open("c2_server/server.py", "r") as f:
    content = f.read()

content = content.replace('\\"\\"\\"\n        Handle a stage request — the stager is asking for the Ghost Loader binary.\n        \\"\\"\\"', '"""\n        Handle a stage request — the stager is asking for the Ghost Loader binary.\n        """')

with open("c2_server/server.py", "w") as f:
    f.write(content)
