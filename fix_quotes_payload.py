with open("c2_server/server.py", "r") as f:
    content = f.read()

content = content.replace('\\"\\"\\"Handle a payload module request from the Nanomachine.\\"\\"\\"', '"""Handle a payload module request from the Nanomachine."""')

with open("c2_server/server.py", "w") as f:
    f.write(content)
