#!/usr/bin/env python3

import copy
import json
import os
import shutil
import sys

def main():
    with open("addresses.json") as f:
        j = json.loads(f.read())
        assert type(j) is list and len(j)
        print(f"Read {len(j)} addresses")
        addresses = j
        del j
    with open("template.json") as f:
        j = json.loads(f.read())
        assert type(j) is dict and len(j) and type(j.get("worker")) is list
        template = j
        del j
    outdir = os.path.join("logs", "users")
    os.makedirs(outdir)
    ctr = 0
    for addr in addresses:
        file = os.path.join(outdir, addr)
        if os.path.exists(file):
            continue
        with open(file, "wt") as f:
            salt = os.urandom(4).hex()
            j = copy.deepcopy(template)
            j["worker"][0]["workername"] = addr + "." + salt
            f.write(json.dumps(j, indent=4))
        ctr += 1
    print(f"Wrote {ctr} new fake user files to {outdir}")


if __name__ == "__main__":
    main()
