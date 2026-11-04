import json
import sys

import httpx
import trio
from holehe.core import import_submodules, get_functions


async def main(email, output_file):
    results = []
    limiter = trio.CapacityLimiter(3)
    async with httpx.AsyncClient(timeout=12, follow_redirects=True) as client:
        async def check(function):
            async with limiter:
                local = []
                try:
                    with trio.fail_after(18):
                        await function(email, client, local)
                    results.extend(local)
                except Exception:
                    results.append({"name": function.__name__, "error": "timeout_or_source_error"})
        async with trio.open_nursery() as nursery:
            for function in get_functions(import_submodules("holehe.modules")):
                nursery.start_soon(check, function)
    with open(output_file, "w") as out:
        json.dump(results, out)


trio.run(main, sys.argv[1], sys.argv[2])
