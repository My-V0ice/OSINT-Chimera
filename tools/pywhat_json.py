import json
import sys
from pathlib import Path
from pywhat import identifier

if __name__ == '__main__':
    # only_text prevents treating caller input as a file or directory.
    result = identifier.Identifier().identify(sys.argv[1], only_text=True)
    Path(sys.argv[2]).write_text(json.dumps(result, ensure_ascii=False), encoding='utf-8')
