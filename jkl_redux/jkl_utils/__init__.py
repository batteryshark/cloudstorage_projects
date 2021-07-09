import jkl_globals
import jkl_logging

import hashlib

# Hash a local file with block_size=2^25 or 32MB.
def get_md5sum(infile,byte_range=None, block_size=2 ** 25):
    f = open(infile, "rb")
    md5 = hashlib.md5()
    while True:
        if(byte_range != None):
            if(f.tell()+block_size > byte_range[1]):
                data = f.read(byte_range[1] - f.tell())
                md5.update(data)
                break
            else:
                data = f.read(block_size)
        else:
            data = f.read(block_size)
        if not data:
            break
        md5.update(data)
    f.close()
    return md5.hexdigest()