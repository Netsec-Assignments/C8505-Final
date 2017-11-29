from __future__ import division

import struct

def make_8_byte_str(instr):
    """Pads and folds the password as necessary to create a bytes() object with 8 bytes.
    
    Note: this doesn't handle unicode, and I'm not going to bother.

    Positional arguments:
    password - the (ASCII) string to convert to 8 bytes.
    
    Returns a bytes() containing the converted input.
    """
    instrlen = len(instr)
    if instrlen == 8:
        return instr

    
    # If the password's length isn't divisible by 8, add the password to itself until it is padded
    # to a multiple of 8
    remainder = instrlen % 8
    if remainder:
        if instrlen >= remainder:
            instr += instr[0:remainder]
        else:
            full_chunks = remainder // instrlen
            last_chunk = remainder % instrlen

            for i in range(full_chunks):
                instr += instr

            if last_chunk:
                instr += instr[0:last_chunk]

    # why this xor stuff? who cares?
    result = struct.unpack("<Q", instr[0:8])[0]
    chunks = len(instr) // 8
    for i in range(1, chunks):
        start = i * 8
        end = start + 8
        nextlong = struct.unpack("<Q", instr[start:end])[0]
        result ^= nextlong

    return struct.pack("<Q", result)

def make_32_byte_str(instr):
    """Pads and folds the given input as necessary to create a bytes() object with 32 bytes.
    
    Note: this doesn't handle unicode, and I'm not going to bother.

    Positional arguments:
    password - the (ASCII) string to convert to a bytes() object with 32 bytes.
    
    Returns a bytes() object containing the converted input.
    """

    instrlen = len(instr)
    if instrlen == 32:
        return instr
    elif instrlen < 32:
        # cheat a bit;
        # pad the last < 8-byte chunk to 8 bytes and add it to the string until we hit 32 bytes
        eight_byte_chunks = instrlen // 8
        remainder = instrlen % 8
        start = (eight_byte_chunks - (1 if remainder == 0 else 0)) * 8

        # cut off the remainder (if there is one) or the last complete 8-byte chunk
        # determine how many chunks we need to add back
        # add the last (possibly padded) 8-byte chunk back to the string to make 32 bytes
        last_eight_bytes = make_8_byte_str(instr[start:])
        instr = instr[0:start]
        to_add = 4 - (eight_byte_chunks + (1 if remainder == 0 else 0))

        for i in range(to_add):
            instr += last_eight_bytes

        return instr
    else:
        # now we're getting reaaaal lazy
        return instr[0:32]
    
        

