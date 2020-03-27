import logging
import argparse
import r2pipe
import binascii
import struct
import sys
import os
import json
import base64 

class R2Api:
    '''
    This class is for interfacing with radare2
    '''

    r = None # the main r2 object

    def __init__(self, gdbhost="127.0.0.1", gdbport="1234", bitness=64):
        '''

        '''
        self.r = r2pipe.open("gdb://{}:{}".format(gdbhost, gdbport), ["-D gdb"])
        try:
            self.rcmd("dr")
        except IOError:
            logging.fatal("Failed to connect to gdbserver! Is it running?")
            sys.exit(1)
        self.bitness = bitness
        self.set_settings(bitness)


    # detach on cleanup
    def detach(self):
        self.rcmd("dp-*")

    def set_settings(self,bitness=64):
        self.rcmd("e dbg.bpinmaps=false")
        self.rcmd("e search.in=??")
        self.rcmd("e search.in=raw")
        self.rcmd("e search.maxhits=1")
        if (bitness==64):
            self.searchmin=0xffffffff80000000
            self.searchmax=0xffffffffffffffff
        else:
            self.searchmin=0xc0000000
            self.searchmax=0xffffffff
        self.searchfrom = self.searchmin
        self.searchto = self.searchmax
        self.rcmd("e asm.bits = {}".format(bitness))
        self.rcmd("e search.from=0x{:x}".format(self.searchmin))#ffffffff80000000")
        self.rcmd("e search.to=0x{:x}".format(self.searchmax))#0xffffffffffffffff")

    def rcmd(self, command, repeat=1):
        if (repeat > 1):
          command="{0}{1}".format(repeat,command)
        logging.debug("R2 Command: {}".format(command))
        out=self.r.cmd(command)
        logging.debug("R2 output: {}\n".format(out[:1024]))
        return out

    def set_search_range( self, sfrom, sto ):
        self.rcmd("e search.from=0x{:x}".format(sfrom))
        self.rcmd("e search.to=0x{:x}".format(sto))
        self.searchfrom = sfrom
        self.searchto = sto
        

    def _search_internal(self, cmd, searchbytes, offset=-1 ):
        foundloc=-1
        #if (offset != -1):
        #    self.seekto(offset)
        found = self.rcmd(cmd+" {}".format(binascii.hexlify(searchbytes).decode("utf-8")))
        if found != "":
            foundloc = int(found.split(" ")[0], 16)
        return foundloc

    def seekto( self, offset ):
        self.rcmd("0x{:x}".format(offset))

    def find(self, searchbytes, offset=-1, end=-1 ):
        if (offset != -1):
            sfrom = self.searchfrom
            self.set_search_range( offset, self.searchto )
        if (end != -1):
            self.set_search_range( offset, end )
        out = self._search_internal( "/x", searchbytes, offset )
        if (offset != -1):
            # restore the search range
            self.set_search_range( sfrom, self.searchto )
        return out

    def rfind(self, searchbytes, offset=-1 ):
        if (offset != -1):
            self.seekto(offset)
        return self._search_internal( "/bx", searchbytes, offset )

    def findall(self, searchbytes, offset=-1, end=-1):
        results=[]
        off=self.find(searchbytes, offset, end)
        while off != -1:
            results.append( off )
            off=self.find(searchbytes, off+len(searchbytes), end )
        return results

    def findptr( self, addr, offset=-1, end=-1 ):
        # find a ptr to addr 
        if (self.bitness == 64):
            addr_packed = struct.pack("<Q", addr)
        else:
            addr_packed = struct.pack("<L", addr)
        return self.find( addr_packed, offset, end )

    def findallptrs(self, addr, offset=-1, end=-1 ):
        results=[]
        off=self.findptr(addr, offset, end)
        while off != -1:
            results.append( off )
            off=self.findptr(addr, off+1, end )
        return results
        
    def findstr(self, searchstr ):
        return self.find( searchstr.encode('utf-8'), self.searchmin )

    def readstr(self, offset ):
        # need to strip trailing newline
        return self.rcmd("psz @ {}".format( offset ))[:-1]
        
    def read( self, offset, length ):
        #self.seekto( offset )
        out = self.rcmd("p6e {0} @ {1}".format( length, offset ))
        return base64.b64decode(out)

    def readushort( self, offset ):
        return int(self.rcmd("pfN2 @ 0x{:x}".format( offset )).split()[-1])

    def readuint( self, offset ):
        return int(self.rcmd("pfN4 @ 0x{:x}".format( offset )).split()[-1])

    def readptr( self, offset, count=1 ):
        # radare2 has a limit of only a few pv's at a time
        maxblock=20
        if (count > maxblock):
            # too many to read at once. First get the size of one pointer
            outstr = self.rcmd("pv @0x{:x}".format(offset))
            #out = self.readptr( offset, 10 )
            ptrsize = int((len(outstr.split()[0])-2)/2)
            # read a block at a time. We could recurse properly, but Python has a recursion limit...
            out=[]
            left=count
            while left > 0:
                if left > maxblock:
                    toread = maxblock
                else:
                    toread = left
                if (toread == 1):
                    out.append( self.readptr( offset ) )
                else:
                    out += self.readptr( offset, toread )
                left -= toread
                offset += toread * ptrsize
            return out 
            #logging.debug("ptrsize: {0}".format(ptrsize))
            #return self.readptr( offset, maxblock ) + self.readptr( offset+(maxblock*ptrsize), count-maxblock )
        elif count==1:
            out = self.rcmd("pv @0x{:x}".format(offset))
        else:
            out = self.rcmd("pv {0} @0x{1:x}".format(count,offset))
        if (count==1):
            return int(out, 16)
        else:
            return [ int(ptr,16) for ptr in out.split() ]
