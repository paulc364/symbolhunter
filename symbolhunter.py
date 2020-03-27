#!/usr/bin/env python3

import logging
import argparse
import r2pipe
import binascii
import struct
import sys
import os
import json
import base64 

#import pdb
from r2api import R2Api


class InfoHunter:
    '''
    This class is for gathering required information needed for further exploitation.
    It will get:
    ksymtab (for symbols)
    task_struct
        task_struct member offsets
    '''

    r = None # the main r2 object
    # key addresses / offsets
    found = {}
    # ksymtable
    symbols = {}

    def __init__(self, gdbhost="127.0.0.1", gdbport="1234",ptrsize=8):
        '''

        '''
        self.bitness = ptrsize*8
        self.r2 = R2Api( gdbhost, gdbport, self.bitness )
        self.ptrsize=ptrsize
        self.r=self.r2.r

    def rcmd(self, command):
        logging.debug("R2 Command: {}".format(command))
        return self.r.cmd(command)

    def save_symbols_to_file(self, filename="symbols.csv"):
        if len(self.symbols) == 0:
            logging.error("No symbols to dump!")
            return
        with open(filename, "w") as fh:
            for entry in self.symbols:
                fh.write("{},0x{:x}\n".format(entry, self.symbols[entry]))

    def add_type( self, struc, name, kind, size, signed ):
        ''' Add a basic type as a dict - e.g.:
          "char": {
          "size": 1,
          "signed": true,
          "kind": "char",
          "endian": "little"
        },
        Everything is little endian for now
        '''
        struc[name] = { 'size' : size, "signed": signed, "kind": kind, "endian": "little" }
        
    def make_basic_types( self ):
        '''
        :returns: a dict with the basic types
        '''
        basics={}
        self.add_type( basics, "", "int", self.ptrsize, False )
        self.add_type( basics, "_bool", "bool", 1, False )
        self.add_type( basics, "char", "char", 1, True )
        self.add_type( basics, "double", "float", 8, True )
        self.add_type( basics, "int", "int", 4, True )
        self.add_type( basics, "unsigned int", "int", 4, False )
        self.add_type( basics, "long int", "int", self.ptrsize, True )
        self.add_type( basics, "long long int", "int", 8, True )
        self.add_type( basics, "long long unsigned int", "int", 8, False )
        self.add_type( basics, "long unsigned int", "int", self.ptrsize, False )
        self.add_type( basics, "pointer", "int", self.ptrsize, False )
        self.add_type( basics, "short int", "int", 2, True )
        self.add_type( basics, "short unsigned int", "int", 2, False )
        self.add_type( basics, "signed char", "char", 1, True )
        self.add_type( basics, "unsigned char", "char", 1, False )
        self.add_type( basics, "void", "void", 0, False )
        return basics

    def save_json_symbols( self, filename="symbols.json", enumfile=None, guess=False):
        alldata = {}

        if guess and not 'dentry_operations' in self.__dict__:
            self.build_dentry_operations( 6 )

        # make metadata header
        metadata = { "source": { "file": "vmlinux", "type": "heuristic" },
          "producer": { "name": "symbolhunter", "version": "0.1" },
          "format": "4.1.0"
        }
        alldata["metadata"] = metadata

        # add base types
        basics = self.make_basic_types()
        alldata["base_types"] = basics

        # format the banner        
        banner = { "type": { "count": len(self.banner),
                   "kind": "array", "subtype": { "kind": "base","name":"char"} },
                   "address": self.bannaddr,
                   "constant_data": str(base64.b64encode(bytearray(self.banner,'utf-8')),'utf-8') }

        if not 'files_struct' in self.__dict__:
            if guess:
                self.build_files_struct()
            else:
                logging.error("No files_struct found - try using -g to guess a suitable structure")
   
    
        if not 'vfsmount' in self.__dict__:
            if guess:
                self.build_vfsmount()
            else:
                logging.error("No vfsmount found - try using -g to guess a suitable structure")

        if not 'dentry' in self.__dict__:
            if guess:
                self.build_dentry()
            else:
                logging.error("No dentry found - try using -g to guess a suitable structure")

        if guess and not 'inode' in self.__dict__:
            self.build_inode()
    
        # add task_struct, mm_struct etc
        alldata["user_types"] = { "task_struct" : self.task_struct,
                                  "mm_struct" : self.mm_struct,
                                  "list_head" : self.list_head,
                                  "qstr" : self.qstr,
                                  "fs_struct" : self.fs_struct,
                                  "files_struct" : self.files_struct,
                                  "super_block" : self.super_block,
                                  "vfsmount" : self.vfsmount,
                                  "dentry" : self.dentry,
                                  "file" : self.file_struct,
                                  "path" : self.path_struct,
                                  "fdtable" : self.fdtable,
                                  "dentry_operations" : self.dentry_operations,
                                  "inode" : self.inode,
                                  "vm_area_struct" : self.vm_area_struct,
                                  "module" : self.module }

        # now the symbols - currently we just have dict of name -> address
        # we need dict of at least name -> { "address" : value }
        symdict = {}
        for kk in self.symbols.keys():
            symdict[kk]={ "address" : self.symbols[kk] }
            if kk == 'init_task':
                symdict[kk]['type'] = { "kind": "struct", "name": "task_struct" }


        alldata["symbols"] = symdict
        alldata["symbols"]["linux_banner"] = banner 

        if (enumfile != None):
            with open(enumfile, "r") as ef:
                jsondata=ef.read()
                enumdata=json.loads(jsondata)
                alldata["enums"] = enumdata["enums"]

        savedata=json.dumps( alldata, indent=2 )

        # write to file
        with open(filename, "w") as fh:
            fh.write( savedata )

        return

    def find_linux_banner( self ):
        '''
        Locates the linux banner in memory
        :returns: the banner string and the location of the banner
        '''
        bannloc = self.r2.findstr("Linux version ")
        banner=''
        if (bannloc != -1):
            banner = self.r2.readstr( bannloc )
            banner += '\n\x00'
        # do some checks
        return banner, bannloc

    def verify_ascii( self, item ):
        '''
        Verifies that the char array is filled with valid printable ascii characters.
        :pram item: list of ascii characters to validate
        :type item: list of chars
        :returns: True if all the characters are ascii printable
        '''
        for ch in item:
            num=ord(ch)
            if ((num < 0x20) or (num > 0x7e)):
                #logging.debug("num 0x{:x} not ascii".format(num))
                return False
        return True

    def read_ascii_strings( self, offset, count=-1, max_length=256 ):
        allstrings=[]
        if (count < 0):
            doAll=True
        else:
            doAll=False

        while (doAll or (len(allstrings) < count)):
            entry = self.r2.readstr( offset )
            if (len(entry)==0):
                break
            offset += len( entry )+1
            if (not self.verify_ascii( entry )):
                #allstrings=None
                break
            allstrings.append( entry )
            #logging.debug("added string {}\n".format(entry))
        return allstrings

    def strtab_pattern_fetch( self, str_offset, strcount=-1 ):
        '''
        Returns a tuple of (strings, string lengths, start_offsets) at str_offset if present
        '''
        # find a good number of strings
        #strcount = 20
        strlist = self.read_ascii_strings( str_offset, strcount )
        if (strlist == None):
            return None
        pattern = [ len(ss)+1 for ss in strlist ]
        off=0
        offsets=[ 0 ]
        for ll in pattern[:-1]:
            off += ll
            offsets.append( off ) 
        return (strlist, pattern, offsets)

    def find_symtab( self ):
        '''
        Attempts to find the symtab and store in member variables.
        '''
        # first search for init_task - should be at start of strtab
        init_task_bytes = b"init_task\00"
        found = self.r2.find(init_task_bytes)

        if found == -1:
            logging.info("init_task string not found")
            return False

        init_ptr=-1
        
        while (found != -1):
          init_task = found
          # we want the first two strings, first will be init_task then something
          second_entry = init_task + 10

          logging.debug("\n\n0x{:x} Second: 0x{:x}".format(init_task,second_entry))
          # search backwards, we want a pointer to first, then 16 bytes later to second
          # self.rcmd("e search.to=0x{:x}".format(init_task))
          # self.rcmd("e search.from=0xffffffff00000000")
          if (self.ptrsize == 8):
              init_task_packed = struct.pack("<Q", init_task)
          else:
              init_task_packed = struct.pack("<L", init_task)

          if init_ptr == -1:
            init_ptr = self.r2.rfind( init_task_packed, init_task )
          if (init_ptr == -1):
              logging.info("init_task string pointer not found - searching for another instance of the string\n")
              found = self.r2.find(init_task_bytes, found+10)
              continue
              #return False

          logging.info("init_task string pointer found at {:x}\n".format(init_ptr))

          # checkptr = self.r2.readptr(init_ptr+(self.ptrsize*2))
          # logging.info("Addr next pointer: 0x{:x}".format(checkptr))
          # if checkptr == second_entry:
              # logging.info("Success! found table pointer at 0x{:x}".format(init_ptr))
              # #break
          # else:
              # logging.warning("The check pointer failed to validate, maybe try the other symbol finding method. Continuing.")
              # string2=self.r2.readstr(checkptr)
              # string3=self.r2.readstr(checkptr+len(string2)+1)
              # logging.info("check pointer string: {}, {}".format(string2, string3))
              # # just keep going to the next phase 
              # #break
              # #found = self.r2.find(init_task_bytes, init_task+10 )
              # #return False

          # try to find as many symbol pointers as we can
          if (found != -1): #func_ptr_table == -1):
              (symstrings, patt, string_offsets) = self.strtab_pattern_fetch( init_task )
              num_of_strings = len(symstrings)
              logging.info("{} strings found in table".format(num_of_strings))

              if (num_of_strings < 64): # some arbitrary number
                  logging.debug("table was {}".format(symstrings))
                  # some string tables have gaps, so try to span those
                  endoff=string_offsets[-1]+len(symstrings[-1])+1
                  strend=init_task+endoff
                  strend=strend+self.ptrsize-(strend%self.ptrsize)
                  skipcount=0
                  while skipcount < 10:
                      (ss, patt2, stroff2)=self.strtab_pattern_fetch(strend) #self.read_ascii_strings( strend )
                      if len(ss) > 0:
                          if (skipcount > 0):
                            logging.info("skipped {} non-strings".format(skipcount))

                          skipcount=0
                          # adjust offsets to be relative to init_task
                          shift=strend-init_task
                         
                          logging.debug("strings at {:x} : {}".format(strend,ss))
                          endoff2=stroff2[-1]+len(ss[-1])+1
                          strend += endoff2
                          strend=strend+self.ptrsize-(strend%self.ptrsize)
                          stroff2=[ off+shift for off in stroff2 ]
                          string_offsets += stroff2
                          symstrings += ss
                          num_of_strings += len(ss)
                          logging.info("string count now {}".format(num_of_strings))
                      else:
                          strend += self.ptrsize
                          skipcount += 1
                  
                  #ptrs=self.r2.readptr(strend, 50 )
                  #logging.info("data from string end on: {}".format(str([hex(val) for val in ptrs])))4
                  
                  # if after all that we still don't have a good number of strings, try again
                  if num_of_strings < 64:
                    logging.info("Table too small, searching for another")
                    init_ptr = self.r2.rfind( init_task_packed, init_ptr-self.ptrsize )
                    if (init_ptr == -1):
                        logging.info("init_task string pointer not found - searching for another instance of the string\n")
                        found = self.r2.find(init_task_bytes, found+10)
                    else:
                        logging.info("Candidate found at {:x}".format(init_ptr))
                        continue
                  else:
                      break
              else:
                  break
                    
        if (found != -1):
            # we now have a list of strings and their offsets
            # in theory these are the symbols in the ksymtab
            # so now fetch the rest of the ptr table starting at the pointer to init_task
            # and check everything points into the table 
            ptr_tab = self.r2.readptr( init_ptr-self.ptrsize, num_of_strings*2)
            logging.info("read {0} pointers (requested {1})".format( len(ptr_tab), num_of_strings*2 ))
            # the table consists of symbol_ptr, string_ptr
            # so the string pointers are every other one

            #self.symbols = self.verify_symtab( ptr_tab, string_offsets, symstrings )
            self.symbols = self.verify_symtab_alt( ptr_tab, symstrings, string_offsets )
            #    logging.info("ksymtab found at 0x{:x}".format( init_ptr-self.ptrsize))


    def verify_symtab_alt( self, ptr_tab, symstrings, string_offsets ):
        verified=0
        syms={}
        # the table consists of symbol_ptr, string_ptr
        # so the string pointers are every other one
        string_ptrs = ptr_tab[1::2]
        fn_ptrs = ptr_tab[0::2]
        count=len(string_ptrs)

        # test dupe detection
        #syms[symstrings[0]] = ptr_tab[0]
        logging.info("Verifying symtab")
        idx=0
        missing={}
        for ptr in string_ptrs:
            target=self.r2.readstr( ptr )
            if (target in symstrings):
                if (not target in syms.keys()):
                    verified += 1
                    syms[target] = fn_ptrs[idx]
                else:
                    logging.info("duplicate sym pointer {:x} to {}, already found {:x}".format(ptr,target,syms[target]))
            else:
                if len(target) > 0:
                    logging.info("string {} not in ptr table".format(target))
                    # record address of each missing string
                    missing[target] = string_ptrs[0]+string_offsets[idx]
            idx += 1
                
        logging.info("verified count: "+str(verified)+"/"+str(count))

        if (verified == count) or (verified > 100):
            print("good enough!")
            for missing_str in missing.keys():
                strloc=missing[missing_str]
                miss_ptr=self.r2.findptr( strloc )
                if miss_ptr != -1:
                    symptr = self.r2.readptr( miss_ptr-self.ptrsize )
                    if self.is_kernel_pointer(symptr):
                        print("Found {} at {:x}".format(missing_str, symptr))
                        syms[missing_str] = symptr
                else:
                    print("Did not find pointer to {}".format(missing_str))
                    
            return syms
        return None

        
    def verify_symtab( self, ptr_tab, offsets, symstrings ):
        '''
        This verifies that the symtab is valid
        :pram ptr_tab:
        :pram offsets:
        :pram symstrings:
        :type ptr_tab:
        :type offsets:
        :type symstrings: list of strings
        :returns: a syms dictionary, or None if the symtab failed to validate.
        '''
        verified=1
        syms={}
        # the table consists of symbol_ptr, string_ptr
        # so the string pointers are every other one
        string_ptrs = ptr_tab[1::2]
        fn_ptrs = ptr_tab[0::2]
        count=len(string_ptrs)

        # we get the first one for free
        syms[symstrings[0]] = ptr_tab[0]

        ptroffs = [ string_ptrs[ii+1]-string_ptrs[0] for ii in range( 0, len(string_ptrs)-1 ) ]
        logging.debug("offsets: {0}...\nsymstrings: {1}...\nfn_ptr count: {2}\n".format( ptroffs[:10], len(symstrings),len(fn_ptrs) ))
        for checkoff in ptroffs:
            try:
                checkidx = offsets.index(checkoff)
            except ValueError:
                checkidx = -1
            if (checkidx == -1):
                logging.info("offset {0} (item no {1}) not in table".format(checkoff, verified))
                #phys=ptrvals[verified+1]-virtoff
                logging.info("pointer value: {0}".format( hex(string_ptrs[verified+1]) ))
                logging.info("  - maybe string: "+symstrings[verified+1]+" pointer value: "+hex(string_ptrs[verified+1]) )
                break
            else:
                verified += 1
                if (checkidx < len(fn_ptrs)):
                    syms[symstrings[checkidx]] = fn_ptrs[checkidx]
                else:
                    logging.info("pointer (offset {2}) indexed to {0}, past end of func ptrs {1} - string {3}".format(checkidx,len(fn_ptrs), checkoff, symstrings[checkidx]))
        print("verified count: "+str(verified)+"/"+str(count))
        if (verified == count) or (verified > 100):
            print("double bingo!!!")
            return syms
        return None

    def pointer_table_search( self, offset, maxsearch, symstrings, lengths, offsets, interval, ptr_size ):
        '''
        Searches for a series of pointer-length values
        where value[i+1] == value[i]+lengths[i]
        Assumes offset and pointers are aligned to ptr_size
        '''
        # read the data
        databytes = self.r2.read( offset, maxsearch, True )
        dataoff=0
        count=len(lengths)
        print("Searching for table pattern: "+str(lengths[:10])+" offsets: "+str(offsets[:10]))
        while (dataoff + (interval*count) + ptr_size < maxsearch):
            # unpack the series of values
            if (ptr_size == 8):
                ptrvals =  [ struct.unpack("<Q", databytes[ss:ss+8] )[0] for ss in range(dataoff, dataoff+(interval)*count, interval ) ]
            else:
                ptrvals =  [ struct.unpack("<L", databytes[ss:ss+4] )[0] for ss in range(dataoff, dataoff+(interval)*count, interval ) ]
            print("pointer values: " + str([ hex(ptr) for ptr in ptrvals[:32] ]))
            ptrdiffs = [ ptrvals[ii+1]-ptrvals[ii] for ii in range( 0, len(ptrvals)-1 ) ]
            print("diffs: "+str(ptrdiffs[:32]) )

            # check the first few
            if (ptrdiffs[0:4] == lengths[0:4]):
              print("Bingo!!")
              virtoff=ptrvals[0]-offset+dataoff
              # verify the whole table - ptrs are not necessarily in order
              verified=1
              ptroffs = [ ptrvals[ii+1]-ptrvals[0] for ii in range( 0, len(ptrvals)-1 ) ]
              for checkoff in ptroffs:
                 if (checkoff not in offsets):
                     print("offset {0} (item no {1}) not in table".format(checkoff, verified))
                     phys=ptrvals[verified+1]-virtoff
                     print("pointer value: {0}, phys: {1}".format( hex(ptrvals[verified+1]),hex(phys) ))
                     print("  - maybe string: "+symstrings[verified+1]+" pointer value: "+hex(ptrvals[verified+1])+" phys: "+hex(phys) )
                     break
                 else:
                     verified += 1
              print("verified count: "+str(verified)+" out of "+str(count))
              if (verified == count) or (verified > 100):
                  print("double bingo!!!")
              return offset+dataoff
            dataoff += ptr_size # assume aligned
        return None  

    def find_swapper( self ):
        swaploc = self.r2.find(b'swapper')
        while (swaploc != -1):
            # check this is either swapper/0\0\0\0\0\0\0
            # or swapper\0\0\0\0\0\0\0\0
            databytes=self.r2.read( swaploc, 15 )
            if (databytes == b'swapper\0\0\0\0\0\0\0\0') or (databytes == b'swapper/0\0\0\0\0\0\0'):
                logging.info("Swapper found at 0x{:x}".format(swaploc))
                return swaploc
            swaploc = self.r2.find(b'swapper', swaploc+8)
        # should do some more verification
        return swaploc

    def find_pid_offset( self, tskaddr, nextaddr, tasks_offset, comm_offset ):
        # pid field is 4 bytes
        for offset in range( tasks_offset+(self.ptrsize*2), comm_offset, 4 ):
            pid0 = self.r2.readuint( tskaddr+offset )
            # swapper pid is 0
            if (pid0 == 0):
                pid1 = self.r2.readuint( nextaddr+offset )
                # init pid is 1
                if (pid1 == 1):
                    # this is a possible offset for pid
                    # now need to check that all pids are different
                    tsk=nextaddr
                    pidlist=[]
                    while (tsk != tskaddr):
                        pidcheck=self.r2.readuint( tsk+offset )
                        if (pidcheck in pidlist):
                            break
                        pidlist.append(pidcheck)
                        nextTsk = self.r2.readptr( tsk+tasks_offset )
                        tsk=nextTsk-tasks_offset
                    if (tsk==tskaddr):
                        # values at this offset were all different
                        return offset
        return -1

    def find_parent_offset( self, tskaddr, nextaddr, task_struct ):
        # we should find the "parent" pointer somewhere between pid and comm
        # it's a pointer to a task_struct

        pid_offset = self.get_offset(task_struct, 'pid')
        comm_offset = self.get_offset(task_struct, 'comm')

        for offset in range( pid_offset, comm_offset, 4 ):
            ptr0 = self.r2.readptr( tskaddr+offset )
            # swapper is its own parent
            if (ptr0 == tskaddr):
                # check the same offset for pid 1 - parent should be swapper
                ptr1 = self.r2.readptr( nextaddr+offset )
                if (ptr1 == tskaddr):
                    # first one of these is real_parent
                    if 'real_parent' not in task_struct['fields']:
                        self.add_field( task_struct, 'real_parent', offset, 'pointer', None, 'struct', 'task_struct' )
                    else:
                        # second one is parent
                        self.add_field( task_struct, 'parent', offset, 'pointer', None, 'struct', 'task_struct' )
                        break
        if ('real_parent' in task_struct['fields'].keys()) and (not 'parent' in task_struct['fields'].keys()):
            # this means there was no real_parent field
            task_struct['fields']['parent'] = task_struct['fields'].pop('real_parent')

    #def check_listhead( self, addr ):
    #    # listhead is next and prev
    #    nextptr = self.r2.readptr( addr )
    #    nextprev = self.r2.readptr( nextptr+self.ptrsize )
    #    logging.debug("check_listhead, addr: {0:x}, next: {1:x}, nextprev: {2:x}".format( addr, nextptr, nextprev )) 
    #    if nextptr == nextprev:
    #        return True
    #    return False

    def find_mm_offset( self, tskaddr, initaddr, task_struct ):
        # in theory we could assume the mm field is the first pointer following "tasks"
        # however, there might be one or more structs before it (e.g. pushable_tasks)
        # that contain pointers
        # We assume that mm is immediately followed by active_mm and that they are the same
        # (at least for swapper)
        # testing
        ptr_offset = self.get_offset(task_struct,'tasks')+(2*self.ptrsize)
        ptrs = self.r2.readptr( tskaddr+ptr_offset, 16 )
        logging.info("after tasks: "+str([ hex(ptr) for ptr in ptrs ]) )
 
        ptrs = self.r2.readptr( initaddr+ptr_offset, 16 )
        logging.info("after init tasks: "+str([ hex(ptr) for ptr in ptrs ]) )

        mmoff=-1

        for ii in range( 0, len(ptrs)-2 ):
            # these two are potentially mm and active_mm
            if (ptrs[ii] == ptrs[ii+1]) and self.is_sensible_pointer(ptrs[ii]):
                # mm is not a listhead
                if not self.check_list_head( ptrs[ii] ):
                    mmoff = ptr_offset + (ii*self.ptrsize)
                    # also the mm field for swapper should be 0
                    swapper_mm = self.r2.readptr( tskaddr+mmoff )
                    if (swapper_mm == 0):
                        if self.is_kernel_pointer(ptrs[ii+2]):
                            # if there's a pointer after active_mm, it should be liux_fmt
                            # (this should only really apply to some 2.x kernels)
                            if not self.check_linux_binfmt_early(ptrs[ii+2]):
                                # not a binfmt, so probably not the offset we were looking for
                                continue
                        logging.info("setting mm offset in task_struct to {}".format(mmoff))
                        self.add_field( task_struct, 'mm', mmoff, 'pointer', None, 'struct', 'mm_struct' )
                        break

    def check_linux_binfmt_early( self, addr, ptrlist=[] ):
        '''
        Checks that there is something that looks a bit like an early linux_binfmt struct at addr
        This will have a next pointer followed by a module pointer
        '''
        dbg=self.r2.readptr( addr, 4 )
        logging.info("check linux_binfmt at {:x} ... {}".format(addr, str([hex(val) for val in dbg])))
        ptrs=self.r2.readptr( addr, 2 )
        valid=False
        if self.is_kernel_pointer(ptrs[0]):
            if not ptrs[0] in ptrlist:
                ptrlist.append(ptrs[0])
                valid=self.check_linux_binfmt_early(ptrs[0])
            else:
                # already checked
                valid=True
            
        if (ptrs[0] == 0) or valid:
            # second pointer should be a module, which should be an enum followed by a list_head
            modval=self.r2.readptr( ptrs[1] )
            logging.info("check_linux_binfmt modval is 0x{:x}".format(modval))
            if (ptrs[1] == 0) or ((not self.is_kernel_pointer(modval)) and self.check_list_head(ptrs[1]+self.ptrsize)):
                logging.info("check_linux_binfmt ok")
                return True
        logging.info("check_linux_binfmt not valid")
        return False
            
    def struct_fdtable( self ):
        ''' 
        Create a partial fdtable containing the common fields
        '''
        self.fdtable={}
        self.add_field( self.fdtable, 'max_fds', 0, 'base', 'unsigned int' )
        self.add_field( self.fdtable, 'fd', 8, 'pointer', None, 'pointer', None, 'struct', 'file' )
        self.add_field( self.fdtable, 'close_on_exec', 8+self.ptrsize, 'pointer', None, 'base', 'long unsigned int' )
        self.add_field( self.fdtable, 'open_fds', 8+(self.ptrsize*2), 'pointer', None, 'base', 'long unsigned int' )

    def check_struct_fdtable( self, addr ):
        max_fds = self.r2.readuint( addr )
        # apply some reasonable limits to the value
        # see include/linux/fdtable.h that max_fds must be at least
        # BITS_PER_LONG (so 32 or 64)
        logging.info("checking potential fdtable at: 0x{0:x}, max_fds={1}".format(addr,max_fds))

        if (max_fds >= self.bitness) and (max_fds <= 65536):
            # should be followed by struct file **fd
            fdoff = self.get_offset(self.fdtable,'fd')
            fdptr = self.r2.readptr( addr+fdoff )
            # XXX could this be null?
            if (self.is_kernel_pointer( fdptr )):
                # good enough for now - we could check there are count of them
                return True
        return False

    def check_files_struct( self, addr ):
        '''
        Checks if there is a likely files_struct at the supplied address
        Assumes the struct starts with a count followed by either the fdt pointer
        or resize fields then the fdt pointer
        '''
        count = self.r2.readuint( addr )
        # kernel initialises count to 1, so sanity check it
        if (count >= 1) and (count <= 65536):
            logging.info("check_files_struct: addr={0:x}, count=0x{1:x}".format(addr,count))
            # assume fdt is aligned to pointer boundary
            fdtoff = self.ptrsize
            val = self.r2.readptr( addr+fdtoff )
            if not self.is_kernel_pointer( val ):
                fdtoff += 8 + 2*self.ptrsize
                val = self.r2.readptr( addr+fdtoff )
                if not self.is_kernel_pointer( val ):
                    return False
            # we now have a valid kernel pointer at addr+fdtoff
            # so we should check it looks something like a struct fdtable
            if self.check_struct_fdtable( val ):
                self.files_struct = {}
                self.add_field( self.files_struct, 'count', 0, 'base','unsigned int' )
                self.add_field( self.files_struct, 'fdt', fdtoff, 'pointer', None, 'struct','fdtable' )
                return True
        return False

    def build_files_struct( self ):
        self.files_struct={}
        self.add_field( self.files_struct, 'count', 0, 'base','unsigned int' )
        self.add_field( self.files_struct, 'fdt', self.ptrsize, 'pointer', None, 'struct','fdtable' )
        return

    def check_old_fs( self, addr, fs_struct ):
        '''
        Check for an fs_struct of the form:
        struct fs_struct {
            atomic_t count;
            rwlock_t lock;
            int umask;
            struct dentry * root, * pwd, * altroot;
            struct vfsmount * rootmnt, * pwdmnt, * altrootmnt;
        };
        '''
        rootaddr = addr+self.get_offset(fs_struct,'root')
        #pwdaddr = fsptr+self.get_offset(fs_struct,'pwd')

        dentptrs=self.r2.readptr( rootaddr, 3 )
        vfsptrs=self.r2.readptr( rootaddr+3*self.ptrsize, 3 )
        logging.debug("at {:x}, dentry ptrs {}, vfsptrs {}".format(rootaddr,str([hex(val) for val in dentptrs]),str([hex(val) for val in vfsptrs])))
        if self.do_dentry( dentptrs[0] ) and self.do_dentry( dentptrs[1] ):
            # good
            logging.debug("------------->dentry found")
            if self.check_vfsmount( vfsptrs[0]):
                return True
            else:
                logging.debug("--->VFS cross-check failed")
        return False

    def find_fs_offset( self, tskaddr, task_struct, fs_struct ):
        '''
        find the offset of the fs member in the task struct
        we assume fs is after the comm field and that fs and files are consecutive
        '''
        startoff = self.get_offset(task_struct,'comm')+16
        endoff = startoff+512*self.ptrsize # assume it's within this range
        
        if 'rootmnt' in fs_struct['fields']:
            # older type
            for offset in range( startoff, endoff, self.ptrsize ):
                logging.debug("checking older fs at offset {}".format(offset))
                if self.check_old_fs(tskaddr+offset, fs_struct):
                    self.add_field( task_struct, 'fs', offset, 'pointer', None, 'struct', 'fs_struct' )
                    self.add_field( task_struct, 'files', offset+self.ptrsize, 'pointer', None, 'struct', 'files_struct' )
                    return offset
        else:
            # newer type, has path
            for offset in range( startoff, endoff, self.ptrsize ):
                # check for two consecutive pointers
                # first should be a pointer to fs_struct, second to struct_files
                fsptr = self.r2.readptr( tskaddr+offset )
                filesptr = self.r2.readptr( tskaddr+offset+self.ptrsize )
                logging.debug("find_fs_offset checking kernel pointers at addr {3:x}, off {2}, {0:x}, {1:x}".format(fsptr, filesptr,offset, tskaddr+offset))
                if not (self.is_sensible_pointer(fsptr) and self.is_sensible_pointer(filesptr)):
                    continue
                logging.debug("find_fs_offset Found 2 kernel pointers at offset {2} {0:x}, {1:x}".format(fsptr, filesptr, offset))
                rootoff = fsptr+self.get_offset(fs_struct,'root')
                pwdoff = fsptr+self.get_offset(fs_struct,'pwd')
                logging.debug("fs root offset: {0}, pwd offset: {1}".format(rootoff-fsptr,pwdoff-fsptr))
                # in this version of fs_struct, root is of type path
                # so is pwd after that (note: not pointers)
                # debug
                #ptrs = [ hex(ptr) for ptr in self.r2.readptr( fsptr-16, 32 ) ]
                #logging.info("fsptr dump at {0:x} {1}\n".format( fsptr-16, str(ptrs)))

                if not (self.check_path_struct(rootoff) and self.check_path_struct(pwdoff)):
                    continue
                # the files element should be of type files_struct
                #pwdptr = self.r2.readptr( pwdoff )
                # try checking the files struct also
                logging.info("find_fs_offset checking files ptr {:x}".format(filesptr))
                if self.check_files_struct( filesptr ):
                    self.add_field( task_struct, 'fs', offset, 'pointer', None, 'struct', 'fs_struct' )
                    self.add_field( task_struct, 'files', offset+self.ptrsize, 'pointer', None, 'struct', 'files_struct' )
                    return offset

        logging.error("Failed to find fs_offset!")
        #return offset
        return None

    def tasks( self, startaddr, task_struct ):
        tasks_offset = self.get_offset(task_struct,'tasks')
        startlist = startaddr+tasks_offset

        # yield the first in the list
        yield startaddr

        nextlist = self.r2.readptr( startlist )
        while (nextlist != startlist):
            yield nextlist-tasks_offset
            nextlist = self.r2.readptr( nextlist )

    def find_exit_state( self, tskaddr, initaddr, task_struct ):
        '''
        Find the offset of exit_state in the task struct
        This should be between active_mm and pid
        '''
        after_mm = self.get_offset(task_struct,'mm')+(2*self.ptrsize)
        pid_offset = self.get_offset(task_struct,'pid')
        #ptrs = [ self.r2.readuint( tskaddr+after_mm+ii ) for ii in range (0, pid_offset-after_mm, 4) ]
        #logging.info("After active_mm, before pid:\n{}".format(str([hex(ptr) for ptr in ptrs])))

        # we assume that there are 3 consecutive integers 
        # exit_state, exit_code_exit_signal
        # and that exit_signal is 0x11 for most processes
        for off in range (after_mm, pid_offset, 4):
            vals=[]
            # get a list of integers at offset into each task_struct
            for tsk in self.tasks( tskaddr, task_struct ):
                vals.append( self.r2.readuint( tsk+off ) )
            # now check if most at this offset are 0x11
            logging.debug("ints at offset {0}: {1}".format( off, [ hex(val) for val in vals ]))
            count11 = sum( [ 1 for val in vals if val == 0x11 ] )
            if (len(vals) > 5) and (count11 > len(vals)/2):
                # we've most likely found exit_signal
                self.add_field( task_struct, 'exit_state', off-8, 'base', 'int' )
                logging.info("exit_state offset {0}".format(off-8))
                break



            #val0 = self.r2.readuint( tskaddr+off )
            #val1 = self.r2.readuint( initaddr+off )
            #logging.info("{0} {1:x} {2:x}".format(off,val0,val1))


    def find_pgd_offset( self, tskaddr ):
        mm_offset = self.get_offset(self.task_struct,'mm')
        # for now, read a bunch of memory here
        mm = self.r2.readptr( tskaddr+mm_offset )

        tasks_off = self.get_offset(self.task_struct, 'tasks' )
        next_tsk = self.r2.readptr( tskaddr+tasks_off )-tasks_off
        while (next_tsk != tskaddr) and (mm == 0):
            mm = self.r2.readptr( next_tsk+mm_offset )
            logging.info("task at {:x}, mm={:x}".format(next_tsk,mm))
            next_tsk = self.r2.readptr( next_tsk+tasks_off )-tasks_off

        mmptrs = self.r2.readptr( mm, 32 )
        logging.info("Data at mm ({0:x}):\n{1}\n".format(mm, str([ hex(ptr) for ptr in mmptrs ] )))
        
        pgd_offset = -1

        # this is very flaky
        for ii in range(0, len(mmptrs)-1):
            if (self.is_sensible_pointer(mmptrs[ii])):
                if (ii < 2):
                    # first few things should be other pointers
                    # but maybe there is other junk at start
                    continue
                # kernel pointer - is there a sensible mm_count after it?
                # init should have some maps but not a vast number
                if (mmptrs[ii+2] > 2) and (mmptrs[ii+2] < 0xFF):
                    # secondary check on swapper
                    ptr_offset = ii*self.ptrsize

                    swap_mm = self.r2.readptr( self.swapaddr+mm_offset )
                    logging.info("swap_mm: {:x}".format(swap_mm))
                    swap_mm_count = self.r2.readptr( swap_mm+ptr_offset )
                    logging.debug("Swapper mm_count: {}".format(swap_mm_count))
                    if (swap_mm_count == self.all_ones()):
                        pgd_offset = ptr_offset
                        self.add_field( self.mm_struct, 'pgd', pgd_offset, 'pointer', None, 'base', 'long unsigned int') #'struct', 'unnamed_pgd_aaaa' )
                        break
                    #    #for jj in range(ii+1, len(mmptrs)):
                    #    #if self.is_kernel_pointer(mmptrs[jj]):
                    #    pgd_offset = jj*self.ptrsize
                    #    self.add_field( self.mm_struct, 'pgd', pgd_offset, 'pointer', None, 'struct', 'unnamed_pgd_aaaa' )
                    #    break

    def vma_heuristics( self, tskaddr ):
        ret=False
        # get the address of the mm struct
        mm_offset = self.get_offset(self.task_struct,'mm')
        mm = self.r2.readptr( tskaddr+mm_offset )
        # first element of mm_struct should be mmap, i.e. a list of VMAs
        mmap = self.r2.readptr( mm )
        # 2 main variants of VMA, one with vm_mm at start, one part way through
        # but we can find that easily anyway as it points back to mm
        vm_mm_off=-1
        for off in range( 0, 16*self.ptrsize, self.ptrsize ):
            vm_mm = self.r2.readptr( mmap+off )
            if (vm_mm == mm):
                vm_mm_off = off
                break
        if vm_mm_off == -1:
            logging.error("Unable to find offset of vm_mm in vma!!")
            return
        # now find the vm_next pointer
        # vm_start and vm_end precede it
        next_off=-1
        for off in range( 2*self.ptrsize, 16*self.ptrsize, self.ptrsize ):
            if off == vm_mm_off:
                continue
            next_ptr = self.r2.readptr( mmap+off )
            # verify with the vm_mm pointer
            next_mm = self.r2.readptr( next_ptr+vm_mm_off )
            if (next_mm == mm):
                next_off = off
                break
        if next_off == -1:
            logging.error("Unable to find offset of vm_next in vma!!")
            return ret
        # we assume vm_flags is 2 pointers further on
        flags_off = next_off + 2*self.ptrsize
        vm_start_off = next_off-2*self.ptrsize
        vm_end_off = next_off - self.ptrsize
        # check for optional prev pointer
        prev_off = -1
        ptr = self.r2.readptr( mmap+next_off+self.ptrsize )
        prev_mm = self.r2.readptr( ptr+vm_mm_off )
        if (prev_mm == mm):
            prev_off = next_off+self.ptrsize
            # bump flags down accordingly
            flags_off += self.ptrsize
        # just need vm_file now
        # we assume vm_file is somewhere after flags
        file_off=-1
        for off in range(flags_off+self.ptrsize, flags_off+32*self.ptrsize, self.ptrsize):
            ptr = self.r2.readptr( mmap+off )
            logging.debug("vma: checking for file at offset {0}, ptr {1:x}".format(off,ptr))
            if self.check_struct_file( ptr ):
                file_off = off
                break
        if file_off == -1:
            logging.warning("Unable to find offset of vm_file in vma!!")
            file_off = 0
        else:
            ret=True
        vma = {}
        self.add_field( vma, 'vm_mm', vm_mm_off, 'pointer', None, 'struct', 'mm_struct' )
        self.add_field( vma, 'vm_start', vm_start_off, 'base', 'long unsigned int' )
        self.add_field( vma, 'vm_end', vm_end_off, 'base', 'long unsigned int' )
        self.add_field( vma, 'vm_next', next_off, 'pointer', None, 'struct', 'vm_area_struct' )
        if prev_off != -1:
            self.add_field( vma, 'vm_prev', prev_off, 'pointer', None, 'struct', 'vm_area_struct' )
        self.add_field( vma, 'vm_flags', flags_off, 'base', 'long unsigned int' )
        self.add_field( vma, 'vm_file', file_off, 'pointer', None, 'struct', 'file' )
        self.vm_area_struct = vma
        return ret

    def check_struct_file( self, addr ):
        valid=False
        # check a struct file by assuming there is a dentry and vfsmount
        # 2 pointers into the struct. This covers at least 2.6-5.6
        vfs = self.r2.readptr( addr+self.ptrsize*2 )
        if self.check_vfsmount( vfs ):
            logging.info("check_struct_file: vfsmount ok")
            dent=self.r2.readptr( addr+self.ptrsize*3 )
            if 'dentry' in self.__dict__:
                dentOk=self.check_dentry( dent )
            else:
                dentOk=self.do_dentry( dent )
            if dentOk:
                valid=True
        return valid

    def add_field( self, struc, name, offset, kind, kind_name, subkind=None, subname=None, subsubkind=None, subsubname=None ):
        if not 'fields' in struc:
            struc['fields'] = {}

        if not 'kind' in struc:
            struc['kind'] = "struct"

        if (subkind == None):
            struc['fields'][name] = { 'offset' : offset, "type": { "kind": kind, "name": kind_name }  }
        else:
            if subsubname == None:
                if subname == None:
                    struc['fields'][name] = { 'offset' : offset, "type": { "kind": kind, "subtype": { "kind" : subkind } }  }
                else:
                    struc['fields'][name] = { 'offset' : offset, "type": { "kind": kind, "subtype": { "kind" : subkind, "name" : subname } }  }
            else:
              struc['fields'][name] = { 'offset' : offset, "type": { "kind": kind, "subtype": { "kind" : subkind, "subtype" : { "kind" : subsubkind, "name" : subsubname  } } }  }
        if not 'size' in struc:
            # make up a size
            struc['size'] = offset+self.ptrsize
        elif offset+self.ptrsize > struc['size']:
            struc['size'] = offset+self.ptrsize

    def get_offset( self, struc, field ):
        return struc['fields'][field]['offset']

    def task_heuristics( self, tskaddr, comm_offset ):
        # read the swapper task struct including the comm field
        #swap_task = self.r2.read( tskaddr, comm_offset+15+1024 )

        #init_task_offset = symbols['symbols']['init_task']['address']
        #comm_offset = symbols['user_types']['task_struct']['fields']['comm']['offset']
        #pid_offset = symbols['user_types']['task_struct']['fields']['pid']['offset']
        #tasks_offset = symbols['user_types']['task_struct']['fields']['tasks']['offset']
        #mm_offset = symbols['user_types']['task_struct']['fields']['mm']['offset']
        #pgd_offset = symbols['user_types']['mm_struct']['fields']['pgd']['offset']
        #parent_offset = symbols['user_types']['task_struct']['fields']['parent']['offset']
        #exit_state_offset = symbols['user_types']['task_struct']['fields']['exit_state']['offset']
 
        initaddr = -1
        tasks_offset = -1
        task_struct = { 'fields' : { 'comm' : {  "type": { "count": 16, "kind": "array", "subtype": {"kind": "base","name": "char"} }, 'offset' : comm_offset } } }

        # first try to find the "tasks" field
        # this will be a list_head, which consists of two pointers next and prev
        # we make the assumption that the struct will be aligned ot a pointer boundary 
        # within the task_struct
        ptrcount = int(comm_offset / self.ptrsize)
        #ptrcount -= (ptrcount % 2)  # make it an even number

        ptrs = self.r2.readptr( tskaddr, ptrcount )
        # other list_heads could include children, sibling and maybe others

        #for (nextptr, prevptr) in [ (ptrs[ii], ptrs[ii+1]) for ii in range(0, ptrcount-1) ]:
        for ii in range(0, ptrcount-1):
            nextptr = ptrs[ii]
            prevptr = ptrs[ii+1]
            if (nextptr == 0) or (nextptr == prevptr):
                continue
            # ignore pointer to self
            ptrloc = tskaddr + (ii*self.ptrsize)
            if (nextptr == ptrloc):
                continue            
            next_strc = self.r2.readptr( nextptr, 2 )
            if (len(next_strc) == 2):
                # check if prev points back to where we started
                ptroff = (ii*self.ptrsize)
                ptrloc = tskaddr + ptroff
                if (next_strc[1] == ptrloc):
                    # sanity check - "next" from swapper should point to init or systemd
                    next_comm = self.r2.readstr( nextptr-ptroff+comm_offset )
                    logging.debug("Found poss list_head at 0x{0:x}, pointing to {1}".format( ptrloc-tskaddr, next_comm ))
                    if (next_comm == "init") or (next_comm == "systemd"):
                        # that should do, tasks is typically the first list_head
                        tasks_offset = ptroff
                        initaddr = nextptr-ptroff
                        break
        if (tasks_offset != -1):
            self.add_field( task_struct, 'tasks', tasks_offset, 'struct', 'list_head' )
 
            # now find the pid offset - typically this is between tasks and comm
            pid_offset = self.find_pid_offset( tskaddr, initaddr, tasks_offset, comm_offset )
            logging.info("pid offset found at {}".format( pid_offset ))
        
            if (pid_offset != -1):
                self.add_field( task_struct, 'pid', pid_offset, 'base', 'int' )

            self.find_parent_offset( tskaddr, initaddr, task_struct )

            # now we need to find mm_offset
            self.find_mm_offset( tskaddr, initaddr, task_struct )

            # we also need to find exit_state
            self.find_exit_state( tskaddr, initaddr, task_struct )

            # we also need some file-related stuff
            self.task_struct = task_struct

            # that's the task_struct dealt with
            #if 'parent' in task_struct['fields']:
            #        logging.info("found parent: {0}".format(str(task_struct)) )

        return initaddr

    def is_kernel_pointer( self, value ):
        if (self.ptrsize == 8):
            return (value > 0xffffffff80000000) and (value < 0xffffffffffffffff)
        else:
            return (value > 0xc0000000) and (value < 0xffffffff)

    def all_ones( self ):
        return (1 << (self.ptrsize*8))-1

    def is_sensible_pointer( self, value ):
        # checks if pointer derefs to something other than -1
        if self.r2.readptr( value ) != self.all_ones():
           return True
        return False

    # returns true if two ranges do not overlap
    def range_distinct( self, s1, e1, s2, e2 ):
        return (e1 < s2) or (e2 < s1)
        
    def mm_heuristics( self, tskaddr ):
        self.mm_struct = { 'fields' : { } }
        self.find_pgd_offset( tskaddr )

        mm_offset = self.get_offset(self.task_struct,'mm')
        mm = self.r2.readptr( tskaddr+mm_offset )

        # now look for mm_list list_head
        pgd_off = self.get_offset(self.mm_struct, 'pgd')
        mmlist_off=-1
        tasks_off = self.get_offset(self.task_struct, 'tasks' )
        next_tsk = self.r2.readptr( tskaddr+tasks_off )-tasks_off
        while (next_tsk != tskaddr) and (mmlist_off == -1):
            mm = self.r2.readptr( next_tsk+mm_offset )
            if mm != 0:
              for off in range(pgd_off+self.ptrsize, pgd_off+1024, self.ptrsize ):
                if self.check_list_head( mm+off, True ):
                    mmlist_off=off
                    logging.info("mmlist_off: {}".format(mmlist_off))
                    break
            next_tsk = self.r2.readptr( next_tsk+tasks_off )-tasks_off

        if mmlist_off == -1:
            mmlist_off = 0
        # look for this:
        # unsigned long start_code, end_code, start_data, end_data;
	    # unsigned long start_brk, brk, start_stack;
	    # unsigned long arg_start, arg_end, env_start, env_end;
        code_off=-1
        for off in range(mmlist_off, mmlist_off+1024, self.ptrsize):
            vals = self.r2.readptr( mm+off, 11 )
            if (vals[0] < vals[1]) and (vals[2] < vals[3]) and (vals[4] < vals[5]) and (vals[7] < vals[8]) and (vals[9] < vals[10]):
                   # check they don't overlap
                   if self.range_distinct( vals[0],vals[1],vals[2],vals[3] ) and self.range_distinct( vals[7],vals[8],vals[9],vals[10] ):
                          self.add_field( self.mm_struct, 'start_brk', off+4*self.ptrsize, 'base','long unsigned int' )
                          self.add_field( self.mm_struct, 'brk', off+5*self.ptrsize, 'base','long unsigned int' )
                          self.add_field( self.mm_struct, 'start_stack', off+6*self.ptrsize, 'base','long unsigned int' )
                          code_off=off
                          break
        # find the owner pointer - it's a task list
        tskoff = self.get_offset( self.task_struct, 'tasks' )
        parentoff = self.get_offset( self.task_struct, 'parent' )
        start = mmlist_off+code_off+10*self.ptrsize
        #for off in range( start, start+1024, self.ptrsize ):
        #    ptr = self.r2.readptr( mm+off )
        #    tskl = self.r2.readptr( ptr+tskoff )
        #    prnt = self.r2.readptr( ptr+parentoff )
        #    if self.check_list_head( ptr ) and self.check_parent_tree( ptr, tskoff, 64 ):
        #        # ptr is the owner pointer

        logging.info("mm_struct: {0}".format(str(self.mm_struct)))

    def fs_struct1(self):
        # fs_struct for versions up to 2.6.26
        self.fs_struct={}
        self.add_field( self.fs_struct, 'count', 0, 'struct', 'unnamed_48d5743551250810' )
        self.add_field( self.fs_struct, 'lock', 4, 'struct', 'unnamed_332c0f84bf92fd41' )
        self.add_field( self.fs_struct, 'umask', 8, 'base', 'int' )
        self.add_field( self.fs_struct, 'root', 12, 'pointer', None, 'struct', 'dentry' )
        off = 12 + self.ptrsize
        self.add_field( self.fs_struct, 'pwd', off, 'pointer', None, 'struct', 'dentry' )
        off += self.ptrsize
        self.add_field( self.fs_struct, 'altroot', off, 'pointer', None, 'struct', 'dentry' )
        off += self.ptrsize
        self.add_field( self.fs_struct, 'rootmnt', off, 'pointer', None, 'struct', 'vfsmount' )
        off += self.ptrsize
        self.add_field( self.fs_struct, 'rootmnt', off, 'pointer', None, 'struct', 'vfsmount' )
        off += self.ptrsize
        self.add_field( self.fs_struct, 'pwdmnt', off, 'pointer', None, 'struct', 'vfsmount' )
        off += self.ptrsize
        self.add_field( self.fs_struct, 'altrootmnt', off, 'pointer', None, 'struct', 'vfsmount' )
        off += self.ptrsize
        self.fs_struct['size'] = off

    def fs_struct2(self, has_seqField=True):
        self.fs_struct={}
        logging.info("fs_struct2 hasSeqField: {0}".format(str(has_seqField)))
        self.add_field(self.fs_struct, 'users', 0, 'base', 'int' )
        self.add_field(self.fs_struct, 'lock', 4, 'base', 'unsigned int') #'struct', 'spinlock' )
        if (has_seqField):
            self.add_field(self.fs_struct, 'seq', 8, 'base', 'unsigned int') #'struct', 'seqcount' )
            off=12
        else:
            off=8
        self.add_field(self.fs_struct, 'umask', off, 'base', 'int' )
        off += 4
        self.add_field(self.fs_struct, 'in_exec', off, 'base', 'int' )
        off += 4
        # align to ptrsize
        if (off % self.ptrsize != 0):
          off += self.ptrsize - (off%self.ptrsize)
        self.add_field(self.fs_struct, 'root', off, 'struct', 'path' )
        off += self.path_struct['size']
        self.add_field(self.fs_struct, 'pwd', off, 'struct', 'path' )
        off += self.path_struct['size']
        self.fs_struct['size'] = off

    def check_path_struct( self, addr ):
        '''
        Checks for a possible path struct at addr
        '''
        vfsptr = self.r2.readptr( addr )
        dentryptr = self.r2.readptr( addr+self.ptrsize )
        logging.debug("check_path_struct at {2:x}: values {0:x} {1:x}".format(vfsptr,dentryptr, addr))
        # XXX debug
        #ptrs = [ hex(ptr) for ptr in self.r2.readptr( addr, 16 ) ]
        #logging.info("dump at {0:x} {1}\n".format( addr, str(ptrs)))

        valid=False
        # struct path is *vfsmount, *dentry 
        if self.check_vfsmount( vfsptr ) and self.is_sensible_pointer( dentryptr ):
            if not 'dentry' in self.__dict__:
                # try to create a dentry based on what's there
                logging.info("Setting up dentry struct")
                valid = self.do_dentry( dentryptr )
            else:
                # verify based on our idea of a dentry
                valid = self.check_dentry( dentryptr )
            logging.info("Valid path_struct: {}".format(valid))
        return valid

    def check_dentry( self, addr ):
        valid = False
        parent_off = self.get_offset( self.dentry, 'd_parent')
        if self.check_parent_tree( addr, parent_off, 64 ):
            # check for sensible name
            name_off = self.get_offset( self.dentry, 'd_name' )
            nameptr = self.r2.readptr(addr+name_off+self.get_offset( self.qstr,'name'))
            namestr = self.r2.readstr( nameptr )
            if len(namestr) > 0:
                logging.info( "dentry name:{}".format(namestr))
                inode_off = self.get_offset( self.dentry,'d_inode')
                inodeptr = self.r2.readptr( addr+inode_off )
                if self.check_inode( inodeptr ):     
                    valid=True
                    # dentry_operations often fails to verify
                    # TODO: investigate this
                    #op_off = self.get_offset( self.dentry, 'd_op')
                    #opptr = self.r2.readptr(addr+op_off)
                    #valid = self.check_dentry_operations( opptr )
        return valid

    def do_dentry( self, addr ):
        ''' 
        Work out the offsets for a dentry, assuming one is at addr
        We only really care about d_parent, d_name, d_op and d_inode 
        '''
        # start by finding the parent field - should be near the start
        # (probably at offset 24)
        parent_off=-1
        for off in range( 0, 64, self.ptrsize ):
            if self.check_parent_tree( addr, off, 64 ):
                parent_off=off
                break
        if parent_off == -1:
            logging.debug("dentry d_parent not found")
            return False
        # name field should follow - this is a struct qstr
        name_off = parent_off + self.ptrsize
        nameptr = self.r2.readptr( addr+name_off+self.get_offset( self.qstr,'name'))
        namestr = self.r2.readstr( nameptr )
        if len(namestr) == 0:
            return False
        logging.info( "dentry name:{}".format(namestr))

        # now find d_op, which is somewhere after name
        op_off=-1
        start=name_off+self.qstr['size']
        for off in range(start, start+256, self.ptrsize ):
            # d_op is a pointer to dentry_operations
            logging.debug("checking for d_op at offset {0}, addr {1:x}".format(off,addr+off))
            op_ptr = self.r2.readptr( addr+off )
            if self.check_dentry_operations( op_ptr ):
                op_off = off
                break
            elif self.check_super_block( op_ptr ):
                # d_op sometimes fails to verify (null), but d_op is followed by d_sb
                op_off = off-self.ptrsize
                logging.info("d_op found through d_sb")
                ptrcount=6
                if self.version_compare( 2,6,22 ) < 0:
                    ptrcount=7 # could be more
                if self.version_compare(3,2,0) <= 0:
                    ptrcount=8
                self.build_dentry_operations(ptrcount)
                # debug
                op_ptrdbg=self.r2.readptr(addr+op_off)
                op_ptrs=self.r2.readptr(op_ptrdbg, 12 )
                logging.info("dentry d_op pointers at {:x} - {}".format(op_ptrdbg, str([hex(val) for val in op_ptrs])))
                break
        if op_off == -1:
            logging.error("dentry d_op not found")
            return False
        logging.info("d_op offset found at: {}".format(op_off))
        
        # now we just need to find the d_inode field
        # that should be an inode pointer before d_op
        inode_off=-1
        for off in range( 0, op_off, self.ptrsize ):
            if (off==parent_off):
                continue
            elif (off >= name_off) and (off < name_off+self.qstr['size']):
                # name is qstr (not a pointer)
                continue
            logging.debug("do_dentry: checking for inode at offset {}".format(off))
            in_ptr = self.r2.readptr( addr+off )
            if self.check_inode( in_ptr ):
                inode_off = off
                break
        if inode_off == -1:
            logging.error("dentry d_inode not found")
            return False
        else:
            logging.info("Setting dentry d_inode offset to {}".format(inode_off))
        # at this point we have the 4 offsets we wanted
        # so enter them into the structure
        self.dentry={}
        self.add_field( self.dentry, 'd_parent', parent_off, 'pointer',None,'struct','dentry')
        self.add_field( self.dentry, 'd_name', name_off, 'struct','qstr')
        self.add_field( self.dentry, 'd_inode', inode_off, 'pointer',None,'struct','inode')
        self.add_field( self.dentry, 'd_op', op_off, 'pointer',None,'struct','dentry_operations')
        logging.info("dentry initialised: {}".format(str(self.dentry)))
        return True


    def check_inode( self, addr ):
        '''
        Check for the presence of an inode at addr
        '''
        valid=False
        if self.version_compare(2,6,38)<=0:
            # from 2.6.38 on the structure changes
            # first field is mode
            mode=self.r2.readushort( addr )
            debugptrs=self.r2.readptr( addr, 16 )
            logging.debug("inode mode: 0x{:x}, debug: {}".format(mode,str([hex(ptr) for ptr in debugptrs])))
            if True: #mode <= 0xFFF:
                # seems like a sensible mode
                # we now look for a super_block pointer
                super_off=-1
                for off in range( 8, 64, self.ptrsize ):
                    ptr = self.r2.readptr( addr+off )
                    logging.debug("check_inode testing ptr {0:x} at offset {1} for superblock".format(ptr,off))
                    if self.check_super_block( ptr ):
                        super_off = off
                        break
                if super_off != -1:
                    logging.info("inode superblock at offset {}".format(super_off))
                    ino_off=-1
                    if self.version_compare(3,1,0) <= 0:
                        # 3.1.0 onwards has:
                        # i_mapping pointer, optional security pointer then ino
                        off=super_off+self.ptrsize
                        map_ptr = self.r2.readptr( addr+off )
                        logging.debug("check_inode: map_ptr {0:x} at off {1}".format(map_ptr,off))
                        if self.is_sensible_pointer( map_ptr ) or (map_ptr == 0):
                            off += self.ptrsize
                            opt_ptr = self.r2.readptr( addr+off )
                            logging.debug("check_inode: opt_ptr {:x}".format(opt_ptr))
                            # let's assume ino is != 0 but security could be null?
                            if (opt_ptr == 0) or (self.is_sensible_pointer(opt_ptr)):
                                # assume we have CONFIG_SECURITY in that case
                                off += self.ptrsize
                            ino_off = off
                            logging.info("check_inode: setting ino_off to {}".format(ino_off))
                            valid=True
                    else:
                        # between 2.6.38 and <3.1.0 
                        # this is a small range so ignore for now
                        logging.error("kernel version unsupported for inode verification!")
                    # we should now have some pointers, then i_ino
                    if valid and not 'inode' in self.__dict__:
                        self.inode={}
                        self.add_field( self.inode, 'i_sb', super_off, 'pointer', None, 'struct', 'super_block' )
                        self.add_field( self.inode, 'i_ino', ino_off, 'base', 'long unsigned int' )
                    
        else:
            # pre-2.6.38, the structure starts with struct hlist_node
            # then 3 list_heads
            off=2*self.ptrsize
            ino={}
            if self.check_list_head( addr+off ):
                self.add_field( ino, 'i_list', off, 'struct', 'list_head' )
                off += self.list_head['size']
                if self.check_list_head( addr+off ):
                    self.add_field( ino, 'i_sb_list', off, 'struct', 'list_head' )
                    off += self.list_head['size']
                    if self.check_list_head( addr+off ):
                        valid=True
                        self.add_field( ino, 'i_dentry', off, 'struct', 'list_head' )
                        off += self.list_head['size']
                        if not 'inode' in self.__dict__:
                            self.add_field( ino, 'i_ino', off, 'base', 'long unsigned int' )
                            self.inode=ino

        return valid

    def build_inode(self):
        '''
        Create the inode structure based on kernel version
        '''
        if self.version_compare(2,6,38)<=0:
            # from 2.6.38 on the structure changes
            # first field is mode
            off=16+3*self.ptrsize
            self.inode={}
            self.add_field( self.inode, 'i_sb', super_off, 'pointer', None, 'struct', 'super_block' )
            off += self.ptrsize

            # 3.1.0 onwards has:
            # i_mapping pointer, optional security pointer then ino
            # we assume optional security pointer is present
            mapoff=superoff+self.ptrsize
            if self.version_compare(3,1,0) <= 0:
                off += self.ptrsize*2
                self.add_field( self.inode, 'i_ino', ino_off, 'base', 'long unsigned int' )


            else:
                # between 2.6.38 and <3.1.0 
                # this is a small range so ignore for now
                logging.error("kernel version unsupported for inode build!")                    
        else:
            # pre-2.6.38, the structure starts with struct hlist_node
            # then 3 list_heads
            off=2*self.ptrsize
            ino={}
            self.add_field( ino, 'i_list', off, 'struct', 'list_head' )
            off += self.list_head['size']
            self.add_field( ino, 'i_sb_list', off, 'struct', 'list_head' )
            off += self.list_head['size']
            self.add_field( ino, 'i_dentry', off, 'struct', 'list_head' )
            off += self.list_head['size']
            self.add_field( ino, 'i_ino', off, 'base', 'long unsigned int' )
            self.inode=ino

        
    def check_dentry_operations( self, addr ):
        # we want at least 6 function pointers
        ptrcount=6
        if self.version_compare( 2,6,22 ) < 0:
            ptrcount=7 # could be more
        if self.version_compare(3,2,0) <= 0:
            ptrcount=8

        ptrs = self.r2.readptr( addr, ptrcount )
          
        for ptr in ptrs:
            if not self.is_sensible_pointer( ptr ):
                logging.debug("d_op pointer {:x} bad".format(ptr))
                return False
            logging.debug("d_op pointer {:x} ok".format(ptr))
            
            # XXX also check for function pointer
        # all pointers validated
        if not 'dentry_operations' in self.__dict__:
            self.build_dentry_operations(ptrcount)

        return True

    def build_dentry_operations( self, ptrcount ):
        # make a dummy dentry_operations
        # but don't include d_dname for now
        ops={}
        off=0
        for opval in range( 0, ptrcount ):
            self.add_field( ops, 'd_op_'+str(opval), off, 'pointer', None, 'function' )
            off += self.ptrsize
        self.dentry_operations = ops


    def check_parent_tree( self, struct_addr, offset, max_depth ):
        depth=1
        nextaddr = struct_addr
        valid=False
        
        while (depth < max_depth):
            parent_ptr = self.r2.readptr( nextaddr+offset )
            logging.debug("check_parent_tree: struct {0:x} parent {1:x} offset {2}".format( nextaddr, parent_ptr,offset ) )
            if parent_ptr == self.all_ones():
                # invalid
                break
            if (parent_ptr == nextaddr): # or (parent_ptr == 0):
                # we've reached the top of the tree
                logging.debug("parent ok")
                valid=True
                break
            depth += 1
            nextaddr = parent_ptr
        return valid

    def check_vfsmount( self, addr ):
        ret = False
        # before 3.3, vfsmount starts with a list_head
        if (self.version_compare( 3, 3, 0 ) > 0):
            # list_head
            ptrval = addr #self.r2.readptr( addr )
            logging.debug("check_vfsmount: checking list_head at {:x}".format(ptrval))
            # XXX debug
            #ptrs = [ hex(ptr) for ptr in self.r2.readptr( addr, 16 ) ]
            #logging.info("dump at {0:x} {1}\n".format( addr, str(ptrs)))
            if self.check_list_head( ptrval ):
              logging.debug("check_vfsmount: list_head ok")
              if self.check_parent_tree( ptrval, 2*self.ptrsize, 64 ):
                # assume that's good enough for now
                ret=True
                if not 'vfsmount' in self.__dict__:
                    self.vfsmount={}
                    self.add_field(self.vfsmount,'mnt_hash',
                                   0,'struct','list_head')
                    off = 2*self.ptrsize
                    self.add_field(self.vfsmount,'mnt_parent',
                                   off,'pointer',None,'struct','vfsmount')
                    off += self.ptrsize
                    self.add_field(self.vfsmount,'mnt_mountpoint',
                                   off,'pointer',None,'struct','dentry')
                    off += self.ptrsize
                    self.add_field(self.vfsmount,'mnt_root',
                                   off,'pointer',None,'struct','dentry')
                    off += self.ptrsize
                    self.add_field(self.vfsmount,'mnt_sb',
                                   off,'pointer',None,'struct','super_block')
                    # that's probably all we need
        else:
            # dentry, super_block. super_block is easier to check
            ptrval = addr+self.ptrsize #self.r2.readptr( addr+self.ptrsize )
            if (self.check_super_block( ptrval )):
                if not 'vfsmount' in self.__dict__:
                    # this is a much simpler structure
                    self.vfsmount={}
                    self.add_field(self.vfsmount,'mnt_root',
                                   0,'pointer',None,'struct','dentry')
                    self.add_field(self.vfsmount,'mnt_sb',
                                   self.ptrsize,'pointer',None,'struct','super_block')
                    self.add_field(self.vfsmount,'mnt_flags',
                                   self.ptrsize*2,'base','int')
                ret=True
        return ret

    def build_vfsmount( self ):
        '''
        Create a vfsmount structure based on kernel version
        '''
        if (self.version_compare( 3, 3, 0 ) > 0):
            self.vfsmount={}
            self.add_field(self.vfsmount,'mnt_hash',
                            0,'struct','list_head')
            off = 2*self.ptrsize
            self.add_field(self.vfsmount,'mnt_parent',
                            off,'pointer',None,'struct','vfsmount')
            off += self.ptrsize
            self.add_field(self.vfsmount,'mnt_mountpoint',
                            off,'pointer',None,'struct','dentry')
            off += self.ptrsize
            self.add_field(self.vfsmount,'mnt_root',
                            off,'pointer',None,'struct','dentry')
            off += self.ptrsize
            self.add_field(self.vfsmount,'mnt_sb',
                                   off,'pointer',None,'struct','super_block')
        else:
            # dentry, super_block
            # this is a much simpler structure
            self.vfsmount={}
            self.add_field(self.vfsmount,'mnt_root',
                            0,'pointer',None,'struct','dentry')
            self.add_field(self.vfsmount,'mnt_sb',
                            self.ptrsize,'pointer',None,'struct','super_block')
            self.add_field(self.vfsmount,'mnt_flags',
                            self.ptrsize*2,'base','int')

    def check_fsname( self, fsname ):
        logging.info("checking fsname {}".format(fsname))
        valid=False
        if len(fsname) >= 3:
            for ch in fsname:
                if (not ch.isdigit()) or not ((ord(ch) >= 97) and (ord(ch) <= 122)):
                    valid=False
                    logging.info("ch {} not valid for fsname".format(ch))
                    break
                valid=True
        return valid

    def check_super_block( self, addr ):
        # just a really basic check for now
        s_list = self.r2.readptr( addr )
        valid = self.check_list_head( s_list )
        # if valid:
            # valid=False
            # # try to find the s_type member
            # for off in range(self.ptrsize*2, self.ptrsize*10, self.ptrsize):
                # stype_ptr = self.r2.readptr( addr+off )
                # # s_type has a string the start (the fs name)
                # nameptr = self.r2.readptr( stype_ptr )
                # fsname = self.r2.readstr( nameptr)
                # if self.check_fsname(fsname):
                    # logging.info("check_super_block: fsname {}".format(fsname))
                    # valid=True
                    # break
        return valid

    def check_list_head( self, addr, allowSelfPtr=False):
        ''' check that there is a list_head at addr '''
        ptrs = self.r2.readptr( addr, 2 )
        nextptr = ptrs[0]
        prevptr = ptrs[1]

        logging.debug("check_list_head: next: {0:x} prev: {1:x}".format(nextptr, prevptr))
        if (nextptr == 0): # or (nextptr == prevptr):
            return False

        # ignore pointer to self?
        if (nextptr == addr) and (not allowSelfPtr):
            return False
            
        next_prev = self.r2.readptr( nextptr+self.ptrsize )
        logging.debug("check_list_head: nextprev: {0:x}".format(next_prev))

        # check if prev points back to where we started
        if (next_prev == addr):
            logging.debug("looks like a valid list_head")
            return True
        return False

    def build_dentry(self):
        # XXX this is wrong, dentry varies across versions
        self.dentry={}
        self.add_field( self.dentry, 'd_flags', 0, 'base', 'unsigned int' )
        self.add_field( self.dentry, 'd_seq', 4, 'base', 'unsigned int' )
        self.add_field( self.dentry, 'd_hash', 8, 'struct', 'hlist_bl_node' )
        off=8+self.ptrsize*2
        self.add_field( self.dentry, 'd_parent', off, 'pointer', None, 'struct', 'dentry' )
        off += self.ptrsize
        self.add_field( self.dentry, 'd_name', off, 'struct', 'qstr' )
        off += self.qstr['size']
        self.add_field( self.dentry, 'd_inode', off, 'pointer', None, 'struct', 'inode' )
        off += self.ptrsize
        self.add_field( self.dentry, 'd_iname', off, 'array', None, 'base', 'unsigned char' )

    def file_structs( self ):
        ''' 
        add the following file-related structures:
        path, fs_struct, vfsmount, dentry, file
        '''
        # we assume the path struct is the same for all versions '''
        self.path_struct = { 'fields' : {} }
        self.add_field( self.path_struct, 'mnt', 0, 'pointer', None, 'struct', 'vfsmount' )
        self.add_field( self.path_struct, 'dentry', self.ptrsize, 'pointer', None, 'struct', 'dentry' )
        self.path_struct['size'] = 2*self.ptrsize

        self.file_struct={}
        self.add_field( self.file_struct, 'f_path', 2*self.ptrsize, 'struct', 'path' )
        
        # we also need to add entries for those two structs - vfsmount and dentry

        # dentry is fairly standard to start with and that covers the offsets we need

        # ignore anything before 2.6 for now
        if (self.version_compare( 2,6,26) >= 0):
            # 2.6.26 and earlier have different structure
            logging.info("using early type fs_struct")
            self.fs_struct1()
        elif self.version_compare( 2, 6, 38 ) >= 0:
            # only 2.6.38 onwards has seq field
            logging.info("setting up fs_struct without seq field")
            self.fs_struct2(False)
        else:
            logging.info("setting up fs_struct with seq field")
            self.fs_struct2(True)
    
        self.struct_fdtable()
        logging.info("Looking for offset of fs in task_struct")
        
        foundFs=False
        
        # only try the first few processes to look for fs offset
        # we should really be ok to get it from swapper
        count=0
        for tsk in self.tasks(self.symbols['init_task'], self.task_struct):
            # XXX debug
            cmd=self.r2.readstr(tsk+self.get_offset(self.task_struct,'comm'))
            logging.info("using process {} to look for fs offset".format(cmd))
            if self.find_fs_offset( tsk, self.task_struct, self.fs_struct ) != None:
                logging.info("fs offset found")
                foundFs=True
                break
            #elif ('users' in self.fs_struct['fields']) and (not 'seq' in self.fs_struct['fields']):
            #    # in case some vendors added the seq field earlier
            #    logging.info("Trying with newer fs_struct variant")
            #    self.fs_struct2(True)
            #    if self.find_fs_offset( tsk, self.task_struct, self.fs_struct ) != None:
            #        foundFs=True
            #        logging.info("fs offset found")
            #        break
            #    else:
            #        self.fs_struct2(False)

            # debug experiment
            #logging.info("debug: setting fs_struct back to type 1")
            #self.fs_struct1()
            #pdb.set_trace()
            #if self.find_fs_offset( tsk, self.task_struct, self.fs_struct ) != None:
            #    foundFs=True
            #    logging.info("fs offset found")
            #else:
            #    self.fs_struct2()
            count += 1
            if count > 2:
                break
        return foundFs
           

    def version_compare( self, maj, minor, sub ):
      '''
      Returns -1/0/1 if offered version is less/same/more than actual
      '''
      logging.debug("Comparing {0},{1},{2} against actual {3}, {4}, {5}".format(maj,minor,sub,self.vers_major,self.vers_minor,self.vers_sub))
      if (maj < self.vers_major):
          logging.debug("major less")
          return -1
      if (maj > self.vers_major):
          return 1
      # major is the same, so check minor
      if (minor < self.vers_minor):
          logging.debug("minor less")
          return -1
      if (minor > self.vers_minor):
          return 1
      # minor is the same, check subversion
      if (sub < self.vers_sub):
          logging.debug("sub {0} less than self sub {1}".format(sub,self.vers_sub))
          return -1
      if (sub > self.vers_sub):
          return 1
      # same!
      return 0


    def linux_version( self, banner ):
        # extract the version major, minor, subversion from the banner
        # banner starts "Linux version " followed by major.minor.sub
        vers_str = banner.split()[2]
        splitver = vers_str.split('.')[:3]
        if len(splitver) < 3:
            splitver.append('0')
        (maj,minor,rest) = splitver
        # the "rest" part can have dahses or dots, e.g. 0-11-amd64
        # we'll just take the first digits
        sub=''
        for ch in rest:
            if ch.isdigit():
                sub += ch
            else:
                break
        self.vers_major = int(maj)
        self.vers_minor = int(minor)
        self.vers_sub = int(sub)

    def do_simple_types(self):
        '''
        Initialise some basic types that are reasonably fixed
        '''
        # assume list_head is same everywhere
        self.list_head={}
        self.add_field( self.list_head, 'next', 0, 'pointer', None, 'struct', 'list_head' )
        self.add_field( self.list_head, 'prev', self.ptrsize, 'pointer', None, 'struct', 'list_head' )
        self.list_head['size'] = 2*self.ptrsize

        self.qstr={}
        # it's not structly this in later kernels but works
        self.add_field( self.qstr, 'hash', 0, 'base', 'unsigned int' )
        self.add_field( self.qstr, 'len', 4, 'base', 'unsigned int' )
        self.add_field( self.qstr, 'name', 8, 'pointer', None, 'base', 'unsigned char')
        self.qstr['size'] = 8+self.ptrsize

        # we only really need the s_dev field from super_block
        self.super_block={}
        self.add_field( self.super_block, 's_list', 0, 'struct', 'list_head' )
        self.add_field( self.super_block, 's_dev', self.list_head['size'], 'base', 'unsigned int' )
        
    def module_struct(self):
        self.module = {}
        self.add_field( self.module, 'name', 3*self.ptrsize, 'array',None,'base','char')
        
    def set_task_size( self, tsk ):
        # find the largest offset and add a bit
        # exact size probably not crucial?
        end=max( [ tsk['fields'][fld]['offset'] for fld in tsk['fields'] ] )
        tsk['size'] = end + 10*self.ptrsize
    
    def find_volatility_symbols( self ):
        # find linux banner
        banner, bannaddr = self.find_linux_banner()
        logging.info("Found linux banner: "+banner )
        self.banner = banner
        self.bannaddr = bannaddr

        self.linux_version( banner )

        # find symtab
        self.find_symtab()

        self.do_simple_types()

        # find swapper and work out task_struct offsets
        self.swapaddr = self.find_swapper()
        logging.info("init_task at: 0x{:x}".format(self.symbols['init_task']))

        # the swapper string should be after the init_task symbol
        # (that symbol points to beginning of task_struct for swapper)
        comm_offset = self.swapaddr - self.symbols['init_task']

        logging.info("comm_offset: {}".format(comm_offset))

        initaddr = self.task_heuristics( self.symbols['init_task'], comm_offset )
        
        self.mm_heuristics( initaddr )

        if self.file_structs():
            # we need the address of the swapper files structure
            init_files_addr = self.swapaddr + self.get_offset( self.task_struct, 'files')
            init_files = self.r2.readptr( init_files_addr )
            self.symbols['init_files'] = init_files

        self.set_task_size( self.task_struct )

        for tsk in self.tasks( initaddr, self.task_struct ):
            if self.vma_heuristics( tsk ):
                break
            # one process should be enough
            break

        self.module_struct()
        
        return

if __name__ == "__main__":
    banner = """
.▄▄ ·  ▄· ▄▌• ▌ ▄ ·. ▄▄▄▄·       ▄▄▌  
▐█ ▀. ▐█▪██▌·██ ▐███▪▐█ ▀█▪▪     ██•  
▄▀▀▀█▄▐█▌▐█▪▐█ ▌▐▌▐█·▐█▀▀█▄ ▄█▀▄ ██▪  
▐█▄▪▐█ ▐█▀·.██ ██▌▐█▌██▄▪▐█▐█▌.▐▌▐█▌▐▌
 ▀▀▀▀   ▀ • ▀▀  █▪▀▀▀·▀▀▀▀  ▀█▄▀▪.▀▀▀ 
 ▄ .▄▄• ▄▌ ▐ ▄ ▄▄▄▄▄▄▄▄ .▄▄▄          
██▪▐██▪██▌•█▌▐█•██  ▀▄.▀·▀▄ █·        
██▀▐██▌▐█▌▐█▐▐▌ ▐█.▪▐▀▀▪▄▐▀▀▄         
██▌▐▀▐█▄█▌██▐█▌ ▐█▌·▐█▄▄▌▐█•█▌        
▀▀▀ · ▀▀▀ ▀▀ █▪ ▀▀▀  ▀▀▀ .▀  ▀         

    SymbolHunter
    """
    parser = argparse.ArgumentParser(description='VMI Tool for extracting symbol information from Linux')
    parser.add_argument("-d", "--debug", help="Increase output verbosity", action="store_true")
    parser.add_argument("--host", default="127.0.0.1", help="GDB Host")
    parser.add_argument("-p", "--port", default="1234", help="Port GDB is listening on.")
    parser.add_argument("-b", "--bitness", default=64, help="Operating system bitness (32 or 64)", choices=["32","64"] )
    parser.add_argument("-e", "--enumfile", help="File containing enum data to add to the output", default=None)
    parser.add_argument("-o", "--output", help="Output filename for the symbols.", default="symbols.json")
    parser.add_argument("-f", "--force", help="Overwrite output filename if it already exists.", action="store_true")
    parser.add_argument("-g", "--guess", default=False, help="Fill in guesses for missing structures.", action="store_true")
    parser.add_argument("-s", "--symsonly", default=False, help="Save ksymtab symbols only (csv, no structure info)", action="store_true")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)
    logging.info(banner)

    # does the output file already exist?
    if os.path.isfile(args.output) and not args.force:
        logging.error("{} already exists! run with -f to overwrite.".format(args.output))
        sys.exit(1)
    if (args.bitness==64):
        ptrsize=8
    else:
        ptrsize=4

    info = InfoHunter(args.host, args.port, ptrsize)
    info.find_volatility_symbols()

    if args.symsonly:
        info.save_symbols_to_file(args.output)
    else:
        info.save_json_symbols(args.output, args.enumfile, args.guess)
