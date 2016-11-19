# -*- encoding: utf-8 -*-
import logging

l = logging.getLogger("maeg.Crash")

import os
import angr
import angrop
import random
import tracer
import hashlib
import operator
from .trace_additions import ChallRespInfo, ZenPlugin
from maeg.exploit import CannotExploit, CannotExplore, ExploitFactory, CGCExploitFactory
from maeg.vulnerability import Vulnerability
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
        	# run the tracer, grabbing the crash state
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
        flag_writes = [m for m in memory_writes if any(v.startswith("cgc-flag") for v in self.state.memory.load(m, 1).variables)] # cgc-flag control
        l.debug("done filtering writes")

        self.symbolic_mem = self._segment(user_writes)
        self.flag_mem = self._segment(flag_writes)

        # crash type
        self.crash_types = []
        # action (in case of a bad write or read) which caused the crash
        self.violating_action = None

        l.debug("traiging crash")
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
        symbolic_actions = [ ]
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
                    l.info("detected write-what-where vulnerability")
                    self.crash_types.append(Vulnerability.WRITE_WHAT_WHERE)
                else:
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


    def exploitable(self):
    	'''
        determine if the crash is exploitable
        :return: True if the crash's type is generally considered exploitable, False otherwise
        '''
        exploitables = [Vulnerability.IP_OVERWRITE, Vulnerability.PARTIAL_IP_OVERWRITE, Vulnerability.BP_OVERWRITE,
                Vulnerability.PARTIAL_BP_OVERWRITE, Vulnerability.WRITE_WHAT_WHERE, Vulnerability.WRITE_X_WHERE]

        return self.one_of(exploitables)

    def one_of(self, crash_types):
        '''
        Test if a self's crash has one of the vulnerabilities described in crash_types
        '''

        if not isinstance(crash_types, (list, tuple)):
            crash_types = [crash_types]

        return bool(len(set(self.crash_types).intersection(set(crash_types))))

    @staticmethod
    def _segment(memory_writes):
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

