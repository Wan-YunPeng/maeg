import os
import time
import angr
import signal
import socket
import claripy
import simuvex
import tempfile
import subprocess
import shellphish_qemu
from .tracerpov import TracerPoV
from .cachemanager import LocalCacheManager
from .simprocedures import receive
from .simprocedures import FixedOutTransmit, FixedInReceive, FixedRandom
from simuvex import s_options as so

import logging

l = logging.getLogger("tracer.Tracer")
l.setLevel('DEBUG')

class Tracer(object):
    '''
    Trace an angr path with a concrete input
    '''

    def __init__(self, binary, input=None,  simprocedures=None,
                 preconstrain_input=True,preconstrain_flag=True, resiliency=True, 
                 add_options=None, remove_options=None, trim_history=True):
        """
        :param binary: path to the binary to be traced
        :param input: concrete input string to feed to binary
        :param povfile: CGC PoV describing the input to trace
        :param hooks: A dictionary of hooks to add
        :param simprocedures: dictionary of replacement simprocedures
        :param seed: optional seed used for randomness, will be passed to QEMU
        :param preconstrain_input: should the path be preconstrained to the
            provided input
        :param preconstrain_flag: should the path have the cgc flag page
            preconstrained
        :param resiliency: should we continue to step forward even if qemu and
            angr disagree?
        :param chroot: trace the program as though it were executing in a
            chroot
        :param add_options: add options to the state which used to do tracing
        :param remove_options: remove options from the state which is used to
            do tracing
        :param trim_history: Trim the history of a path.
        """

        self.binary = binary
        self.input = input
        self.preconstrain_input = preconstrain_input
        self.preconstrain_flag = preconstrain_flag
        self.simprocedures = {} if simprocedures is None else simprocedures
        self.resiliency = resiliency
        self.add_options = set() if add_options is None else add_options
        self.trim_history = trim_history
        self.constrained_addrs = []

        cm = LocalCacheManager() if GlobalCacheManager is None else GlobalCacheManager
        # cache managers need the tracer to be set for them
        self._cache_manager = cm
        self._cache_manager.set_tracer(self)

        # set by a cache manager
        self._loaded_from_cache = False

        if remove_options is None:
            self.remove_options = set()
        else:
            self.remove_options = remove_options

        # internal project object, useful for obtaining certain kinds of info
        self._p = angr.Project(self.binary)
        # try to find the install base
        self.os = self._p.loader.main_bin.os
        self.base = shellphish_qemu.qemu_base()
        self.tracer_qemu = "shellphish-qemu-linux-%s" % self._p.arch.qemu_name
        qemu_platform = self._p.arch.qemu_name

        self.tracer_qemu_path = shellphish_qemu.qemu_path(qemu_platform)
        self.qemu_path = {}
        self.trace = self.dynamic_trace()



    def dynamic_trace(self, stdout_file=None):
        '''
        accumulate a basic block trace using qemu
        '''
        args = [self.binary,self.input]
        p = subprocess.Popen(args)
        ret = p.wait()
        # the return value of program is less than zero, there is a error happen
        # set the crash_mode
        l.debug("crash return code %d", ret)
        if ret < 0:
            # 11 or 4: signal.SIGSEGV:invalid memory access, such as segment fault; signal.SIGILL: invalid program image, such as invalid instruction
            if abs(ret) == signal.SIGSEGV or abs(ret) == signal.SIGILL:   
                l.info("input caused a crash (signal %d)during dynamic tracing", abs(ret))
                l.info("entering crash mode")
                self.crash_mode = True
            else:
                l.info("input did not cause a crash by qemu, and the signal is %d", abs(ret))
        # use qemu to trace the basic
        # temp file

        lname = tempfile.mktemp(dir="/dev/shm/", prefix="tracer-log-")
        args = [self.tracer_qemu_path]

        args += ["-d", "exec", "-D", lname, self.binary]

        with open('/dev/null', 'wb') as devnull:
            stdout_f = devnull
            if stdout_file is not None:
                stdout_f = open(stdout_file, 'wb')

            # we assume qemu with always exit and won't block
            if self.pov_file is None:
                l.info("tracing as raw input")
                p = subprocess.Popen(
                        args,
                        stdin=subprocess.PIPE,
                        stdout=stdout_f,
                        stderr=devnull)
                _, _ = p.communicate(self.input)
            else:
                l.info("tracing as pov file")
                in_s, out_s = socket.socketpair()
                p = subprocess.Popen(
                        args,
                        stdin=in_s,
                        stdout=stdout_f,
                        stderr=devnull)

                for write in self.pov_file.writes:
                    out_s.send(write)
                    time.sleep(.01)

            p.wait()
            # # did a crash occur?
            # if ret < 0:
            #     if abs(ret) == signal.SIGSEGV or abs(ret) == signal.SIGILL:
            #         l.info("input caused a crash (signal %d)\
            #                 during dynamic tracing", abs(ret))
            #         l.info("entering crash mode")
            #         self.crash_mode = True

            if stdout_file is not None:
                stdout_f.close()

        with open(lname, 'rb') as f:
            trace = f.read()

        addrs = [int(v.split('[')[1].split(']')[0], 16)
                 for v in trace.split('\n')
                 if v.startswith('Trace')]
        i = 1
        for addr in addrs:
            l.debug('%d block at %#x',i,addr)
            self.qemu_path[i] = addr
            i += 1
        # grab the faulting address
        if self.crash_mode:
            self.crash_addr = int(
                    trace.split('\n')[-2].split('[')[1].split(']')[0],
                    16)

        os.remove(lname)

        return addrs

    def run(self, constrained_addrs=None):
        '''
        run a trace to completion

        :param constrained_addrs: addresses which have had constraints applied
            to them and should not be removed
        :return: a deadended path of a complete symbolic run of the program
                 with self.input
        '''

        # keep calling next_branch until it quits
        branches = None
        while (branches is None or len(branches.active)) and self.bb_cnt < len(self.trace):
            branches = self.next_branch()

            # if we spot a crashed path in crash mode return the goods
            if self.crash_mode and 'crashed' in branches.stashes:
                last_block = self.trace[self.bb_cnt - 1]
                l.info("crash occured in basic block %x", last_block)

                # time to recover the crashing state

                # before we step through and collect the actions we have to set
                # up a special case for address concretization in the case of a
                # controlled read or write vulnerability

                if constrained_addrs is None:
                    self.constrained_addrs = []
                else:
                    self.constrained_addrs = constrained_addrs

                bp1 = self.previous.state.inspect.b(
                    'address_concretization',
                    simuvex.BP_BEFORE,
                    action=self._dont_add_constraints)

                bp2 = self.previous.state.inspect.b(
                    'address_concretization',
                    simuvex.BP_AFTER,
                    action=self._grab_concretization_results)

                # step to the end of the crashing basic block,
                # to capture its actions
                self.previous.step()

                # Add the constraints from concretized addrs back
                self.previous._run = None
                for var, concrete_vals in self._address_concretization:
                    if len(concrete_vals) > 0:
                        l.debug("constraining addr to be %#x", concrete_vals[0])
                        self.previous.state.add_constraints(var == concrete_vals[0])

                # then we step again up to the crashing instruction
                p_block = self._p.factory.block(self.previous.addr,
                        backup_state=self.previous.state)
                inst_cnt = len(p_block.instruction_addrs)
                insts = 0 if inst_cnt == 0 else inst_cnt - 1
                succs = self.previous.step(num_inst=insts)
                if len(succs) > 0:
                    if len(succs) > 1:
                        succs = [s for s in succs if s.state.se.satisfiable()]
                    self.previous = succs[0]

                # remove the preconstraints
                l.debug("removing preconstraints")
                self.remove_preconstraints(self.previous)
                self.previous._run = None

                l.debug("reconstraining... ")
                self.reconstrain(self.previous)

                l.debug("final step...")
                self.previous.step()

                # now remove our breakpoints since other people might not want them
                self.previous.state.inspect.remove_breakpoint("address_concretization", bp1)
                self.previous.state.inspect.remove_breakpoint("address_concretization", bp2)
                # successors are state
                successors = self.previous.next_run.successors
                successors += self.previous.next_run.unconstrained_successors
                state = successors[0]

                l.debug("tracing done!")
                return (self.previous, state)

        # this is a concrete trace, there should only be ONE path
        all_paths = branches.active + branches.deadended
        if len(all_paths) != 1:
            raise TracerMisfollowError("program did not behave correctly, \
                    expected only one path")

        # the caller is responsible for removing preconstraints
        return all_paths[0], None

    def next_branch(self):
        """
        windup the tracer to the next branch

        :return: a path_group describing the possible paths at the next branch
                 branches which weren't taken by the dynamic trace are placed
                 into the 'missed' stash and any preconstraints are removed
                 from 'missed' branches.
        """
        # step the continuous blocks(reach max size)
        while len(self.path_group.active) == 1:
            current = self.path_group.active[0]
            l.debug('deal with the branch %#x',current.addr)

            try:
                if current.state.scratch.executed_block_count > 1:
                    # executed unicorn fix bb_cnt
                    self.bb_cnt += current.state.scratch.executed_block_count - 1 - current.state.scratch.executed_syscall_count
            except AttributeError:
                pass

            if not self.no_follow:

                # expected behavor, the dynamic trace and symbolic trace hit
                # the same basic block
                if self.bb_cnt >= len(self.trace):
                    l.debug('reach the last block')
                    return self.path_group

                if current.addr == self.trace[self.bb_cnt]:
                    l.debug('enter the new block')
                    self.bb_cnt += 1

                # angr steps through the same basic block twice when a syscall occurs
                elif current.addr == self.previous_addr or self._p.is_hooked(self.previous_addr) and \
                        self._p.hooked_by(self.previous_addr).IS_SYSCALL:
                    l.debug('steps through the same basic block twice when a syscall occurs, do nothing')
                    pass
                elif current.jumpkind.startswith("Ijk_Sys"):
                    l.debug('syscall, bb_cnt += 1')
                    self.bb_cnt += 1

                # handle library calls and simprocedures
                elif self._p.is_hooked(current.addr) \
                        or not self._address_in_binary(current.addr):
                    # are we going to be jumping through the PLT stub?
                    # if so we need to take special care
                    l.debug('handle library calls and simprocedures')
                    r_plt = self._p.loader.main_bin.reverse_plt
                    if current.addr not in self._resolved \
                            and self.previous.addr in r_plt:
                        self.bb_cnt += 2
                        self._resolved.add(current.addr)

                # handle hooked functions
                # we use current._project since it seems to be different than self._p
                elif current._project.is_hooked(self.previous_addr) and self.previous_addr in self._hooks:
                    l.debug('handle hooked functions')
                    l.debug("ending hook for %s", current._project.hooked_by(self.previous_addr))
                    l.debug("previous addr %#x", self.previous_addr)
                    l.debug("bb_cnt %d", self.bb_cnt)
                    # we need step to the return
                    current_addr = current.addr
                    while current_addr != self.trace[self.bb_cnt] and self.bb_cnt < len(self.trace):
                        self.bb_cnt += 1
                    # step 1 more for the normal step that would happen
                    self.bb_cnt += 1
                    l.debug("bb_cnt after the correction %d", self.bb_cnt)
                    if self.bb_cnt >= len(self.trace):
                        return self.path_group

                else:
                    l.error("the dynamic trace and the symbolic trace disagreed")

                    l.error("[%s] dynamic [0x%x], symbolic [0x%x]",
                            self.binary,
                            self.trace[self.bb_cnt],
                            current.addr)

                    l.error("inputs was %r", self.input)
                    if self.resiliency:
                        l.error("TracerMisfollowError encountered")
                        l.warning("entering no follow mode")
                        self.no_follow = True
                    else:
                        raise TracerMisfollowError

            # shouldn't need to copy
            self.previous = current
            # TODO this shouldn't be needed, fish fix the bug plesae
            self.previous_addr = current.addr

            # Basic block's max size in angr is greater than the one in Qemu We follow the one in Qemu
            if self.bb_cnt >= len(self.trace):
                bbl_max_bytes = 800
            else:
                y2 = self.trace[self.bb_cnt]
                y1 = self.trace[self.bb_cnt - 1]
                bbl_max_bytes = y2 - y1
                if bbl_max_bytes <= 0:
                    bbl_max_bytes = 800

            # detect back loops
            # this might still break for huge basic blocks with back loops
            # but it seems unlikely
            bl = self._p.factory.block(self.trace[self.bb_cnt-1],
                    backup_state=current.state)
            back_targets = set(bl.vex.constant_jump_targets) & set(bl.instruction_addrs)
            if self.bb_cnt < len(self.trace) and self.trace[self.bb_cnt] in back_targets:
                target_to_jumpkind = bl.vex.constant_jump_targets_and_jumpkinds
                if target_to_jumpkind[self.trace[self.bb_cnt]] == "Ijk_Boring":
                    bbl_max_bytes = 800

            # if we're not in crash mode we don't care about the history
            if self.trim_history and not self.crash_mode:
                current.trim_history()

            self.prev_path_group = self.path_group
            l.debug('path_group step max_size : %d',bbl_max_bytes)
            self.path_group = self.path_group.step(max_size=bbl_max_bytes)
            l.debug('now, it is %d block', self.bb_cnt)
            # if our input was preconstrained we have to keep on the lookout
            # for unsat paths
            if self.preconstrain_input:
                self.path_group = self.path_group.stash(from_stash='unsat',
                                                        to_stash='active')

            self.path_group = self.path_group.drop(stash='unsat')

            # check to see if we reached a deadend
            if self.bb_cnt >= len(self.trace):
                l.debug('check to see if we reached a deadend')
                tpg = self.path_group.step()
                # if we're in crash mode let's populate the crashed stash
                if self.crash_mode:
                    tpg = tpg.stash(from_stash='active', to_stash='crashed')
                    return tpg
                # if we're in normal follow mode, just step the path to
                # the deadend
                else:
                    if len(tpg.active) == 0:
                        self.path_group = tpg
                        return self.path_group

        # if we stepped to a point where there are no active paths,
        # return the path_group
        if len(self.path_group.active) == 0:
            # possibly we want to have different behaviour if we're in
            # crash mode
            l.debug('we have no active path at %d block', self.bb_cnt)
            return self.path_group

        # if we have to ditch the trace we use satisfiability
        # or if a split occurs in a library routine
        a_paths = self.path_group.active

        if self.no_follow or all(map(
                lambda p: not self._address_in_binary(p.addr), a_paths
                )):
            self.path_group = self.path_group.prune(to_stash='missed')
        else:
            l.debug("bb %d / %d", self.bb_cnt, len(self.trace))
            self.path_group = self.path_group.stash_not_addr(
                                           self.trace[self.bb_cnt],
                                           to_stash='missed')
        if len(self.path_group.active) > 1: # rarely we get two active paths
            self.path_group = self.path_group.prune(to_stash='missed')

        if len(self.path_group.active) > 1: # might still be two active
            self.path_group = self.path_group.stash(
                    to_stash='missed',
                    filter_func=lambda x: x.jumpkind == "Ijk_EmWarn"
            )

        # make sure we only have one or zero active paths at this point
        assert len(self.path_group.active) < 2

        l.debug("taking the branch at %#x", self.path_group.active[0].addr)

        rpg = self.path_group

        # something weird... maybe we hit a rep instruction?
        # qemu and vex have slightly different behaviors...
        if not self.path_group.active[0].state.se.satisfiable():
            l.warning("detected small discrepency between qemu and angr, "
                    "attempting to fix known cases")

            # did our missed branch try to go back to a rep?
            target = self.path_group.missed[0].addr
            if self._p.arch.name == 'X86' or self._p.arch.name == 'AMD64':

                # does it looks like a rep?
                if self._p.factory.block(target).bytes.startswith("\xf3"):
                    l.info("rep discrepency detected, repairing...")
                    # swap the stashes
                    s = self.path_group.move('missed', 'chosen')
                    s = s.move('active', 'missed')
                    s = s.move('chosen', 'active')
                    self.path_group = s

        self.path_group = self.path_group.drop(stash='missed')

        return rpg



