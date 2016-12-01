# -*- coding: utf-8 -*-
import commands
import logging
from pwn import *
import random

l = logging.getLogger("maeg.analyzer")
l.setLevel('INFO')

class Analyzer(object):
    LEAK_SYMBOLS = ['puts', 'printf']
    MIN_BUF_SIZE = 20

    def __init__(self, binary):
        self.binary = binary
        self.path = None
        self.result = None
        self.paths = []
        self.results = []

    def analyze(self, path):
    	self.path = path
    	self.results = self._new_result()
    	self._analyze()

        self.paths.append(self.path)
        self.results.append(self.result)    	


    def _analyze(self):
        # successors = self.path.next_run.successors
        # successors += self.path.next_run.unconstrained_successors
        # state = successors[0]
    	state = self.path.state
    	self._binary_info()
    	self.results['arch'] = state.arch.name
    	self.results['ip_symbolic'] = self._fully_symbolic(state,state.ip)

    	l.debug('Checking ip %s... symbolic: %s' % (str(state.ip), self.results['ip_symbolic']))

    	if self.results['ip_symbolic']:
    		self._ip_symbolic_info()

    def _ip_symbolic_info(self):
        state = self.path.state
    	self.result['ip_vars'] = list(state.ip.variables)
    	self.result['padding'] = self._get_padding()
    	self.result['bufs'] = self._get_bufs()
    	for addr, length in self.result.items():
    		l.debug('Finding %d buffers at %s.' % (length,addr))
    		l.info('Finding %d buffers at %s.' % (length,addr))


    # find buffer to store the shellcode 
   	def _get_bufs(self):
   		state = self.path.state

   		stdin_file = state.posix.get_file(0)

        sym_addrs = []
        for var in stdin_file.variables():
            sym_addrs.extend(state.memory.addrs_for_name(var))
        sym_addrs = sorted(sym_addrs)
        bufs = []
        for addr in sym_addrs:
            addr, length = self._check_continuity(addr, sym_addrs)
            if length > Analyzer.MIN_BUF_SIZE:
            	bufs.append({'addr': addr, 'length': length})
        return bufs


    def _check_continuity(self, address, all_address):
        i = 0
        while True:
            if not address + i in all_address:
                return address, i
            i += 1
            
    def _get_padding(self):
        state = self.path.state
                            
        if state.ip.op == 'Extract':
            return state.ip.args[1] / 8
        else:
            l.warning('ip: %s..., ip.op != "extract"' % str(state.ip))
            padding = set()
            try:
                for _ in xrange(5):
                    test_value = random.getrandbits(state.arch.bits)
                    tmp = self.path.copy()
        			# random generate value of state.arch.bits
                    tmp.state.add_constraints(tmp.state.ip == test_value)
                    inp = tmp.state.posix.dumps(0)
                    if state.arch.bits == 32:
                        padding.add(inp.find(p32(test_value)))
                    else:
                        padding.add(inp.find(p64(test_value)))
                    if len(padding) != 1:
                        l.warning('Found multiple paddings: %s' % padding)
            except:
                l.warning('Can not find padding.')
                padding.add(-1)
            l.info('Guess padding: %s' % padding)
            return padding.pop()



    def _fully_symbolic(self, state, variable):
        for i in range(state.arch.bits):
            if not state.se.symbolic(variable[i]):
                return False
        return True

    def _binary_info(self):
    	"""
        pwntools source:
            https://github.com/Gallopsled/pwntools/blob/master/pwnlib/elf/__init__.py#L652

        RELRO:
            - 'Full'
            - 'Partial'
            - None
        Stack Canary:
            - True
            - False
        NX:
            - True
            - False
        PIE:
            - True
            - False
        """
        elf = ELF(self.binary)
        self.result['elf'] = {
            'RELRO': elf.relro,
            'Canary': elf.canary,
            'NX': elf.nx,
            'PIE': elf.pie}

        ldd_output = commands.getoutput('ldd %s' % self.binary).split('\n')
        lib = filter(lambda lib: 'libc.so.6' in lib, ldd_output)[0]
        self.result['elf']['libc'] = re.findall('=> (.*) \(', lib)[0]

        self.result['elf']['leak_symbol'] = []
        for symbol in Analyzer.LEAK_SYMBOLS:
        	# detect if there are some leakable functions, such as printf, puts....
            if symbol in elf.symbols:
                self.result['elf']['leak_symbol'].append(symbol)


    def _new_result(self):
		# ip:instruction pointer expression
        return {
            'arch': '',
            'ip_symbolic': False,
            'ip_vars': [],
            'padding': -1,
            'bufs': [],
            'elf': {},
        }
