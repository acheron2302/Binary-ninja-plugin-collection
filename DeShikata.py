from unicorn import *
from keystone import *
from capstone import *
from unicorn.x86_const import *
from binaryninja import *

def decrypt(bv, _address, _key, _len):
	xor_key = Transform['XOR']
	address = _address
	key = _key
	for i in range(_len):
		enc_str = bv.read(address, 4)
		decrypted_str = xor_key.decode(enc_str, {'key': key.to_bytes(4, 'little')})
		bv.write(address, decrypted_str)
		key += int.from_bytes(bv.read(address, 4), 'little')
		key &= 0xffffffff
		address += 4

def _parse_xor_token(_token):
	offset = _token[6].value
	eip = _token[4].text
	key = _token[-1].text
	return key, eip, offset

def str_to_unicorn_reg(reg_str):
	reg = None

	if reg_str == 'eax':
		reg =  UC_X86_REG_EAX
	if reg_str == 'ebx':
		reg =  UC_X86_REG_EBX
	if reg_str == 'ecx':
		reg =  UC_X86_REG_ECX
	if reg_str == 'edx':
		reg =  UC_X86_REG_EDX
	if reg_str == 'esi':
		reg =  UC_X86_REG_ESI
	if reg_str == 'edi':
		reg =  UC_X86_REG_EDI
	if reg_str == 'ebp':
		reg =  UC_X86_REG_EBP
	if reg_str == 'esp':
		reg = UC_X86_REG_ESP

	return reg



class DeobfuscateShikataGaNai:
	def __init__(self, bv, addr):
		self.bv = bv
		self.emu = Uc(UC_ARCH_X86, UC_MODE_32)
		self.begin_address = addr
		self.eip_reg = None
		self.key_reg = None
		self.offset = 0
		# intialise component for emulate
		emulate_bytes, counter_addr = self.get_code_to_emulate(bv, addr)
		self.opcodes = emulate_bytes

		self.len = 0
		self.eip = 0
		self.key = 0

		self.xor_address = counter_addr
		

	def get_code_to_emulate(self, bv, addr):
		emulate_byte = [] # variable to store the byte to run the emulation
		counter_addr = addr # this variable will store the address to count
		token_gen = bv.disassembly_tokens(addr)

		for token in token_gen:
			# Now we want to find the token in the form ['xor', ' ', 'dword', ...]
			# We first check if token contain xor
			if token[0][0].text != 'xor':
				temp_store = bv.read(counter_addr, token[1])
				emulate_byte += temp_store
				counter_addr += token[1]
				continue

			# Now we check if the len of token is 10
			# Note: have it smaller than 10 also work because i don't know if the number is out of range or not
			if len(token[0]) < 10:
				temp_store = bv.read(counter_addr, token[1])
				emulate_byte += temp_store
				counter_addr += token[1]
				continue

			# Now we have found the xor that we need, parse it and return 
			# the key, 
			# the offset
			# and the address of the last FPU instructions
			key, eip, offset = _parse_xor_token(token[0])
			self.key_reg, self.eip_reg , self.offset = key, eip, offset
			break

		return emulate_byte, counter_addr

	def _check_block_addr_for_fnstenv(self):
		# check the first 15 instructions after the begin_address
		# The right way to do this is to check every instruction in the basic block against the list at: https://docs.oracle.com/cd/E18752_01/html/817-5477/eoizy.html
		# but i am too lazy and this work everytime
		tokens = self.bv.disassembly_tokens(self.begin_address)
		counter = 0
		for token in tokens:
			if token[0][0].text == 'fnstenv':
				return True
			if counter > 15:
				return False
			counter += 1
		return False


	def _emulate(self):
		'''
		The initialise emulation is taken from https://github.com/tkmru/nao/blob/778d7c9eef929589a4a43b74ec6dcee249d2f37f/nao/eliminate.py#L12
		'''
		begin_address = self.begin_address
		page_map = begin_address - begin_address % 0x1000 # page alignment
		self.emu.mem_map(page_map, 0x400000)
		self.emu.mem_write(begin_address, bytes(self.opcodes))

		# initialize stack
		self.emu.reg_write(UC_X86_REG_ESP, begin_address + 0x200000)
		self.emu.reg_write(UC_X86_REG_EBP, begin_address + 0x200100)

		# initialize registers
		self.emu.reg_write(UC_X86_REG_EAX, 0x1234)
		self.emu.reg_write(UC_X86_REG_EBX, 0x1234)
		self.emu.reg_write(UC_X86_REG_ECX, 0x1234)
		self.emu.reg_write(UC_X86_REG_EDX, 0x1234)
		self.emu.reg_write(UC_X86_REG_EDI, 0x1234)
		self.emu.reg_write(UC_X86_REG_ESI, 0x1234)

		# initialize flags
		self.emu.reg_write(UC_X86_REG_EFLAGS, 0x0)

		# ============== My code start from here =================
		self.emu.emu_start(begin_address, begin_address + len(self.opcodes))
		eip = self.emu.reg_read(str_to_unicorn_reg(self.eip_reg))
		key = self.emu.reg_read(str_to_unicorn_reg(self.key_reg))
		eip += self.offset

		self.key = key
		self.eip = eip
		self.len = self.emu.reg_read(UC_X86_REG_ECX)
		return

	def run_deobfuscate(self):
		# first check if the new begin_address of the block contain the instruciton fnstenv
		check = True
		count = 0
		while check:
			check = self._check_block_addr_for_fnstenv()
			if check == False:
				break
		
			self._emulate()
			log_info(f"Start decrypt at position: {hex(self.eip)}")
			log_info(f"Using the key: {hex(self.key)}")
			log_info(f"With len: {hex(self.len)}")


			decrypt(self.bv, self.eip, self.key, self.len)
			self.bv.update_analysis_and_wait()
			count += 1

			loop_address = self.xor_address
			for instr in self.bv.disassembly_tokens(self.xor_address):
				if instr[0][0].text == 'loop':
					break
				loop_address += instr[1]

			# setup the next address
			self.begin_address = self.bv.get_next_basic_block_start_after(loop_address)
			self.emu = Uc(UC_ARCH_X86, UC_MODE_32)
			emulate_bytes, counter_addr = self.get_code_to_emulate(self.bv, self.begin_address)
			self.opcodes = emulate_bytes

			self.len = 0
			self.eip = 0
			self.key = 0

			self.xor_address = counter_addr

		log_info(f"Done decode shikata ga nai, the number of layers is: {count}")
		return

	
class RunInBackground(BackgroundTaskThread):
	def __init__(self, bv, addr, msg):
		BackgroundTaskThread.__init__(self, msg, True)
		self.bv = bv
		self.addr = addr

	def run(self):
		bv = self.bv
		DeShikata = DeobfuscateShikataGaNai(self.bv, self.addr)
		DeShikata.run_deobfuscate()

def main(bv, address):
	s = RunInBackground(bv, address, "Deobfuscate shikata ga nai")
	s.start()

PluginCommand.register_for_address("DeShikata", "Decode a round of shikata ga nai on given address", main)