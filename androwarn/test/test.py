#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys, re, logging, cgi

PATH_INSTALL = "/home/android/tools/androguard/"
sys.path.append(PATH_INSTALL)


from androlyze import *
from androguard.core import *
from androguard.core.androgen import *
from androguard.core.androconf import *
from androguard.core.bytecode import *
from androguard.core.bytecodes.jvm import *
from androguard.core.bytecodes.dvm import *
from androguard.core.bytecodes.apk import *
from androguard.core.analysis.analysis import *
from androguard.core.analysis.ganalysis import *
from androguard.decompiler.decompiler import *

import chilkat
from OpenSSL import crypto, SSL
# Constants 
ERROR_INDEX_NOT_FOUND = -2

# Logguer
log = logging.getLogger('log')
log.setLevel(logging.DEBUG)
formatter = logging.Formatter('[%(levelname)s] %(message)s')
handler = logging.StreamHandler()
handler.setFormatter(formatter)
log.addHandler(handler)

#TEST  = 'examples/java/test/orig/Test1.class'
#TEST = 'HelloWorld/bin/classes.dex'
#TEST = 'HelloWorld/bin/HelloWorld.apk'
#TEST = '/home/android/PFE/APKS/Trojan-SMS_for_Android_FakePlayer_RU.apk'
TEST = '/home/android/PFE/APKS/Papaya_Farm_1.3.apk'
#TEST = '/home/android/PFE/APKS/Android.Qicsomos_-_Fake_CarrierIQ_detector-SMS_Trojan.apk'

#a = AndroguardS( TEST )
#x = analysis.VMAnalysis( a.get_vm(), code_analysis=True )
#classes = a.get_vm().get_classes_names()

#Constants
CONST_STRING = 'const-string'
CONST = 'const'
MOVE = 'move'
MOVE_RESULT = 'move-result'
APUT = 'aput'
INVOKE = 'invoke'
INVOKE_NO_REGISTER = 'invoke-no-register'
INVOKE_2_REGISTERS = 'invoke-2-registers'
NEW_INSTANCE = 'new-instance'

def match_current_instruction(current_instruction, registers_found) :
		#regexes
		p_const 				= re.compile('^const(?:\/4|\/16|\/high16|-wide(?:\/16|\/32)|-wide\/high16|)? v([0-9]+) , (?:.*) // \{(\-?[0-9]+(?:\.[0-9]+)?)\}$')
		p_const_string			= re.compile('^const-string(?:||-jumbo) v([0-9]+) , \[ string@ (?:[0-9]+) \'(.*)\' \]$')
		p_move					= re.compile('move(?:|\/from16|-wide(?:\/from16|\/16)|-object(?:|\/from16|\/16))? v([0-9]+) , (v[0-9]+)')
		p_move_result			= re.compile('move(?:-result(?:|-wide|-object)|-exception)? v([0-9]+)')
		p_aput					= re.compile('^aput(?:-wide|-object|-boolean|-byte|-char|-short|) v([0-9]+) , v([0-9]+) , v([0-9]+)$')
		p_invoke 				= re.compile('^invoke-(?:static|virtual|direct|super|interface|interface-range|virtual-quick|super-quick) v([0-9]+) , \[ meth@ (?:[0-9]+) (L(?:.*); .*) \[(.*)\] \]$')
		p_invoke_2_registers 	= re.compile('^invoke-(?:static|virtual|direct|super|interface|interface-range|virtual-quick|super-quick) v([0-9]+) , v([0-9]+) , \[ meth@ (?:[0-9]+) (L(?:.*); .*) \[(.*)\] \]$')
		p_invoke_no_register	= re.compile('^invoke-(?:static|virtual|direct|super|interface|interface-range|virtual-quick|super-quick) \[ meth@ (?:[0-9]+) (L(?:.*); .*) \[(.*)\] \]$')
		p_new_instance 			= re.compile('^new-instance v([0-9]+) , \[ type@ (?:[0-9]+) (L(?:.*);) \]$')
		
		
		# Returned values init
		instruction_name = ''
		local_register_number = -1
		local_register_value = -1
		
		
		if p_const_string.match(current_instruction) :
			#print p_const_string.match(current_instruction).groups()
			
			instruction_name = CONST_STRING
			
			register_number = p_const_string.match(current_instruction).groups()[0]
			register_value = p_const_string.match(current_instruction).groups()[1]
			
			if not(register_number in registers_found) :
				registers_found[register_number] = register_value
			else :
				old_string = registers_found[register_number]
				new_string = "%s %s" % (str(register_value), str(old_string))
				registers_found[register_number] = new_string
			
			local_register_number = register_number
			local_register_value = register_value
	
	
		if p_const.match(current_instruction) :
			#print p_const.match(current_instruction).groups()
			
			instruction_name = CONST
			
			register_number = p_const.match(current_instruction).groups()[0]
			register_value = p_const.match(current_instruction).groups()[1]
			
			if not(register_number in registers_found) :
				registers_found[register_number] = register_value
			
			local_register_number = register_number
			local_register_value = register_value
	
	
		if p_move.match(current_instruction) :
			#print p_move.match(current_instruction).groups()
			
			instruction_name = MOVE
			
			register_number = p_move.match(current_instruction).groups()[0]
			register_value = p_move.match(current_instruction).groups()[1]
			
			if not(register_number in registers_found) :
				registers_found[register_number] = register_value				
			
			local_register_number = register_number
			local_register_value = register_value


		if p_move_result.match(current_instruction) :
			#print p_move_result.match(current_instruction).groups()
			
			instruction_name = MOVE_RESULT
			
			register_number = p_move_result.match(current_instruction).groups()[0]
			register_value = ''
			
			if not(register_number in registers_found) :
				registers_found[register_number] = register_value		
			
			local_register_number = register_number
			local_register_value = register_value	
			#print "number returned %s" % local_register_number
			#print "value returned %s" % local_register_value	

		if p_invoke.match(current_instruction) :
			#print p_invoke.match(current_instruction).groups()
			
			instruction_name = INVOKE
			
			register_number = p_invoke.match(current_instruction).groups()[0]
			register_value = p_invoke.match(current_instruction).groups()[1]
			
			if not(register_number in registers_found) :
				registers_found[register_number] = register_value		
			
			local_register_number = register_number
			local_register_value = register_value		
		
		if p_invoke_no_register.match(current_instruction) :
			#print p_invoke.match(current_instruction).groups()
			
			instruction_name = INVOKE_NO_REGISTER
			
			register_number = ''
			register_value = p_invoke_no_register.match(current_instruction).groups()[0]
			
			local_register_number = register_number
			local_register_value = register_value
		
		if p_invoke_2_registers.match(current_instruction) :
			#print p_invoke.match(current_instruction).groups()
			
			instruction_name = INVOKE_NO_REGISTER
			
			register_number = p_invoke_2_registers.match(current_instruction).groups()[0]
			register_value = p_invoke_2_registers.match(current_instruction).groups()[1]
			
			local_register_number = register_number
			local_register_value = register_value		
			
		if p_new_instance.match(current_instruction) :
			#print p_new_instance.match(current_instruction).groups()
			
			instruction_name = INVOKE
			
			register_number = p_new_instance.match(current_instruction).groups()[0]
			register_value = p_new_instance.match(current_instruction).groups()[1]
			
			if not(register_number in registers_found) :
				registers_found[register_number] = register_value		
			
			local_register_number = register_number
			local_register_value = register_value
		
		if p_aput.match(current_instruction) :
			#print p_aput.match(current_instruction).groups()
			
			instruction_name = APUT
			
			register_object_reference = p_aput.match(current_instruction).groups()[0]
			register_array_reference = p_aput.match(current_instruction).groups()[1]
			register_element_index = p_aput.match(current_instruction).groups()[2]

			local_register_number = register_object_reference 
			local_register_value =  register_array_reference	
			#supprimer dans relevant_registers la valeur 'array_reference'
			
			#ajouter object_reference
			#modifier la condition d'ajout pour "const_string" pour le cas ou il y a déja ce même numéro de registre => concaténer les valeurs en LIFO strcat(%s%s,new_element, old_string)
		
		return instruction_name, local_register_number, local_register_value, registers_found	

def find_call_index_in_code_list(index_to_find, instruction_list):
	"""
	@param index_to_find : index of the method call
	@param code_list : instruction list of the parent method called
	
	@rtype : the index of the method call in the instruction listing
	"""	
	idx = 0
	for i in instruction_list :
		if index_to_find <= idx :
			#print "[+] code offset found at the index " + str(instruction_list.index(i))
			return instruction_list.index(i)
		else :
			idx += i.get_length()
	
	# in case of failure, return an inconsistent value
	return ERROR_INDEX_NOT_FOUND

def backtrace_registers_before_call(x, method, index_to_find) :
	"""
	@param x : a VMAnalysis instance
	@param method : a regexp for the method (the package)
	@param index_to_find : index of the matching method
	
	@rtype : an ordered list of dictionaries of each register content [{ 'register #': 'value' }, { 'register #': 'value' } ...]
	"""	
	registers = {}
	
	code = method.get_code()
	#code.show()
	
	bc = code.get_bc()
	instruction_list = bc.get()
	

	found_index = find_call_index_in_code_list(index_to_find, instruction_list)
	
	if (found_index < 0) :
		log.error("The call index in the code list can not be found")
		return 0
		
	else :
		# Initialize the returned list of dictionaries
		registers_final = []
		
		# Initialize the harvesting dictionary
		registers_found = {}
		
		# List the register indexes related to the method call
		relevant_registers = relevant_registers_for_the_method(method, index_to_find)
		print relevant_registers
		
		i = int(found_index) - 1 # start index
		

		while ((all_relevant_registers_filled(registers_found,relevant_registers) != True) and (i >= 0)) :
			current_instruction = instruction_list[i].show_buff(0)
			#print current_instruction
			
			instruction_name, local_register_number, local_register_value, registers_found =  match_current_instruction(current_instruction, registers_found)
			
			if cmp(instruction_name, APUT) == 0:
				try :
					list_index_to_be_changed = relevant_registers.index(str(local_register_value))
					#print "index_to_be_changed %s" % list_index_to_be_changed
					del(relevant_registers[int(local_register_value)]) 
					relevant_registers.insert(list_index_to_be_changed, local_register_number)
					log.info("New relevant_registers %s" % relevant_registers)
				except :
					log.warn("'%s' does not exist anymore in the relevant_registers list" % local_register_value)
			
			if (cmp(instruction_name, MOVE_RESULT) == 0) and (local_register_number in relevant_registers):
				try:
					past_instruction = instruction_list[i-1].show_buff(0)
					p_instruction_name, p_local_register_number, p_local_register_value, registers_found =  match_current_instruction(past_instruction, registers_found)
					
					print past_instruction
					if cmp(p_instruction_name, INVOKE_NO_REGISTER) == 0 :
						registers_found[local_register_number] = p_local_register_value
					
					else:
						list_index_to_be_changed = relevant_registers.index(str(local_register_number))
						del(relevant_registers[int(list_index_to_be_changed)])
						relevant_registers.insert(list_index_to_be_changed, p_local_register_number)
					
					log.info("New relevant_registers %s" % relevant_registers)
				
				except:
					log.warn("'%s' does not exist anymore in the relevant_registers list" % local_register_value)

			i = i - 1
		
		#log.info('Registers found during the analysis %s' % registers_found)
			
			
		
		final_answer = all_relevant_registers_filled(registers_found,relevant_registers)
		log.info("Are all relevant registers filled ? %s" % str(final_answer))
		
		for i in relevant_registers :			
			try:
				register_number	= i
				#print register_number
				
				register_value 	= registers_found[i]
				#print register_value
				
				temp_dict = { register_number : register_value }
				registers_final.append(temp_dict)
			
			except KeyError:
				registers_final = []
				log.warn("KeyError exception : The value of the register # %s could not be found for the relevant registers %s" % (register_number, relevant_registers))
				break
				
		
		
		return registers_final

def extract_register_index_out_splitted_values(registers_raw_list_splitted) :
	"""
	@param : registers_raw_list_splitted : a list of registers still containing the 'v' prefix [' v1 ', ' v2 ' ...]
	
	@rtype : an ordered list of register indexes ['1', '2' ...]
	"""		
	relevant_registers = []
	
	# Trim the values
	registers_raw_list_splitted[:] = (value.strip() for value in registers_raw_list_splitted if len(value) > 0)
	
	for value in registers_raw_list_splitted :
		
		# Remove that 'v'
		p_register_index_out_of_split = re.compile('^v([0-9]+)$')
		
		if p_register_index_out_of_split.match(value) :
			register_index = p_register_index_out_of_split.match(value).groups()[0]
			
			relevant_registers.append(register_index)
		
		else :
			relevant_registers.append('N/A')
	
	return relevant_registers


def relevant_registers_for_the_method(method, index_to_find) :
	"""
	@param method : a method instance
	@param index_to_find : index of the matching method
	
	@rtype : an ordered list of register indexes related to that method call
	"""	
	relevant_registers = []
	
	code = method.get_code()
	#code.show()
	
	bc = code.get_bc()
	instruction_list = bc.get()
	

	found_index = find_call_index_in_code_list(index_to_find, instruction_list)
	
	if (found_index < 0) :
		log.error("The call index in the code list can not be found")
		return 0
		
	else :
		current_instruction = instruction_list[found_index].show_buff(0)
		#print current_instruction
	
		p_invoke = re.compile('^invoke-(static|virtual|direct|super|interface|interface-range|virtual-quick|super-quick)(?:\/range)? (v(.+) ,)+ \[(?:(.*))$')
		
		if p_invoke.match(current_instruction) :
			registers_raw_list_splitted = p_invoke.match(current_instruction).groups()[1].split(',')
			relevant_registers = extract_register_index_out_splitted_values(registers_raw_list_splitted)
		
		# -- OLD --
		#Delete the 1st elements, as it is the method's instance register
		#relevant_registers.pop(0)
		# ---------
		
		return relevant_registers

def all_relevant_registers_filled(registers, relevant_registers) :
	"""
	@param registers : a dictionary of each register content { 'register #': 'value' }
	@param relevant_registers : an ordered list of register indexes related to that method call
	
	@rtype : True if all the relevant_registers are filled, False if not 
	"""	
	answer = True
	
	for i in relevant_registers :
		# assert a False answer for null registers from the "move-result" instruction
		if not(i in registers) or (i in registers and len(registers[i]) < 1) :
			answer = False
		'''	
		if not(i in registers) :
			answer = False
		'''
	return answer
	

#b = x.tainted_packages.search_methods("Landroid/telephony/SmsManager","sendTextMessage", ".")
#b =  x.tainted_packages.search_methods("Landroid/location/LocationManager","getProviders", ".")
'''
b = x.tainted_packages.search_methods("Ljava/lang/Runtime","exec", ".")






for result in xrange( len(b) ) :
	oncreate_method = b[result].get_method()
	method_call_index_to_find = b[result].get_offset()
	registers = backtrace_registers_before_call(x, oncreate_method, method_call_index_to_find)
	log.info("Class '%s' - Method '%s' - register state before call %s" % (b[result].get_class_name(),b[result].get_name(), registers))

	#print relevant_registers_for_the_method(oncreate_method, method_call_index_to_find)
'''

def AnalyzeAPK(filename, raw=False) :
    """
        Analyze an android application and setup all stuff for a more quickly analysis !

        @param filename : the filename of the android application or a buffer which represents the application
        @param raw : True is you would like to use a buffer
        
        @rtype : return the APK, DalvikVMFormat, and VMAnalysis objects
    """
    androconf.debug("APK ...")
    a = APK(filename, raw)

    d, dx = AnalyzeDex( filename, a.get_dex() )

    return a, d, dx

def grab_certificate_information(cert) :
	cert_info = []
	cert_info.append("Serial number: \t\t%s" % cert.serialNumber())
	cert_info.append("Issuer:\t\t\tC=%s, ST=%s, L=%s, O=%s,\n\t\t\tOU=%s, CN=%s" % (cert.issuerC(), cert.issuerS(), cert.issuerL(), cert.issuerO(), cert.issuerOU(), cert.issuerCN()))
	cert_info.append("Subject:\t\tC=%s, ST=%s, L=%s, O=%s,\n\t\t\tOU=%s, CN=%s" % (cert.subjectC(), cert.subjectS(), cert.subjectL(), cert.subjectO(), cert.subjectOU(), cert.subjectCN()))
	cert_info.append("SHA1 Thumbprint:\t%s" % cert.sha1Thumbprint())

	#print "Version %s" % cert.exportCertPem()
	
	return cert_info
'''
a, d, x = AnalyzeAPK(TEST)
success, cert = a.get_certificate("META-INF/PAPAYA.RSA")
for i in grab_certificate_information(cert):
	print i
'''

from HTMLParser import HTMLParser

class MLStripper(HTMLParser):
    def __init__(self):
        self.reset()
        self.fed = []
    def handle_data(self, d):
        self.fed.append(d)
    def get_data(self):
        return ''.join(self.fed)

def strip_tags(html):
    s = MLStripper()
    s.feed(html)
    return s.get_data()



#tainted = '<p>Official client for VK.com, the all-purpose tool for communication and finding friends. Featuring in this version:<br>- Newsfeed and Friends<br>- Photo and Location Sharing<br>- Private Messages and Group Chats<br>- Music<br>- User profiles<br>- Photo albums<br>- Contacts sync<br>- Widgets'
tainted = 'Keep this Text <remove><me /> KEEP </remove> 123'
tainted = tainted.replace('<br>', '\n')
print strip_tags(tainted)
#certpem = cert.exportCertPem()
#cert_openssl = crypto.load_certificate(crypto.FILETYPE_PEM, certpem)









'''
#display_SEARCH_METHODS( a, x, classes,"Landroid/telephony/SmsManager","sendTextMessage", "(Ljava/lang/String; Ljava/lang/String; Ljava/lang/String; Landroid/app/PendingIntent; Landroid/app/PendingIntent;)V" )
b = x.tainted_packages.search_methods("Landroid/telephony/SmsManager","sendTextMessage", ".")


oncreate_method = b[0].get_method()
code = oncreate_method.get_code()
bc = code.get_bc()

print code
print "Offsettttttt " + str(b[0].get_offset())


# 1) Trouver offset de la méthode recherchée ("sendTextMessage") => get_offset()
# 2) Connaitre la valeur des registres avant appel
idx_to_find = b[0].get_offset()


for i in bc.get() :
	if i.get_offset() == idx_to_find :
		print "[+] code offset found at the index " + idx
		break
	else :
		idx = idx + 1

print "[+] idx to find " + str(idx_to_find)
idx = 0
for i in bc.get() :
	print "[+] current idx " + str(idx)
	buff = i.show_buff(idx)
	#print "[+] Index " + str(idx) + " : " + buff
	#print "\t",  i.get_name(), i.get_operands(), i.get_formatted_operands()
	if idx_to_find <= idx :
		print "[+] code offset found at the index " + str(bc.get().index(i))
	else :
		idx += i.get_length()
	print

print bc.get()[15].show_buff(0)
#print show_a_Path(b[0])

'''

'''
# Informations pour une METHODE
for method in a.get("method", "onCreate") :
    #method.show()
    print "[+] get_class_name : " + method.get_class_name()
    print "[+] get_name : " + method.get_name()
    print "[+] get_descriptor : " + method.get_descriptor()
    
    code = method.get_code()
    
    # 1ere methode pour afficher le code (detaillee)
    # type(code) = DalvikCode qui contient un attribut code
    # type(code.code) = DCODE
    # code.show() -> code.code->show() -> DCODE.show() à la ligne 2806 de androguard/core/dvm.py
    # Fonction responsable du formattage -> show_buff(self, pos) à la ligne 2468 de androguard/core/dvm.py
    #code.show() 
    
    
    bc = code.get_bc()
    
    idx = 0
    
    # Affichage du code
    for i in bc.get() :
		#2eme methode pour afficher le code (pas detaillee)
        #print "\t",  i.get_name(), i.get_operands(), i.get_formatted_operands()
        idx += i.get_length()

# How-to get the certificate 
success, cert = a.get_certificate("META-INF/PAPAYA.RSA")
print str(success) + " "+ str(type(cert))
show_Certificate(cert)

def display_SEARCH_METHODS(a, x, classes, package_name, method_name, descriptor) :
    #print "Search method", package_name, method_name, descriptor
    analysis.show_Path( x.tainted_packages.search_methods( package_name, method_name, descriptor) )
    
#display_SEARCH_METHODS( a, x, classes,"Landroid/telephony/SmsManager","sendTextMessage", "(Ljava/lang/String; Ljava/lang/String; Ljava/lang/String; Landroid/app/PendingIntent; Landroid/app/PendingIntent;)V" )


def show_a_Path(path) :
	"""
	Show paths of packages
	@param paths : a path
	"""
	print "%s %s %s (@%s-0x%x)  ---> %s %s %s" % (path.get_method().get_class_name(), path.get_method().get_name(), path.get_method().get_descriptor(), \
													  path.get_bb().get_name(), path.get_bb().start + path.get_idx(), \
													  path.get_class_name(), path.get_name(), path.get_descriptor())

def display_SEARCH_PACKAGES(a, x, classes, package_name) :
    print "Search package", package_name
    print len(x.tainted_packages.search_packages( package_name ))
    #analysis.show_Path( x.tainted_packages.search_packages( package_name ) )

#Recherche
#result_search = x.tainted_packages.search_packages( "Landroid/telephony/" )

#Affichage des résultats à la ligne 1362 de core/analysis.py
#print (result_search[1].get_method().get_name())

#method = a.get_methods()[7]
#g = x.get_method( method ) # onCreate
#print g #type MethodAnalysis
#print method.get_class_name(), method.get_name(), method.get_descriptor()




for i in g.basic_blocks.get() :
	print i.get_start()

for i,n in g.basic_blocks.get_tainted_packages().get_packages():
	#print i.get_name()
	print analysis.show_Path(i.get_methods())

for i in g.basic_blocks.get_tainted_variables():
	#print "\t %s %x %x" % (i.name, i.start, i.end), i.ins[-1].get_name(), '[ CHILDS = ', ', '.join( "%x-%x-%s" % (j[0], j[1], j[2].get_name()) for j in i.childs ), ']', '[ FATHERS = ', ', '.join( j[2].get_name() for j in i.fathers ), ']', i.free_blocks_offsets
	print i
'''


'''
#Generate Report Jinja stuff

for i in data :
	# avoid empty results
	if data[i] :
		temp_dict = {}
		temp_dict[i] = data[i]
		print temp_dict
		print type(temp_dict[i])
		#print "i %s, type i %s, data i %s" % (i,type(i), data[i])
		template.stream(temp_dict).dump(output_file, encoding='utf-8')
'''
#temp.dump(output_file, encoding='utf-8')
#template.stream(application_icon=icon, application_description=desc).dump(OUTPUT_DIR+'lol.html', encoding='utf-8')
