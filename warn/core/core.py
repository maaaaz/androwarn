#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This file is part of Androwarn.
#
# Copyright (C) 2012, 2019, Thomas Debize <tdebize at mail.com>
# All rights reserved.
#
# Androwarn is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Androwarn is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Androwarn.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

# Global imports
import re
import logging

# Constants 
ERROR_VALUE_NOT_FOUND = 'N/A'
ERROR_CONSTANT_NAME_NOT_FOUND = 'N/A'

CONST_STRING = 'const-string'
CONST = 'const'
MOVE = 'move'
MOVE_RESULT = 'move-result'
APUT = 'aput'
INVOKE = 'invoke'
INVOKE_NO_REGISTER = 'invoke-no-register'
INVOKE_2_REGISTERS = 'invoke-2-registers'
NEW_INSTANCE = 'new-instance'

# Logguer
log = logging.getLogger('log')

# Instruction matcher
def match_current_instruction(current_instruction, registers_found) :
    """
        @param current_instruction : the current instruction to be analyzed
        @param registers_found : a dictionary of registers recovered so far
    
        @rtype : the instruction name from the constants above, the local register number and its value, an updated version of the registers_found
    """
    p_const                 = re.compile('^const(?:\/4|\/16|\/high16|-wide(?:\/16|\/32)|-wide\/high16|)? v([0-9]+), \+?(-?[0-9]+(?:\.[0-9]+)?)$')
    p_const_string          = re.compile("^const-string(?:||-jumbo) v([0-9]+), u?'(.*)'$")
    p_move                  = re.compile('^move(?:|\/from16|-wide(?:\/from16|\/16)|-object(?:|\/from16|\/16))? v([0-9]+), (v[0-9]+)$')
    p_move_result           = re.compile('^move(?:-result(?:|-wide|-object)|-exception)? v([0-9]+)$')
    p_aput                  = re.compile('^aput(?:-wide|-object|-boolean|-byte|-char|-short|) v([0-9]+), v([0-9]+), v([0-9]+)$')
    p_invoke                = re.compile('^invoke-(?:static|virtual|direct|super|interface|interface-range|virtual-quick|super-quick) v([0-9]+), (L(?:.*);->.*)$')
    p_invoke_2_registers    = re.compile('^invoke-(?:static|virtual|direct|super|interface|interface-range|virtual-quick|super-quick) v([0-9]+), v([0-9]+), (L(?:.*);->.*)$')
    p_invoke_no_register    = re.compile('^invoke-(?:static|virtual|direct|super|interface|interface-range|virtual-quick|super-quick) (L(?:.*);->.*)$')
    p_new_instance          = re.compile('^new-instance v([0-9]+), (L(?:.*);)$')
    
    
    # String concat
    current_instruction = "{} {}".format(current_instruction.get_name(), current_instruction.get_output())
    
    # Returned values init
    instruction_name = ''
    local_register_number = -1
    local_register_value = -1
    
    
    if p_const_string.match(current_instruction):
        #print(p_const_string.match(current_instruction).groups())
        
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


    if p_const.match(current_instruction):
        #print(p_const.match(current_instruction).groups())
        
        instruction_name = CONST
        
        register_number = p_const.match(current_instruction).groups()[0]
        register_value = p_const.match(current_instruction).groups()[1]
        
        if not(register_number in registers_found) :
            registers_found[register_number] = register_value
        
        local_register_number = register_number
        local_register_value = register_value


    if p_move.match(current_instruction):
        #print(p_move.match(current_instruction).groups())
        
        instruction_name = MOVE
        
        register_number = p_move.match(current_instruction).groups()[0]
        register_value = p_move.match(current_instruction).groups()[1]
        
        if not(register_number in registers_found) :
            registers_found[register_number] = register_value               
        
        local_register_number = register_number
        local_register_value = register_value


    if p_move_result.match(current_instruction):
        #print(p_move_result.match(current_instruction).groups())
        
        instruction_name = MOVE_RESULT
        
        register_number = p_move_result.match(current_instruction).groups()[0]
        register_value = ''
        
        if not(register_number in registers_found) :
            registers_found[register_number] = register_value       
        
        local_register_number = register_number
        local_register_value = register_value 

    if p_invoke.match(current_instruction):
        #print(p_invoke.match(current_instruction).groups())
        
        instruction_name = INVOKE
        
        register_number = p_invoke.match(current_instruction).groups()[0]
        register_value = p_invoke.match(current_instruction).groups()[1]
        
        if not(register_number in registers_found) :
            registers_found[register_number] = register_value       
        
        local_register_number = register_number
        local_register_value = register_value       
    
    if p_invoke_no_register.match(current_instruction):
        #print(p_invoke.match(current_instruction).groups())
        
        instruction_name = INVOKE_NO_REGISTER
        
        register_number = ''
        register_value = p_invoke_no_register.match(current_instruction).groups()[0]
        
        local_register_number = register_number
        local_register_value = register_value
    
    if p_invoke_2_registers.match(current_instruction):
        #print(p_invoke.match(current_instruction).groups())
        
        instruction_name = INVOKE_NO_REGISTER
        
        register_number = p_invoke_2_registers.match(current_instruction).groups()[0]
        register_value = p_invoke_2_registers.match(current_instruction).groups()[1]
        
        local_register_number = register_number
        local_register_value = register_value       
        
    if p_new_instance.match(current_instruction):
        #print(p_new_instance.match(current_instruction).groups())
        
        instruction_name = NEW_INSTANCE
        
        register_number = p_new_instance.match(current_instruction).groups()[0]
        register_value = p_new_instance.match(current_instruction).groups()[1]
        
        if not(register_number in registers_found) :
            registers_found[register_number] = register_value       
        
        local_register_number = register_number
        local_register_value = register_value
    
    if p_aput.match(current_instruction):
        #print(p_aput.match(current_instruction).groups())
        
        instruction_name = APUT
        
        register_object_reference = p_aput.match(current_instruction).groups()[0]
        register_array_reference = p_aput.match(current_instruction).groups()[1]
        register_element_index = p_aput.match(current_instruction).groups()[2]

        local_register_number = register_object_reference 
        local_register_value =  register_array_reference
        
    
    return instruction_name, local_register_number, local_register_value, registers_found   


def backtrace_registers_before_call(x, method, calling_index) :
    """
        @param x : a Analysis instance
        @param method : a regexp for the method (the package)
        @param calling_index : index of the matching method
    
        @rtype : an ordered list of dictionaries of each register content { 'register #': 'value' , 'register #': 'value', ... }
    """ 
    registers = {}
    
    bc = method.get_code().get_bc()
    instruction_list = list(bc.get_instructions())
    
    found_index = bc.off_to_pos(calling_index)
    
    if (found_index < 0) :
        log.error("The call index in the code list can not be found")
        return 0
        
    else :
        # Initialize the returned list of dictionaries
        registers_final = []
        
        # Initialize the harvesting dictionary
        registers_found = {}
        
        # List the register indexes related to the method call
        relevant_registers = relevant_registers_for_the_method(instruction_list[found_index])
        
        # start index
        i = int(found_index) - 1 

        while ((all_relevant_registers_filled(registers_found, relevant_registers) != True) and (i >= 0)) :
            current_instruction = instruction_list[i]
            
            instruction_name, local_register_number, local_register_value, registers_found = match_current_instruction(current_instruction, registers_found)
            
            if instruction_name == APUT:
                try :
                    list_index_to_be_changed = relevant_registers.index(str(local_register_value))
                    del(relevant_registers[int(local_register_value)]) 
                    relevant_registers.insert(list_index_to_be_changed, local_register_number)
                    log.debug("New relevant_registers %s" % relevant_registers)
                except :
                    log.debug("'%s' does not exist anymore in the relevant_registers list" % local_register_value)
            
            if (instruction_name == MOVE_RESULT) and (local_register_number in relevant_registers):
                try:
                    past_instruction = instruction_list[i-1]
                    p_instruction_name, p_local_register_number, p_local_register_value, registers_found =  match_current_instruction(past_instruction, registers_found)
                    
                    if p_instruction_name == INVOKE_NO_REGISTER:
                        registers_found[local_register_number] = p_local_register_value
                    
                    else:
                        list_index_to_be_changed = relevant_registers.index(str(local_register_number))
                        del(relevant_registers[int(list_index_to_be_changed)])
                        relevant_registers.insert(list_index_to_be_changed, p_local_register_number)
                    
                    log.debug("New relevant_registers %s" % relevant_registers)
                
                except:
                    log.debug("'%s' does not exist anymore in the relevant_registers list" % local_register_value)

            i = i - 1
        
        final_answer = all_relevant_registers_filled(registers_found,relevant_registers)
        log.debug("Are all relevant registers filled ? %s" % str(final_answer))
        
        # We need to have an ordered list of registers, so that is why we are not just returning the dict
        for i in relevant_registers :           
            try:
                register_number = i
                register_value  = registers_found[i]
                
                temp_dict = { register_number : register_value }
                registers_final.append(temp_dict)
            
            except KeyError:
                registers_final = []
                log.debug("KeyError exception : The value of the register #%s could not be found for the relevant registers %s" % (register_number, relevant_registers))
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
    
    for value in registers_raw_list_splitted:
        # Remove that 'v'
        p_register_index_out_of_split = re.compile('^v([0-9]+)$')
        
        if p_register_index_out_of_split.match(value):
            register_index = p_register_index_out_of_split.match(value).groups()[0]
            
            relevant_registers.append(register_index)
        
        else :
            relevant_registers.append('N/A')
    
    return relevant_registers


def relevant_registers_for_the_method(instruction) :
    """
        @param method : a method instance
        @param index_to_find : index of the matching method
    
        @rtype : an ordered list of register indexes related to that method call
    """ 
    relevant_registers = []
    
    current_instruction_name = instruction.get_name()
    current_instruction = instruction.show_buff(0)
    
    
    p_invoke_name       = re.compile('^invoke-(?:static|virtual|direct|super|interface|interface-range|virtual-quick|super-quick)$')
    p_invoke_range_name = re.compile('^invoke-(?:static|virtual|direct|super|interface|interface-range|virtual-quick|super-quick)(?:\/range)$')

    if p_invoke_name.match(current_instruction_name) :
        
        p_invoke_registers = re.compile('(v[0-9]+),')
        
        if p_invoke_registers.findall(current_instruction) :
            registers_raw_list_splitted = p_invoke_registers.findall(current_instruction)
            relevant_registers = extract_register_index_out_splitted_values(registers_raw_list_splitted)
    
    if p_invoke_range_name.match(current_instruction_name) :
        # We're facing implicit an implicit range declaration, for instance "invoke v19..v20"
        p_invoke_registers_range = re.compile('^v([0-9]+) ... v([0-9]+), L.*$')
        
        if p_invoke_registers_range.match(current_instruction) :
            register_start_number = p_invoke_registers_range.match(current_instruction).groups()[0]
            register_end_number = p_invoke_registers_range.match(current_instruction).groups()[1]
            
            if int(register_start_number) > int(register_end_number) :
                log.error("invoke-kind/range incoherent: # of the start register is lower than the end one")
            else :
                relevant_registers = [ str(i) for i in range(int(register_start_number), int(register_end_number))]
                # +1 because range does not provide the higher boundary value
        
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

    return answer


def get_register_value(index, registers) :
    """
        @param index : integer value of the index
        @param registers : an ordered list of register indexes related to that method call
    
        @rtype : a value casted in string
    """
    # Index - 1, list starts at index 0
    if index < len(registers) :
        dict = registers[index]
        return list(dict.values())[0]
    else :
        return ERROR_VALUE_NOT_FOUND

def get_constants_name_from_value(constant_dict, value) :
    """
        @param constant_dict : constant dictionary to consider
        @param value : value's constant name to retrieve
    
        @rtype : a string
    """
    try:
        return constant_dict[value]
    
    except KeyError:
        log.error("The constant name corresponding to the value '%s' can not be found in the dictionary '%s'" % (value, constant_dict))
        return ERROR_CONSTANT_NAME_NOT_FOUND

def data_flow_analysis(results, x) :
    """
        @param tab : structural analysis results tab
        @param result : current iteration
        @param x : a Analysis instance
    
        @rtype : an ordered list of dictionaries of each register content [{ 'register #': 'value' }, { 'register #': 'value' } ...]
    """
    for result in results:
        found_calls = result.get_xref_from()
        
        for parent_class, parent_method, calling_offset in found_calls:
            registers = backtrace_registers_before_call(x, parent_method, calling_offset)
    
            class_str   = "Class '%s'" % parent_class.orig_class.get_name()
            method_str  = "Method '%s'" % parent_method.get_name()
            regs_str    = "Register state before call %s" %  registers
            
            formatted_str = "{0:50}- {1:35}- {2:30}".format(class_str,method_str, regs_str)
            
            log.debug(formatted_str)
            yield registers