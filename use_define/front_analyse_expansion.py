import angr
from use_define.utils import get_arguments_call_with_instruction_address,get_string
DEBUG=False
# find the API that is used for parsing web input by finding the function containning many of the input keywords,
# then use the API to expand the list of the input keywords
class Front_analyse_expansion():
    def __init__(self, project, cfg, xref_struct, return_API=True):
        self.project = project
        self.cfg = cfg
        self.xref_struct=xref_struct
        self.return_API=return_API

    # the main function of this class
    def expand_keywords(self):
        API_set,expanded_xref_struct=self.expand_keywords_by_input_params(self.xref_struct)
        return expanded_xref_struct
        #when the user input params are not enough to recognize the APIs, use some static keywords to expand the keyword list
        const_keywords=None
        if len(API_set)<1:
            const_keywords=self.find_key_address(self.str_info,{'username','password','url','filename','ip_addr'})
        if const_keywords is None:
            return key_addr
        if DEBUG:
            print(const_keywords)
        API_set,key_addr_new=self.expand_keywords_by_input_params(const_keywords)
        if DEBUG:
            print("expand keywords done")
        return key_addr+key_addr_new#the output of this class, which is a list contains the origin input keywords, with the form of [(addr,str_name),(addr,str_name),...]

    # find the APIs by analysing the function references of the input parameters
    def expand_keywords_by_input_params(self,xref_struct):
        API_count_dict={}
        API_set=set()
        most_common_api=None
        most_common_api_occurance=1
        for string_addr in xref_struct.keys():
            xrefs = xref_struct[string_addr]
            if DEBUG:
                print(xrefs)
            call_addr_count_dict={}
            most_common_caller=None
            inner_api_occurance=0
            for xref in xrefs:
                reg_name,call_addr = self.get_reg_name_and_call_addr(xref)
                if call_addr is None:
                    continue
                if call_addr not in call_addr_count_dict.keys():
                    call_addr_count_dict[call_addr]=(1,reg_name)
                else:
                    if call_addr_count_dict[call_addr][1]==reg_name:#in different references, the argument should be parsed by the same register, as the keyword in an API won't occure in different locations in different use situation
                        call_addr_count_dict[call_addr]=(call_addr_count_dict[call_addr][0]+1,call_addr_count_dict[call_addr][1])
                if call_addr_count_dict[call_addr][0] > inner_api_occurance:#use a same function to parse the argument for many times
                    inner_api_occurance=call_addr_count_dict[call_addr][0]
                    most_common_caller=call_addr
                    if inner_api_occurance>3:# after an API appeared too many times, we can similiarly regard it as most common refered API of this input param
                        break
            if most_common_caller is None and len(call_addr_count_dict) > 0:
                for call_addr in call_addr_count_dict.keys():
                    most_common_caller=call_addr
                    break
            if most_common_caller is not None and most_common_caller not in API_count_dict.keys():
                API_count_dict[most_common_caller]=(1,call_addr_count_dict[most_common_caller][1])
            elif most_common_caller is not None:
                API_count_dict[most_common_caller]=(API_count_dict[most_common_caller][0]+1,API_count_dict[most_common_caller][1])
                if API_count_dict[most_common_caller][0] == 5:#use a same function to parse the argument for many times, use "==" instead of ">" in order to avoid duplicate outputing
                    API_set.add((most_common_caller,API_count_dict[most_common_caller][1]))
                    print("find API, addr:",self.cfg.functions.get_by_addr(most_common_caller).name)
                if API_count_dict[most_common_caller][0] > most_common_api_occurance:#if the referenced count is not significant, only return the most common refered api
                    try:
                        most_common_api_occurance=API_count_dict[most_common_caller][0]
                        most_common_api=self.cfg.functions.get_by_addr(most_common_caller)
                    except:
                        pass
        if most_common_api is not None and len(API_set) == 0:
            print("find API, addr:",most_common_api.name)
            API_set.add((most_common_api.addr,API_count_dict[most_common_api.addr][1]))
        #find all references to the web-input APIs, use them to expand the user input
        xref_struct=self.find_references_and_expand_input(API_set,xref_struct)
        if self.return_API:
            return API_set,xref_struct

    def find_references_and_expand_input(self,API_set,xref_struct):
        xref_struct[0xff]=[]#an list which contains the expanded references
        for api_addr,reg_name in API_set:
            try:
                api_func=self.cfg.functions.get_by_addr(api_addr)
                func_node = self.cfg.model.get_any_node(api_func.addr)
                func_pred_nodes = func_node.predecessors#the node of the basic block contaning the caller of the API
                #print(func_pred_nodes)
                #search all xrefs of all API, for each xref, if there is a string 
                for pred_node in func_pred_nodes:
                    #TODO: as we need the addr of the target str, we need the index of the argument of the interested str to avoid analysing too much strings
                    
                    pred_block=pred_node.block
                    set_params=get_arguments_call_with_instruction_address(self.project,pred_block)
                    str_refed_before=False
                    str_in_key=False
                    for addr,object in set_params:
                        #print("check arg",addr,self.project.arch.register_names[object.offset],reg_name)
                        if reg_name==self.project.arch.register_names[object.offset]:
                            # due to the limitations of the angr xref API, some strval in tenda and d-link are often recognized as "uncertain_str", so we use addr instead of value to expand the xref result
                            straddr,strval=self.find_strval(addr)
                            for string_addr in xref_struct.keys():
                                if straddr == string_addr:
                                    str_in_key=True
                                xrefs = xref_struct[string_addr]
                                for xref in xrefs:
                                    if xref == addr:
                                        #print("referenced",addr)
                                        str_refed_before=True
                            if not str_refed_before:
                                print("add new user input",addr)
                                if str_in_key:
                                    xref_struct[straddr].append(addr)
                                else:
                                    xref_struct[0xff].append(addr)
                            '''
                            straddr,strval=self.find_strval(addr)
                            if strval!="uncertain_str":
                                if DEBUG:
                                    print(api_func.name,addr,strval,straddr)
                                for (addr,str_name) in key_address:
                                    if str_name==strval:
                                        str_refed_before=True
                                        break
                                if not str_refed_before:
                                    print("add new user input",strval)
                                    key_address.append((straddr,strval))
                            '''
                    
            except:
                print("API expand keyword error")
        return xref_struct

    def find_strval(self,refaddr):#find the value of a string through its reference address
        try:
            xrefs=self.project.kb.xrefs.get_xrefs_by_ins_addr(refaddr)
            for xref in xrefs:
                if xref.type==0:
                    str_addr=xref.dst
                    return str_addr,get_string(self.project,str_addr,extended=True)
        except:
            pass
        return None,"uncertain_str"

    # given the addr of an argument, return its call addr and its reg name(eg：if the string is parsed by $a0, then its reg name is a0, which means that it's the first arg)
    def get_reg_name_and_call_addr(self,instr_addr):
        # ipaddr:40ae94
        orig_instr_addr=instr_addr
        if DEBUG:
            print(hex(instr_addr))
        block=self.cfg.model.get_any_node(instr_addr)
        arg_containing_input='unknown'
        while block is None and instr_addr>self.project.loader.main_object.min_addr:
            instr_addr-=4
            block=self.cfg.model.get_any_node(instr_addr)
        try:
            callee=block.successors[0].addr
            callee_name=self.cfg.functions.get_by_addr(callee).name
            if callee_name == "UnresolvableJumpTarget" or callee_name == "UnresolvableCallTarget":
                return None,None
            if "cmp" in callee_name or "cpy" in callee_name or "match" in callee_name or "print" in callee_name or "ntoa" in callee_name or "dup" in callee_name or "put" in callee_name or "strstr" in callee_name or "err" in callee_name or "set" in callee_name or "md5" in callee_name or "log" in callee_name or "int" in callee_name or "strlen" in callee_name:#or "open" in callee_name, may opening a file be a source input? 
                return None,None
            if DEBUG:
                print(hex(block.addr),callee_name)
            instructions=block.block.capstone.insns
            for instruction in instructions:
                if instruction.insn.address==orig_instr_addr:
                    op_str=instruction.insn.op_str
                    arg_containing_input=op_str.split(',')[0]
                    #print("op_str",op_str,arg_containing_input)
                    if not arg_containing_input.isalnum():
                        arg_containing_input=arg_containing_input[1:]
                    if DEBUG:
                        print(arg_containing_input)
                    break
            return arg_containing_input,callee
        except:
            pass
        return None,None

    

    