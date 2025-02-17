from use_define.utils import get_string,get_arity
from use_define.symbolic_execution_check import Symbolic_Execution_Checker
from angr.knowledge_plugins.key_definitions.undefined import Undefined
from angr.knowledge_plugins.key_definitions.tag import ReturnValueTag,ParameterTag

DEBUG=False
# recurse through the result of a use-def check, resolve the use-def of the local parameters, find the functions & function_argument that can influence the sink param
# if found the definition of a fmt_string, also return the position of its %s param, which is used for further use-def check 
class RD_Graph_Resolver():
    # project, cfg:angr project and its cfg
    # rd_rdd_graph:the result of ReachingDefinitions.depthgraph
    # input_param:the list containning all addresses of the user-input, which is the taint source
    # alert_sink_path_list: the sink name and sink path used for output
    # top_func_addr: the address of the top function used for output
    # output_dir:the path of the output file
    # is_direct_return: used to check whether the sink function hit the source param directly, 
    #   eg: param="http_passwd";system(param), 
    #   in this case, sink directly hit source, but it is used as a fixed string, not user input
    #   eg2: str="http_passwd";param=webgetvar(str);system(param),
    #   in this case, sink did not directly hit source while there is a function call between them, therefore, the user input might could influence sink function
    # debug:show debug information
    def __init__(self, project, cfg, rd_ddg_graph,input_param,alert_sink_path_list,top_func_addr,output_dir,is_direct_ret=False,enable_symbolic_check=True,debug=False):
        self.project = project
        self.cfg = cfg
        self.rd_ddg_graph = rd_ddg_graph
        self.input_param=input_param
        self.alert_sink_and_path_list=alert_sink_path_list
        self.top_func_addr=top_func_addr
        self.is_direct_ret=is_direct_ret
        self.output_dir=output_dir
        self.enable_symbolic_check=enable_symbolic_check

        global DEBUG
        DEBUG = debug

    # reg_def:the rd_defintion of a register, which can influence the sink parameter of the sink function
    # reg_is_fmt: if the register to be checked is a fmt_string, check the position of its %s param
    def resolve_use_def(self, reg_def,reg_is_fmt):
        # a dictionary that stores the functions whose return value can influence the given register
        # format:need_check_func[func_addr]=func_arity
        need_check_func = {}
        # a set that stores the function_argument that can influence the sink param
        upper_param = set()
        # a set that stores the register position of the %s params of a fmt_string
        current_extra_param = set()
        # all of the definitions to be checked(they all can influence the given register)
        defs_to_check = set()
        defs_to_check.add(reg_def)
    
        # store all seen nodes to prevent repeating analyse
        seen_defs = set()

        while len(defs_to_check) != 0:
            current_def = defs_to_check.pop()
            seen_defs.add(current_def) 
            # Check if the current Definition has a tag 
            def_type,def_value = self.check_definition_tag(current_def)
            if def_type=="sink":#sink reached source, return notion to inform the caller, now already disabled due to the use of yield_analyse
                return None,None,None
            if def_type=="retval":#a return val can influence the given reg
                if DEBUG:
                    print("hit a function call",current_def)
                    print("arity",get_arity(self.project,current_def.codeloc.block_addr))
                try:
                    block=self.cfg.model.get_any_node(current_def.codeloc.block_addr)
                    func_addr=block.successors[0].addr
                    func=self.cfg.functions.get_by_addr(func_addr)
                    if "atoi" in func.name or "ntoa" in func.name or "aton" in func.name:
                        continue
                except:
                    pass
                need_check_func[current_def.codeloc.ins_addr]=get_arity(self.project,current_def.codeloc.block_addr)#(func_call_addr,arity),check all parameters of current function
                continue
            elif def_type=="input":#reached a argument
                upper_param.add(def_value)
                pass
            else:
                dataset = current_def.data 
                # A value in DataSet can be "Int" or "Undefined", undefined means local_variable
                undefined_pointers = False 
                
                for data in dataset:
                    if type(data) == Undefined: undefined_pointers = True  

                if undefined_pointers:# resolve local variables
                    try:#sometimes there is a error(networkx.exception.NetworkXError: The node xxx is not in the digraph.)
                        for pred in self.rd_ddg_graph.graph.predecessors(current_def):
                            if pred not in seen_defs:
                                defs_to_check.add(pred)
                    except Exception as e:
                        pass
                else:
                    # This is a constant.
                    if reg_is_fmt is not None:#find the register position of the %s params of a fmt_string
                        try:#Todo:should I add process for int objects?
                            fmt_str=get_string(self.project,data,extended=True)
                            if fmt_str.count('%')==0:
                                continue
                            param_index=reg_is_fmt+1
                            for single_fmt in fmt_str.split("%")[1:]:
                                if single_fmt[0]=='s':
                                    current_extra_param.add(param_index)
                                param_index+=1       
                        except Exception as e:
                            if DEBUG:
                                print(e)
        return need_check_func,upper_param,current_extra_param

    def clear_direct_ret_tag(self):#if ended one resolve use def and didn't reached source, then sink isn't a direct return, clear the tag
        self.is_direct_ret=False

    # Checking the tag over a definition.
    def check_definition_tag(self, definition):
        if not self.is_direct_ret and definition.codeloc.ins_addr in self.input_param:#find that user-input reached the sink
            if DEBUG:
                print("alarm",self.alert_sink_and_path_list)
            with open(self.output_dir,'a') as f:
                self.printpath(self.alert_sink_and_path_list,f,definition.codeloc.ins_addr)
            # after enabling yield analyse, we can't return after finding a sink, as the sink param may reach other sources
            #return "sink",None
        if definition.codeloc.ins_addr==None:#may reached the top of the function
            try:
                test_variable=definition.atom.reg_offset
                if DEBUG:
                    print("reach args:",definition.atom.reg_offset)
            except Exception as e:#if the atom have no reg offset, then it is out of the function but not a input param(it might be a stack variable)
                if DEBUG:
                    print("get a external codeloc with no input param",definition)
                    for pred in self.rd_ddg_graph.graph.predecessors(definition):
                        print("pred",pred)
                return None,None
            if DEBUG:
                for pred in self.rd_ddg_graph.graph.predecessors(definition): 
                    print("pred",pred)
            return "input",definition.atom.reg_offset
        elif len(definition.tags) > 0:# local variable or int value
            curr_tag = definition.tags.pop() # take the first tag as its own tag
            if type(curr_tag) == ReturnValueTag:
                if DEBUG:
                    pass
                    #print(definition.codeloc.ins_addr)
                return "retval",curr_tag.function
            #ParameterTag means that the atom is a parameter,which is different from the real parameter parsed when the function begin
            # elif type(curr_tag) == ParameterTag:
            #     print(definition)
            #     try:
            #         print(dir(definition.atom))
            #         print(definition.atom.reg_offset)#the offset of input register
            #         for pred in self.rd_ddg_graph.graph.predecessors(definition):
            #             print("pred",pred)
            #             for pred2 in self.rd_ddg_graph.graph.predecessors(pred):
            #                 print("pred-pred",pred2)
            #                 print(dir(pred2.codeloc))
            #                 print(pred2.atom.reg_offset)
            #     except:
            #         pass
            #     return "is_param"
            else:# for all local variables, just resolve by recurse, so just return and let resolve_use_def check it
                if DEBUG:
                    pass
                    #print(type(curr_tag))#usually local_variable
                return None,None
        else:
            return None,None

    def find_strval(self,refaddr):#find the value of a string through its reference address
        try:
            xrefs=self.project.kb.xrefs.get_xrefs_by_ins_addr(refaddr)
            for xref in xrefs:
                if xref.type==0:
                    str_addr=xref.dst
                    return get_string(self.project,str_addr,extended=True)
        except:
            pass
        return "uncertain_str"

    def printpath(self,path_info_list,f,refaddr):#print the output if sink reached source
        for sink_name,sink_path in path_info_list:
            path=[]
            i=len(sink_path)-1
            addr, callee = sink_path[i][:2]
            path.append(addr)
            while(i>0):
                i-=1
                addr, callee = sink_path[i][:2]
                path.append(callee)
                path.append(addr)
            path.append(self.top_func_addr)#top function
            if DEBUG:
                print(path)
            #whether we need to use symbolic execution to check the output
            if self.enable_symbolic_check:
                
                #try:
                sym_checker=Symbolic_Execution_Checker()
                can_reach=sym_checker.symbolic_explore(self.project,self.cfg,refaddr,path[0],sink_name)
                if can_reach==0:
                    f.write("symbolic execution unreachable: ")
                if can_reach==-1:
                    f.write("symbolic execution Error/Timeout: ")
                #except:
                    #f.write("symbolic execution Error/Timeout: ")
            f.write("str "+self.find_strval(refaddr)+" refed at refaddr "+str(hex(refaddr))+" reached sink "+sink_name+",sink path:")
            depth=int((len(path)-1)/2)
            while depth>=0:
                call_addr, function = path[2*depth],path[2*depth+1]
                if call_addr==function and call_addr==0xffffff:
                    #if it occures 0xfffffff,0xffffff, it means that the trigger point is in a library function
                    f.write('library function >>')
                else:
                    f.write('Func %s -> %s >>' % (str(hex(function)),str(hex(call_addr))))
                depth-=1
            f.write('>>sink\n')