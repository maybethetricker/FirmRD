from use_define.utils import _ordered_argument_regs_names
from use_define.rdg_resolver import RD_Graph_Resolver

import angr.analyses.reaching_definitions.dep_graph as dep_graph

DEBUG=False

# check the reaching definition analyse from sink to source, in order to find sink path
class Use_Def_Checker():
    # save calls that is analysed by use-def to aviod repeating analyse
    analysed_call={}
    # if the length limit of a strncpy or a snprintf is fixed, it is usually not able to trigger a buffer overflow vulnerability, this dictionary contains the analyse result of the length limit, which is used for prune
    length_limit_result={}

    def __init__(self, analysed_call, length_limit_result, enable_symbolic_check=True,debug=False):
        #since the analysed calls should be saved globally for each binary, we just import it
        self.analysed_call=analysed_call
        self.length_limit_result=length_limit_result
        self.enable_symbolic_check=enable_symbolic_check
        global DEBUG
        DEBUG = debug

    #for all sink functions, return all position of parameters that in vulnerable
    #the second return value is the position of a fmt_string(None for none-fmt functions)
    #the third return value is the length limit of functions such as strncpy,snprintf(None for no-length-limit functions)
    def get_arg_list(self,func_name):
        if DEBUG:
            print(func_name)
        #some command insert funcs
        if func_name=="system" or func_name=='___system' or func_name=="popen" or func_name=="execve" or func_name=='bstar_system' or func_name=='twsystem':
            return [0],None,None
        if func_name=='_popen' or func_name=='_system' or func_name=='__system':
            return [0],None,None
        if func_name=='CsteSystem' or func_name=='cgi_deal_popen' or func_name=='ExecShell' or func_name=='exec_shell_popen' or func_name=='exec_shell_popen_str':
            return [0],None,None
        if func_name=='ExeCmd':
            return [1],None,None
        #the following args are not sure
        if func_name=='doSystembk' or func_name=='doSystem' or func_name=='COMMAND' or func_name=='_doSystembk'  or func_name=='_doSystem' or func_name=='_COMMAND':
            return [0],None,None
        if func_name=='fwrite':
            return [0,3],None,None
        if func_name=="sprintf":
            return [1],[1],None
        if func_name=='doSystemCmd' or func_name=='doShell':#can use fmt_str when executing
            return [0],[0],None
        if func_name=='_doSystemCmd' :
            return [0],[0],None
        if func_name=="strcpy" or func_name=="strcat":
            return [1],None,None
        if func_name=="memcpy":
            return [1],None,[2]
        if func_name=="snprintf":#Todo:add the check of n>len(dest)
            return [2],[2],[1]
        if func_name=="strncpy":#Todo:add the check of n>len(dest)
            return [1],None,[2]
        #Todo:add crypto misuse
        if DEBUG:
            print("function name not found",func_name)
        return [],None,None

    def get_vex_offset(self,project,reg):#turn a intuitive offset into a vex_offset which angr use, eg: trcpy(a,b), intuitive offset of (a,b) is (1,2), but vex_offset is (0,8)
        if len(_ordered_argument_regs_names[project.arch.name])<=reg:#Todo:fix stack params(but usually functions do not have too many arguments)
            return None
        return project.arch.registers.get(_ordered_argument_regs_names[project.arch.name][reg], None)[0]

    def get_vex_offsets_by_input_value(self,project,value):#turn the given offset set/list into vex_offset which angr use
        reg_vex_offsets=set()
        #if in upper function,we dont't need to convert again
        if type(value)==type(set()):
            if DEBUG:
                print("upper get vex_offset")
            reg_vex_offsets=value
        else:
            for reg_offset in value:
                vex_off=self.get_vex_offset(project,reg_offset)
                if vex_off is not None:
                    reg_vex_offsets.add(vex_off)
        return reg_vex_offsets
    
    def check_const_length_limit(self,project,current_func,current_call_addr,length_limit_arg,observe_point_op):
        if current_call_addr in self.length_limit_result.keys():#prune
            return self.length_limit_result[current_call_addr]
        try:#run reaching definition analyse
            rd = project.analyses.ReachingDefinitions(subject=current_func, 
                                                            func_graph=current_func.graph,
                                                            cc = current_func.calling_convention,
                                                            
                                                            observation_points= [("insn", current_call_addr , observe_point_op)],
                                                            dep_graph = dep_graph.DepGraph()
                                                            )
        except Exception as e:
            if DEBUG:
                print("error when running rd",current_call_addr,e)
            self.length_limit_result[current_call_addr]=True
            return True
        reg_vex_offsets=self.get_vex_offsets_by_input_value(project,length_limit_arg)#get the vex_offset of the interested argument
        if rd.observed_results != {}:
            # Cycle all over the results 
            for observed_result in rd.observed_results.items():
                #for reg_vex_offset in reg_vex_offsets:
                while len(reg_vex_offsets)>0:
                    reg_vex_offset=reg_vex_offsets.pop()
                    if DEBUG:
                        print("check argument",reg_vex_offset)
                    #reg_defs = observed_result[1].register_definitions.load(reg_vex_offset, size, endness=project.arch.register_endness)
                    reg_defs = observed_result[1].register_definitions.get_objects_by_offset(reg_vex_offset)#the use_def information of the argument
                    if reg_defs is None:
                        continue
                    if len(reg_defs)>1:
                        self.length_limit_result[current_call_addr]=False
                        return False#if the length limit comes from multi definitions, this limitation might be not strong enough
                    for reg_def in reg_defs: # the definition positions of the length limit argument
                            dataset = reg_def.data # the content of a length limit definition
                            for data in dataset:
                                if isinstance(data,int) and data < project.loader.main_object.min_addr:# the definition comes from a fixed int, and is not an address
                                    self.length_limit_result[current_call_addr]=True
                                    return True
        self.length_limit_result[current_call_addr]=False
        return False

    # the use_define analyse function, given the project and cfg
    # single_key: a path from source param to sink function, to be checked by use-def
    # output_dir: the path of output file
    # yield analyse: when false, disable yield analyse mode, which means stop analysing when source and sink is in a same function; when true, enable yield analyse, analyse all yielded paths together
    def check_use_define(self,project,bin_cfg,single_key,output_dir,yield_analyse=False):
        #the name of the sink_function
        sink_name=single_key[0]
        #the path from source to sink
        key_path=single_key[1]
        #a variable used to store the vex_offsets of the argumentss of a function that is influenced by sink
        #these vex_offsets will be parsed into the upper function to do further use_def check until it reached source param 
        need_parse_vex=None
        path_info_list=[]#only used when yield analyse, it stores the sink name and the complete sink path just use for output
        top_func_addr=None#only used when yield analyse, it stores the address of the top function
        if yield_analyse:
            path_info_list=key_path.pop(-1)
            need_parse_vex=key_path.pop(-1)#restore upper_vex result at the time we stop a analyse(when source and sink is in the same func) and decide to yield it
            top_func_addr=key_path[1]
        input_param=key_path.pop(-1)#the addrs of user input params(eg:password,gateway)
        if DEBUG:
            print("input param:",input_param)
        # as we search from sink to source, depth means the number of functions we have analysed
        # eg:funcA(contain ipaddr param)->funcB->system
        # then the analyse in funcB is in depth0(whether the param of system can reach the arguments of funB), analyse in funcA is in depth1(whether the param of system can reach ipaddr)
        depth=0
        #the sink reached the source
        key_sinked=False
        #   is_direct_return: used to check whether the sink function hit the source param directly, 
        #   eg: param="http_passwd";system(param), 
        #   in this case, sink directly hit source, but it is used as a fixed string, not user input
        #   eg2: str="http_passwd";param=webgetvar(str);system(param),
        #   in this case, sink did not directly hit source while there is a function call between them, therefore, the user input might could influence sink function
        is_direct_ret=False
        max_depth=int((len(key_path)-1)/2)
        while len(key_path)>2*depth+1:
            current_need_check_calls={}#this dictionary contains all of the instructions in the current function that can inflence sink, originally it's the address of the sink func
            upper_vex=set()#the vex_offset of the argumentss of the current_depth-1 function, which can influence sink
            current_refered_funcs=set()#if input param is in the current function(thus we can't prune it),and the function called itself(recurse),we use this flag to jump out, in order to avoid dead-loop
            is_fmt=None#whether the sink argument is a fmt_string
            length_limit_arg=None#whether we need to check the length limit argument of a sink function
            current_call_addr=key_path[2*depth]
            if DEBUG:
                print("analysing function",key_path[2*depth+1])
            is_direct_ret=True
            if depth==0 and not yield_analyse:#originally, analyse the dangerous parameters of a sink function, eg: arg0 of system()
                current_need_check_calls[current_call_addr],is_fmt,length_limit_arg=self.get_arg_list(sink_name)
                #current_need_check_calls[current_call_addr]=[2]
            else:#use upper_vex to continue analyse
                if yield_analyse and len(sink_name)>0:#if sink and source is originally in the same function, eg:ipaddr=webgetvar;sprintf("%s",ipaddr),we need to set the is_fmt and length_limit_arg to analyse them, if not, those flags should be cleared
                    tmp_vex,is_fmt,length_limit_arg=self.get_arg_list(sink_name)
                    if tmp_vex != need_parse_vex:
                        is_fmt = None
                        length_limit_arg = None
                current_need_check_calls[current_call_addr]=need_parse_vex
            if depth == max_depth and not yield_analyse:#yield the analyse of top func(the function containing sourse)
                return True,[input_param[0],current_call_addr,key_path[2*depth+1],current_need_check_calls[current_call_addr],sink_name]
            if current_call_addr in self.analysed_call.keys():#analysed before,skip it
                if depth < max_depth:#just reuse the analysed_before results
                    if DEBUG:
                        print("analysed before",hex(current_call_addr))
                    tmp_upper_vex=None
                    if depth != 0:#the format of analysed_call might be different when depth is or isnot 0, since for upper functions, we need to store the result for each different arguments
                        for tmp_need_parse_vex,tmp_upper_vex_inlist in self.analysed_call[current_call_addr]:
                            if tmp_need_parse_vex == need_parse_vex:
                                tmp_upper_vex=tmp_upper_vex_inlist
                                break
                    else:
                        tmp_need_parse_vex,tmp_upper_vex=self.analysed_call[current_call_addr][0]#but for sink function, the arguments that we are interested in is fixed
                    if tmp_upper_vex is not None:
                        upper_vex=tmp_upper_vex
                        need_parse_vex=upper_vex
                        if len(upper_vex)==0:#sink cannot reach the arguments of current function, so it also cannot reach source which is in the upper function
                            if DEBUG:   
                                print("sink unreachable")
                            return False,depth
                        depth+=1
                        continue
            try:
                current_func = bin_cfg.functions.get_by_addr(key_path[2*depth+1])
            except Exception as e:
                if DEBUG:
                    print("error when getting function",key_path[2*depth+1],e)
                    print("sink unreachable")
                with open("./unexpected_err_log","a") as f:
                    f.write("can't get func, may bug "+str(hex(key_path[2*depth+1])+'\n'))
                    #f.write(e)
                    f.write('\n')
                return False, depth-1
            #observation_points is an argument of angr's reaching definition API, the third parameter of the observation_points tuple infers OP_BEFORE(0)/OP_AFTER(1), if OP_BEFORE is set, angr do not consider delay slots
            observe_point_op = 0
            if project.arch.name == "MIPS32":#MIPS programs have delay slots
                observe_point_op = 1
            if length_limit_arg is not None:
                if self.check_const_length_limit(project,current_func,current_call_addr,length_limit_arg,observe_point_op):
                    return False,depth
            while len(current_need_check_calls)>0:
                key,value=current_need_check_calls.popitem()#key:instruction addr of a function_call, value: which argument of this call can influence sink
                if DEBUG:
                    print("check next")
                    print(hex(key),value)
                try:#run reaching definition analyse
                    rd = project.analyses.ReachingDefinitions(subject=current_func, 
                                                                    func_graph=current_func.graph,
                                                                    cc = current_func.calling_convention,
                                                                    observation_points= [("insn", key , observe_point_op)],
                                                                    dep_graph = dep_graph.DepGraph()
                                                                    )
                except Exception as e:
                    if DEBUG:
                        print("error when running rd",key,value,e)
                    continue
                rd_ddg_graph = rd.dep_graph
                # Instantiate the object that will walk back the dep_graph.
                rd_resolver = RD_Graph_Resolver(project, bin_cfg, rd_ddg_graph,input_param,path_info_list,top_func_addr,output_dir,is_direct_ret,self.enable_symbolic_check)
                reg_vex_offsets=self.get_vex_offsets_by_input_value(project,value)#get the vex_offset of the interested argument
                if rd.observed_results != {}:
                    # Cycle all over the results 
                    for observed_result in rd.observed_results.items():
                        #for reg_vex_offset in reg_vex_offsets:
                        while len(reg_vex_offsets)>0:
                            reg_vex_offset=reg_vex_offsets.pop()
                            if DEBUG:
                                print("check argument",reg_vex_offset)
                            #reg_defs = observed_result[1].register_definitions.load(reg_vex_offset, size, endness=project.arch.register_endness)
                            reg_defs = observed_result[1].register_definitions.get_objects_by_offset(reg_vex_offset)#the use_def information of the argument
                            if reg_defs is None:
                                continue
                            for reg_def in reg_defs:
                                reg_is_fmt=None
                                if is_fmt is not None:
                                    for reg in is_fmt:
                                        if self.get_vex_offset(project,reg)==reg_vex_offset:
                                            reg_is_fmt=reg
                                            break
                                # recurse through the result of a use-def check, resolve the use-def of the local parameters, find the functions & function_argument that can influence the sink param
                                # if found the definition of a fmt_string, also return the position of its %s param through "extra", which is used for further use-def check 
                                functions,uppers,extra = rd_resolver.resolve_use_def(reg_def,reg_is_fmt)
                                
                                if functions is None and uppers is None and extra is None:#this key already sinked
                                    key_sinked=True
                                    break
                                if DEBUG:
                                    print("function:",functions)
                                    print("upper",uppers)
                                    print("fmt get extra args:",extra)
                                # analyse the %s arguments of a fmt_string call
                                while len(extra)>0:
                                    item=extra.pop()
                                    vex_off=self.get_vex_offset(project,item)
                                    if vex_off is not None:
                                        reg_vex_offsets.add(vex_off)
                                #if the return value of a function can inflence sink, then all its arguments can influence sink
                                #!!!:this assumption may cost to much time, it can also be changed, but changing it may cause false positive
                                for func,arity in functions.items():
                                    if func not in current_refered_funcs:
                                        current_refered_funcs.add(func)
                                    else:
                                        continue
                                    arg_list=[]
                                    for i in range(arity):
                                        arg_list.append(i)
                                    current_need_check_calls[func]=arg_list
                                for upper in uppers:
                                    upper_vex.add(upper)
                            if key_sinked:
                                break
                        if key_sinked:
                            break
                        if is_direct_ret:#after sink reached a non-source function, it is currently not a direct return
                            is_direct_ret=False
                            rd_resolver.clear_direct_ret_tag()
                    if key_sinked:
                        break
            if key_sinked:
                return True,depth
            if DEBUG:
                print("finish analysing function:",key_path[2*depth+1],"input args sinked:",upper_vex)
            if current_call_addr not in self.analysed_call.keys():
                self.analysed_call[current_call_addr]=[]
            self.analysed_call[current_call_addr].append((need_parse_vex,upper_vex))
            need_parse_vex=upper_vex
            if len(upper_vex)==0:
                if DEBUG:   
                    print("sink unreachable")
                return False,depth
            depth+=1
        #when reached here, the sink have influenced some arguments of the top function, and we need to return it, thus, change depth into a structure
        #this change will only influence library function summarize, since when yield_analyse=False, the function will never reach here, and when yield_analyse in the border binary,we never use any return value
        return False,[depth,need_parse_vex]