from use_define.utils import SINKS,ALLOWED_CHARS
from use_define.use_def_checker import Use_Def_Checker
from use_define.lib_func_summarizer import Lib_global_info,Lib_Function_Summarizer
from use_define.front_analyse_expansion import Front_analyse_expansion
import angr 
import time
import string
DEBUG = False


class Xref_Finder_Usedef():
    # if a function's all sub-functions can't reach any sink or can reach sink but the sink's parameter can't reach the function's input parameters, regard it as a safe function
    globalSafeFuncs=[]
    # speed up by yielding the use-def analyse in the same function:
    # if there are many input parameters in a function, save it's path to the sink in the same function in order to analyse them together later
    # eg: gateway -> strcpy & ipaddr -> strcpy, if don't yield analyse, we will analyse twice, but if yield, just analyse parameter of strcpy once to check whether it can reach this two input params
    globalYieldAnalyseCalls={}
    # save calls that is analysed by use-def to aviod repeating analyse
    analysed_call={}
    # if the length limit of a strncpy or a snprintf is fixed, it is usually not able to trigger a buffer overflow vulnerability, 
    # this dictionary contains the analyse result of the length limit, which is used for prune
    length_limit_result={}
    def __init__(self, project, cfg, param_file,output_dir,xref_API="ghidra",enable_symbolic_check=True):
        self.project = project
        self.cfg = cfg
        self.param_file=param_file
        self.output_dir=output_dir
        self.globalSafeFuncs=[]
        self.globalYieldAnalyseCalls={}
        self.analysed_call={}
        self.length_limit_result={}
        self.xref_API=xref_API
        self.enable_symbolic_check=enable_symbolic_check
    
    #search the xref of the given input parameters, judge whether they can reach a sink
    def search_xref(self,search_API=False):
        paramTargets = set(open(self.param_file).read().strip().split())
        if DEBUG:
            print(paramTargets)
        #get the address of all strings in a binary
        str_info = self.get_bin_strings(self.project.loader.main_object.binary)
        t = time.time()
        #print(self.project.loader.main_object.binary)
        key_addresses=self.find_key_address(str_info,paramTargets)
        xref_struct={}
        use_ghidra=True
        if self.xref_API=="angr":
            use_ghidra=False
        if use_ghidra:
            xref_struct=self.get_xref_by_ghidra()
        else:
            for (str_offset,str_value) in key_addresses:
                xrefs = self.project.kb.xrefs.get_xrefs_by_dst(str_offset)
                xref_struct[str_offset]=[]
                for xref in xrefs:
                    xref_struct[str_offset].append(xref.ins_addr)
        front_expansion=Front_analyse_expansion(self.project,self.cfg,xref_struct)
        xref_struct=front_expansion.expand_keywords()
        #search xref by API
        #self.searchAPIByAddrSet(API_set)
        #search xref by key addresses
        for string_addr in xref_struct.keys():
            xrefs = xref_struct[string_addr]
            for xref in xrefs:
                self.findSinkPath(xref)
        '''
        if use_ghidra:
            print("before_expand",len(key_addresses))
            print("after_expand",len(key_addrs))
            new_key_list=[]
            for (str_offset,str_value) in key_addrs:
                new_key_list.append(str_value)
            new_keys=" ".join(new_key_list)
            f=open(self.param_file,"w")
            f.write(new_keys)
            f.close()
            #xref_struct=self.get_xref_by_ghidra()
        else:
            self.searchParams(key_addrs)
        '''
        #yield analyse
        if DEBUG:
            print(self.globalYieldAnalyseCalls)
        self.yieldAnalyse()
        t = time.time() - t
        print('Time Cost:', t)

    #due to the limitations of the angr xref API, this module analyse the xref in ghidra in order not to miss some sources
    def get_xref_by_ghidra(self):
        import subprocess
        import json
        import os
        ghidra_path='/'.join(self.output_dir.split('/')[:-1])+"/ghidra_xref"
        ghidra_project_name=self.project.loader.main_object.binary.split('/')[-1]
        ghidra_rep = ghidra_path + '/' + ghidra_project_name + ".rep"
        if not os.path.isdir(ghidra_path):
            os.makedirs(ghidra_path)
        ghidra_args = [
            os.getcwd()+'/ghidra/support/analyzeHeadless', ghidra_path, ghidra_project_name,
            '-postscript', os.getcwd()+'/use_define/ghidra_xref.py', self.param_file, ghidra_path+'/xref_out'
            '-scriptPath', os.getcwd()+'/use_define/'
        ]
        if os.path.exists(ghidra_rep):
            ghidra_args += ['-process', os.path.basename(self.project.loader.main_object.binary)]
        else:
            ghidra_args += ['-import', "'"+self.project.loader.main_object.binary+"'"]
        try:
            p = subprocess.Popen(ghidra_args)
            p.wait()
        except:
            print("ghidra xref finding error")
            return {}
        xref_result=json.loads(open(ghidra_path+'/xref_out-scriptPath').read())
        print("ghidra_xref_result_length",len(xref_result))
        #os.remove(ghidra_path+'/xref_out-scriptPath')
        return xref_result
        

    def yieldAnalyse(self):
        for call_addr in self.globalYieldAnalyseCalls.keys():#load the yielded informations and continue their analyse
            func_addr=self.globalYieldAnalyseCalls[call_addr][0]#the address of the to_be_analysed function
            path_info_list=self.globalYieldAnalyseCalls[call_addr][2]#the name of the sink function and the sink path used for output
            tmp_sink_name=""
            for sink_name_item,sink_path_item in path_info_list:
                if len(sink_path_item)==1:
                    #if sink and source is originally in the same function, eg:ipaddr=webgetvar;sprintf("%s",ipaddr),we need to set the is_fmt flag to be true, if not, the flag should be cleared
                    #therefore we need to parse the sink name into the use def analyser, otherwise sink name is not used, simply set it to be ""
                    tmp_sink_name=sink_name_item
                    break#for all path that len==1,the sink name should be the same since the call addr to the sink is same
            arg_and_ref_list=self.globalYieldAnalyseCalls[call_addr][1]#which argument of current call_addr can reach a sink, which refs in this funcion might inflence the argument
            for argset,refaddrs in arg_and_ref_list:
                tmp_key=[tmp_sink_name,[call_addr,func_addr,refaddrs,argset,path_info_list]]
                use_def_checker=Use_Def_Checker(self.analysed_call,self.length_limit_result,self.enable_symbolic_check,DEBUG)
                sinked,depth=use_def_checker.check_use_define(self.project,self.cfg,tmp_key,self.output_dir,yield_analyse=True)
            pass
        pass

    # filter the keywords that is referenced by cmp APIs that can never contain user input
    def API_is_cmp(self,instr_addr):
        block=self.cfg.model.get_any_node(instr_addr)
        while block is None:
            instr_addr-=4
            block=self.cfg.model.get_any_node(instr_addr)
        try:
            callee=block.successors[0].addr
            callee_name=self.cfg.functions.get_by_addr(callee).name
            if "cmp" in callee_name or "cpy" in callee_name or "match" in callee_name or "print" in callee_name or "ntoa" in callee_name or "dup" in callee_name or "put" in callee_name or "strstr" in callee_name or "err" in callee_name or "md5" in callee_name or "log" in callee_name or "int" in callee_name or "strlen" in callee_name:#or "open" in callee_name, may opening a file be a source input? 
                return True
        except:
            pass
        return False
    
    #search all xrefs of all input_params, for each xref, try to find whether it can reach a sink
    def searchParams(self,key_addrs):
        for (str_offset,str_value) in key_addrs:
            xrefs = self.project.kb.xrefs.get_xrefs_by_dst(str_offset)
            if len(xrefs)==0:
                continue
            if DEBUG:
                print(xrefs)
            for xref in xrefs:
                if self.API_is_cmp(xref.ins_addr):
                    continue
                if DEBUG:
                    print(xref.ins_addr)
                self.findSinkPath(xref.ins_addr)

    #search all xrefs of all user_input_related APIs when given their names, for each reference of an API, try to find whether it can reach a sink
    def searchAPIByName(self,API_list):
        for func_addr, func in self.cfg.kb.functions.items():
            if func.name in API_list:
                func_node = self.cfg.model.get_any_node(func.addr)
                func_pred_nodes = func_node.predecessors#the node of the basic block contaning the caller of the API
                #search all xrefs of all API, for each xref, try to find whether it can reach a sink
                for pred_node in func_pred_nodes:
                    pred_block=pred_node.block
                    #find whether this call can reach sink
                    if DEBUG:
                        print("API refed at",pred_block.instruction_addrs[-1])
                    self.findSinkPath(pred_block.instruction_addrs[-1])

    #search all xrefs of all user_input_related APIs when given an API set generated by front_analyse_expansion.py, for each reference of an API, try to find whether it can reach a sink
    def searchAPIByAddrSet(self,API_set):
        for api_addr,reg_name in API_set:
            try:
                api_func=self.cfg.functions.get_by_addr(api_addr)
                func_node = self.cfg.model.get_any_node(api_func.addr)
                func_pred_nodes = func_node.predecessors#the node of the basic block contaning the caller of the API
                #search all xrefs of all API, for each xref, try to find whether it can reach a sink
                for pred_node in func_pred_nodes:
                    pred_block=pred_node.block
                    #find whether this call can reach sink
                    if DEBUG:
                        print("API refed at",pred_block.instruction_addrs[-1])
                    self.findSinkPath(pred_block.instruction_addrs[-1])
            except:
                print("API get function error")

    #find whether a reference to source string can reach a sink function
    def findSinkPath(self,refaddr):
        currentSinkReachableFuncs=[]#while in one dfs,check all paths to confirm the final global_safe_func, if a function can reach a sink, it is not global_safe
        startFunc = None
        def searchStartFunc(refaddr, start=None):#search the function that contains refaddr
            try:
                for func_addr, func in self.cfg.kb.functions.items():
                    if func_addr > refaddr:
                        continue
                    call_sites = func.get_call_sites()
                    for basic_block in func.blocks:
                        if basic_block.addr <= refaddr and basic_block.size+basic_block.addr >= refaddr:
                            return func,call_sites
                if DEBUG:
                    print("ref not in callsites")
                with open("./unexpected_err_log","a") as f:
                    f.write("ref not in callsites: "+str(hex(refaddr)+'\n'))
            except:
                print("search start func error",refaddr,type(refaddr))
            return None,None

        # path: a argument that stores the list of the path from source to sink, format:[(addr of call, callee), (addr of call, callee), ...]
        def dfs(func, call_sites, path):
            if func.name in SINKS and len(path):
                #return True#test the speed of dfs
                if DEBUG:
                    print(func.name,path)
                # parsed the path into the format that use_define analyse can accept(since we need to analyse from sink to source, but orig path is from source to sink)
                check_path=[]
                i=len(path)-1
                addr, callee = path[i][:2]
                check_path.append(addr)
                while(i>0):
                    i-=1
                    addr, callee = path[i][:2]
                    check_path.append(callee)
                    check_path.append(addr)
                check_path.append(startFunc.addr)
                check_path.append([refaddr])
                tmp_key=[func.name,check_path]
                #check use_define, after adding yield analyse, sinked does not means source reached sink, it only means source MIGHT reach sink, as they are in a same function, and should analyse later(yield it)
                #depth:if sink can't reached source, in which depth it failed to reach upper function(a information used to Prune)
                #eg: funcA->funB->funC->sink,sink can reach arguments of funC, but can't reach arguments of funcB, so depth is 0
                use_def_checker=Use_Def_Checker(self.analysed_call,self.length_limit_result,DEBUG)
                sinked,depth=use_def_checker.check_use_define(self.project,self.cfg,tmp_key,self.output_dir)
                if DEBUG:
                    print(sinked,depth)
                key_path=tmp_key[1]
                if DEBUG:
                    print(key_path)
                if sinked:
                    #now it returns [ref_addr,current_call_addr,function_containning_calladdr,args,sinkname] as depth, as we need to save the analyse information for yield analysing
                    if depth[1] not in self.globalYieldAnalyseCalls.keys():
                        self.globalYieldAnalyseCalls[depth[1]]=[depth[2],[],[]]
                    path_info_list=self.globalYieldAnalyseCalls[depth[1]][2]
                    #as enabled yield analyse, the analyse of different input param may reach the same sink with the same path, and as we will print every sink path for every sinkable user input at last(the path might be different for sink path in libraries), this might cause repeating output
                    #therefore, skip the same path in the path_info_list
                    path_refed=False
                    for sink,orig_path in path_info_list:
                        if path==orig_path:
                            path_refed=True
                            break
                    if not path_refed:
                        path_info_list.append((depth[4],path))#add sink name and sink path information for output
                    argset_refered=False
                    for argset,refaddrs in self.globalYieldAnalyseCalls[depth[1]][1]:
                        if argset==depth[3]:
                            argset_refered=True
                            refaddrs.append(depth[0])
                            break
                    if not argset_refered:
                        self.globalYieldAnalyseCalls[depth[1]][1].append((depth[3],[depth[0]]))
                    depth=int((len(key_path)-1)/2)#for all function except the top function, they are all sink_reachable and not global safe
                #for all functions that sink can reach it, store it as it is not global_safe
                depth-=1        
                while depth>=0:
                    if key_path[2*depth+1] not in currentSinkReachableFuncs:
                        currentSinkReachableFuncs.append(key_path[2*depth+1])
                    depth-=1
                return True
            #sometimes a user-input keyword may be found as a fixed argument of the imp function call(eg: set_enable():a1="enabled",call imp_set_enable())
            # (in this case, it use the fixed string as a argument, which do not store real user input and is unsinkable),to avoid this state, ensure len(path)>0
            if func.is_plt and len(path):
                #it's a library import function
                lib_info_instance=Lib_global_info()
                recurse_func_summary=lib_info_instance.get_function_summary(func.name)#if an import function is called, get its function summary
                if recurse_func_summary is None:#lazy binding: generate function summary for the function
                    func_summarizer=Lib_Function_Summarizer(self.project.loader.requested_names,func.name)
                    func_summarizer.generate_func_summary()
                    recurse_func_summary=lib_info_instance.get_function_summary(func.name)
                if recurse_func_summary is not None:#if it's still None, it means after lazy binding, we still cannot generate the function summary, most likely, the function is in a library that can't be found under the fs path
                    for (sinkable_arg_set,partial_path_info) in recurse_func_summary:#each item means a sink path from the target funtion to a sink function, if the import function is safe, then the function summary is an empty list
                        #consider the sinkable import function as a sink function, analyse the use define from the function to the function the user_input is in(as we enabled yield analyse)
                        # parsed the path into the format that use_define analyse can accept(since we need to analyse from sink to source, but orig path is from source to sink)
                        
                        #reuse the processing method of yield analyse since we need to continue an analyse with the given call address and arg set
                        #as we need to reuse yield_analyse=True to set the need_check_arguments of the interested library function, by setting the input parameter into an useless address, the analyse will just stop until it reached the max depth
                        #however, we should now store result for yield analysing, we need to limit the max_depth to ensure that the analyse will stop when sink and source are in the same function
                        #therefore, delete the first element of path to set new_max_depth=old_max_depth-1, and since the use_define analyse need at least len(path)!=0, if len(path)==1, just skip analyse
                        returned_argset=None
                        if len(path)>1:
                            #[(call_to_funA,funA)(call_to_sink,sink)]
                            tmp_path=path[1:]
                            check_path=[]
                            i=len(tmp_path)-1
                            addr, callee = tmp_path[i][:2]
                            check_path.append(addr)
                            while(i>0):
                                i-=1
                                addr, callee = tmp_path[i][:2]
                                check_path.append(callee)
                                check_path.append(addr)
                            check_path.append(path[0][1])#the end of the analyse should be the function that is called by the start_function
                            #therefore, if the sink did not reach the arguments of the input parameter of the function that is called by the start_function, the returned depth should be maxdepth, if it reached the arguments, then it's depth should be maxdepth+1 and it will reach the last "return" of use_def_checker.check_use_define
                            check_path.append([0x1])#useless input parameter, ensure that it won't be reached
                            tmp_sink_name,tmp_partial_path=partial_path_info[0]#the name of the sink function and the path from summarised func to sink which is required for the output of yield-analyse, actually unused here because the source here will never be reached
                            argset=sinkable_arg_set#which argument of current call_addr can reach a sink
                            check_path.append(argset)
                            check_path.append(tmp_partial_path)
                            tmp_key=[tmp_sink_name,check_path]
                            #check use def, similiar with the condition when func.name in sink
                            use_def_checker=Use_Def_Checker(self.analysed_call,self.length_limit_result,DEBUG)
                            sinked,depth=use_def_checker.check_use_define(self.project,self.cfg,tmp_key,"",yield_analyse=True)#since the refaddr is unreachable,the output directory is actually not used
                            key_path=tmp_key[1]
                            if type(depth)==list:#sink and source are in the same function, the path might be sinkable
                                depth,returned_argset=depth
                            #for all functions that sink can reach it, store it as it is not global_safe
                            depth-=1        
                            while depth>=0:
                                if key_path[2*depth+1] not in currentSinkReachableFuncs:
                                    currentSinkReachableFuncs.append(key_path[2*depth+1])
                                depth-=1
                        else:#if len(path)==1, the start function directly called an import function, we simply don't need any use_define analyse, the returned argset should simply be the argset of the library function
                            returned_argset=sinkable_arg_set
                        if returned_argset is not None:#if argset is not none, we found a paritial path that may be sinkable
                            #store the information for yield analyse
                            call_addr_from_top_func=path[0][1]#the call that the current analyse stop at, which is the call in the top function, save it as we need to recover it in yield analyse
                            top_func_addr=startFunc.addr
                            if call_addr_from_top_func not in self.globalYieldAnalyseCalls.keys():
                                self.globalYieldAnalyseCalls[call_addr_from_top_func]=[top_func_addr,[],[]]
                            path_info_list=self.globalYieldAnalyseCalls[call_addr_from_top_func][2]
                            #combine the path from sink to the sinkable import function and the path from the sinkable import function to the top function
                            for sink_name,partial_path in partial_path_info:
                                combined_path=path+[(0xffffff,0xffffff)]+partial_path#after combining, the path is [...(call_to_sinkable_imp_func,sinkable_imp_func),HERE IS THE COMBINE POINT (call_in_the_sinkable_imp_func,callee_func)...(call_to_sinkfunc,sinkfunc)]
                                path_info_list.append((sink_name,combined_path))#add the sink name and sink path to the corresponding arg set
                            argset_refered=False
                            for argset,refaddrs in self.globalYieldAnalyseCalls[call_addr_from_top_func][1]:
                                if argset==returned_argset:
                                    argset_refered=True
                                    refaddrs.append(refaddr)
                                    break
                            if not argset_refered:
                                self.globalYieldAnalyseCalls[call_addr_from_top_func][1].append((returned_argset,[refaddr]))
                    return True
                return False#the function summary is None, we can't find any sink under this import function, therefore regard this function as an unsinkable function
            #if a function is global_safe, we don't need to analyse again
            if func.addr in self.globalSafeFuncs and func.addr != startFunc.addr:#ensure it is not start_func(as sink in startfunc may can reach source as they are in the same function)
                return False
            sinkReached = False
            # dfs search all calls in a function recursely, until we find a sink
            for call_site in call_sites:
                basic_block = self.project.factory.block(call_site)
                if basic_block:
                    callee=self.cfg.model.get_any_node(basic_block.addr).successors[0].addr#the seccessor is the callee function
                    if DEBUG:
                        print(callee)
                    if callee in [x[1] for x in path] + [func.addr]:#prevent dead loop
                        continue
                    callee_func=None
                    for tmp_func_addr, tmp_func in self.cfg.kb.functions.items():
                        if callee==tmp_func_addr:
                            callee_func=tmp_func
                            break
                    if DEBUG:
                        print("callee_func",callee_func)
                    if callee_func == None:
                        continue
                    call_addr=basic_block.instruction_addrs[-1]
                    #a node of path is in the form of (call_addr,callee,sinked)
                    #dfs, jump into the callee_function to continue analyse
                    sinkReached = dfs(callee_func, callee_func.get_call_sites(), path + [(call_addr, callee, False)]) or sinkReached
            #prune
            if not sinkReached:#all callsites of this function cannot reach sinks
                #case1:source can't reach any sinks
                if func.addr not in self.globalSafeFuncs:
                    self.globalSafeFuncs.append(func.addr)
            if func.addr not in currentSinkReachableFuncs and func.addr != startFunc.addr:
                #case2:all sinks in the sub_funcs all cannot reach current func
                #added func.addr != startFunc.addr, because after adding yield analyse, we are not sure whether the startFunction's arguments can reach sink
                if func.addr not in self.globalSafeFuncs:
                    self.globalSafeFuncs.append(func.addr)
            return sinkReached

        startFunc,call_sites=searchStartFunc(refaddr)
        if startFunc==None:
            return False
        sinkReached = dfs(startFunc, call_sites, [])
        return sinkReached
    
    #get the address of the given input parameters
    def find_key_address(self,str_info,paramTargets):
        if DEBUG:
            print("paramTargets",paramTargets)
        key_addrs=[]
        for i, param in enumerate(paramTargets):
            key_addrs+=self.get_string_addrs(param,str_info)#get the address of the given input parameters
        return key_addrs
    
    #get the address of the given input parameters(parsed by param target_str)
    def get_string_addrs(self, target_str, str_info):    
        tmp = [x for x in str_info if target_str in x[0]]
        info = []
        # if we find the target_string, return itself and its address
        for strval,off in tmp:
            if target_str != strval:# filter the sub_strs that is reused,eg:wan_iptv_interface,and some xrefs use sub_str "iptv_interface"
                index=strval.find(target_str)
                if index > 0 and strval[index-1] in ALLOWED_CHARS and index+len(target_str)==len(strval):
                    off+=index
                else:
                    continue
            info.append((target_str,off))
        return [(self.project.loader.main_object.min_addr + off,target_str) for target_str, off in info]

    #get the address of all strings in a binary
    def get_bin_strings(self,filename):
        with open(filename, "rb") as f:
            results = []
            last_off = None
            off = 0
            t_str = ""

            for c in f.read():
                char = chr(c)
                if char in string.printable and char != '\n':
                    last_off = off if not last_off else last_off
                    t_str += char
                else:
                    if t_str and len(t_str) > 1:
                        results.append((t_str, last_off))
                    last_off = None
                    t_str = ""
                off += 1
        return results

def sink_check(bin_path,param_file,output_dir,xref_API="ghidra",enable_symbolic_check=True):#given a binary and a file containing the name of input parameters(eg:password ipv6_gateway), check the sink and print the result to the output dir
    project = angr.Project(bin_path, auto_load_libs=False)
    bin_cfg = project.analyses.CFG(resolve_indirect_jumps=True, cross_references=True, 
                                force_complete_scan=False, normalize=True, symbols=True)
    xref_finder=Xref_Finder_Usedef(project,bin_cfg,param_file,output_dir,xref_API,enable_symbolic_check)
    xref_finder.search_xref()

def test_xref():
    #sink_check("./redfish","./Prar_simple.result","./TAISHAN_596_redfish")
    sink_check("./httpd_r7000","./httpd_r7000.result","./xref_test_output_1025")
    #sink_check("use_define/eapd","use_define/eapd.result","./xref_test_output_eapd")
#test_xref()
