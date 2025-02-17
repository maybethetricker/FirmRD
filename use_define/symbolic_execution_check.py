import angr
import claripy
from use_define.utils import _ordered_argument_regs_names
import time
import os
import psutil
import gc
import threading
import multiprocessing
DEBUG=False
# a timeout decorator using multiprocessing, the main process won't be killed even if segment fault appear in child process
def time_out(interval, callback=None):
    def decorator(func):
        def wrapper(*args, **kwargs):
            p =multiprocessing.Process(target=func, args=args, kwargs=kwargs)
            p.start()
            p.join(interval)  # wait for interval seconds
            if p.is_alive() and callback:
                p.terminate()
                return threading.Timer(0, callback).start()  # call callback function
            else:
                p.terminate()
                return
        return wrapper
    return decorator

class Symbolic_Execution_Checker():
    skip_functions=["nvram_safe_get"]
    # since angr.step may cause timeout, and it may also trigger segment fault when using timeout alarm to stop it
    # we use multiprocess method to set timeout, and parses return value with global variables
    timeout_returnvar=0
    found_stash=[]

    def __init__(self):
        self.clear_multiprocess_globals()

    # initialize the shared variables in multi_processing before calling multiprocess calls
    def clear_multiprocess_globals(self):
        self.timeout_returnvar=multiprocessing.Value("b",0)
        self.found_stash=multiprocessing.Manager().list()

    def searchStartFunc(self,refaddr,cfg, start=None):#search the function that contains refaddr
        try:
            for func_addr, func in cfg.kb.functions.items():
                if func_addr > refaddr:
                    continue
                call_sites = func.get_call_sites()
                for basic_block in func.blocks:
                    if basic_block.addr <= refaddr and basic_block.size+basic_block.addr >= refaddr:
                        return func,call_sites
            with open("./unexpected_err_log","a") as f:
                f.write("ref not in callsites: "+str(hex(refaddr)+'\n'))
        except:
            print("search start func error",refaddr,type(refaddr))
        return None,None

    def find_instructon_after_call(self,cfg,current_func,instr_addr):# find the instruction after an API is called
        block=cfg.model.get_any_node(instr_addr)
        while block==None and instr_addr>=current_func.addr:
            instr_addr-=4
            block=cfg.model.get_any_node(instr_addr)
        output=[]
        for succ in cfg.graph.successors(block):
            if current_func.addr > succ.addr:
                    continue
            for basic_block in current_func.blocks:
                if basic_block.addr <= succ.addr and basic_block.size+basic_block.addr >= succ.addr:
                    output.append(succ.addr)
                    break
        return output


    @time_out(120)
    def angr_step(self,simgr,end,timeout,step_limit=200):
        simgr.stashes['avoided'] = []
        simgr.stashes['bad'] = []
        simgr.stashes['unconstrained'] = []
        step = 0
        start = time.time()
        pid = os.getpid()
        p = psutil.Process(pid)
        try:
            while simgr.active:
                memory_use=p.memory_full_info().uss/1024/1024/1024 #the memory usage of the program
                if memory_use>6: 
                    if DEBUG:
                        print("memory out!!!",memory_use)
                    # if the max memory usage is greater then 6G(considering the memory cost of use-define prune info storage at the same time)
                    # skip the exploration
                    self.timeout_returnvar.value=-1
                    return
                simgr.step()
                elapsed_time = time.time() - start
                simgr.move("active", "deadended", filter_func=lambda s: s.addr == 0x41414141)
                simgr.move("active", "found", filter_func=lambda s: s.addr in end)
                step += 1
                if elapsed_time > timeout:
                    self.timeout_returnvar.value=-1
                    return
                if step > step_limit:
                    self.timeout_returnvar.value=-1
                    return
                if len(simgr.stashes['found'])>0:
                    if DEBUG:
                        print("found")
                    for stage in simgr.stashes['found']:
                        self.found_stash.append(stage)
                    return
        except Exception:
            pass
        return

    # symbolic explore from start to end and set user input to be "a;"+'a'*0x1000, check whether the vulnerable arguments of sink functions is indeed influenced by the input
    def symbolic_explore(self,project,cfg,start,end,sink_name):
        # delete the old structures which may occupy too much memory
        gc.collect()
        # first, execute from the function start point to the input point in order to get the initialize values of the registers and some memory variables
        func,call_sites=self.searchStartFunc(start,cfg)
        if func==None:
            return -1
        begin_state=project.factory.blank_state(addr=func.addr, remove_options={angr.options.LAZY_SOLVES})

        begin_state.stack_push(0x41414141)#we do not need to symbolic explore to the outer function
        # in angr.step method, the state address may skip the address inside a basic block, so it's better to use the basic block after it
        user_input_node=self.find_instructon_after_call(cfg,func,start)
        simgr = project.factory.simgr(begin_state)
        simgr.use_technique(angr.exploration_techniques.Veritesting())
        #timeout = angr.exploration_techniques.Timeout(600)
        #simgr.use_technique(timeout)
        self.hook_symbols(project)
        if DEBUG:
            print("exploring to user_input instruction")
        try:
            self.angr_step(simgr,user_input_node,60,100)
            is_timeout=self.timeout_returnvar.value
        except:
            if DEBUG:
                print("explore error")
            is_timeout=-1
        init_arg_state=None
        if len(self.found_stash) == 0: # the control flow cannot reach the input point, which is usually imposible, so we regard it as a kind of timeout
            is_timeout=-1
        if is_timeout==-1: #time out, some functions might be too complex
            # try again using a blank state as the user_input state, although some initial value may not match
            
            init_arg_state=project.factory.blank_state(addr=user_input_node[0], remove_options={angr.options.LAZY_SOLVES})
            init_arg_state.stack_push(0x41414141)#we do not need to symbolic explore to the outer function
        else:
            init_arg_state=self.found_stash[0]
        input_state=init_arg_state
        sinkable_input="a;"+'a'*0x1000
        input_state.memory.store(0x60000000, sinkable_input)
        if project.arch.name == 'ARMEL':
            input_state.regs.r0 = 0x60000000
        if project.arch.name == 'AARCH64':
            input_state.regs.x0 = 0x60000000
        if project.arch.name == 'MIPS32':
            input_state.regs.v0 = 0x60000000
        if DEBUG:
            print("exploring to dst")
        del simgr # delete the old simgr which may occupy too much memory
        gc.collect()
        self.clear_multiprocess_globals()
        simgr = project.factory.simgr(input_state)
        simgr.use_technique(angr.exploration_techniques.Veritesting())
        try:
            #we need to execute to the state after executing the sink function to check the result of the function call
            end=self.find_instructon_after_call(cfg,func,end)
            self.angr_step(simgr,end,120,120)
            is_timeout=self.timeout_returnvar.value
        except:
            if DEBUG:
                print("explore error")
            del simgr # delete the old simgr which may occupy too much memory
            gc.collect()
            return -1
        if is_timeout==-1: #time out, some functions might be too complex
            del simgr # delete the old simgr which may occupy too much memory
            gc.collect()
            return -1 
        if len(self.found_stash) == 0: # the control flow is unreachable
            del simgr # delete the old simgr which may occupy too much memory
            gc.collect()
            return 0
        else:
            for sim_stage in self.found_stash:
                if sink_name=='fwrite' or sink_name=="sprintf" or sink_name=="strcpy" or sink_name=="strcat" or sink_name=="memcpy" or sink_name=="snprintf" or sink_name=="strncpy":
                    #for arg in _ordered_argument_regs_names[project.arch.name]:
                    #check the dest buffer in order to better check the length limit
                    arg=_ordered_argument_regs_names[project.arch.name][0]
                    #check the end of the buffer to make sure the buffer is not cutted 
                    reg_bv=sim_stage.memory.load(getattr(sim_stage.regs,arg)+0x9f0,project.arch.bits//8)
                    #print(sim_stage.solver.eval(reg_bv))
                    if sim_stage.solver.eval(reg_bv)==0x61616161:# buffer overflow has happend
                        del simgr # delete the old simgr which may occupy too much memory
                        gc.collect()
                        return 1
                    else:#sometimes the strcpy function may be executed with errors, in fact, when the source is sinked, the sink should also be sinked
                        if sink_name=="strcpy" or sink_name=="strcat":
                            arg=_ordered_argument_regs_names[project.arch.name][1]
                            reg_bv=sim_stage.memory.load(getattr(sim_stage.regs,arg)+0x9f0,project.arch.bits//8)
                            if sim_stage.solver.eval(reg_bv)==0x61616161:# buffer overflow has happend
                                del simgr # delete the old simgr which may occupy too much memory
                                gc.collect()
                                return 1
                        if sink_name=="sprintf":
                            for i in range(3):
                                arg=_ordered_argument_regs_names[project.arch.name][i+1]
                                reg_bv=sim_stage.memory.load(getattr(sim_stage.regs,arg)+0x9f0,project.arch.bits//8)
                                if sim_stage.solver.eval(reg_bv)==0x61616161:# buffer overflow has happend
                                    del simgr # delete the old simgr which may occupy too much memory
                                    gc.collect()
                                    return 1
                else:#for command injection functions, we  make sure ';' is not filtered as an example(regardless of unimplicate filtering which onlt filters ';')
                    for arg in _ordered_argument_regs_names[project.arch.name]:
                        reg_bv=sim_stage.memory.load(getattr(sim_stage.regs,arg),project.arch.bits//8)
                        if sim_stage.solver.eval(reg_bv)==0x613b6161:
                            del simgr # delete the old simgr which may occupy too much memory
                            gc.collect()
                            return 1
        del simgr # delete the old simgr which may occupy too much memory
        gc.collect()
        return 0            
    
    def hook_symbols(self,project):
        #hook unimportant functions
        #for function in skip_functions: 
        #    project.hook_symbol(function,unimportant_funtion())
        #hook strtok since it do not make vulnerability unuseable, but need the input string to contain certain format
        project.hook_symbol("strtok",strtok_hook())
        #sometimes, the origin strcpy implement of angr may result in errors
        project.hook_symbol("strcpy",strcpy_hook())
    
class unimportant_func_hook(angr.SimProcedure):
    def run(self):
        return 0

class strtok_hook(angr.SimProcedure):
    def run(self,a,b):
        return a
    
class strcpy_hook(angr.SimProcedure):
    def run(self,a,b):
        a=b
        return a

def test():
    #project= angr.Project("httpd_c5v2",auto_load_libs=False)
    #project= angr.Project("cstecgi.cgi_A7000",auto_load_libs=False)
    project= angr.Project("httpd_r7000",auto_load_libs=False)
    #project= angr.Project("httpd_mr6400",auto_load_libs=False)
    bin_cfg = project.analyses.CFG(resolve_indirect_jumps=True, 
                                    force_complete_scan=False, normalize=True, symbols=True)
    
    #try:
    #result=symbolic_explore(project,bin_cfg,0x41BCD8,0x41BD3C,"snprintf")
    sym_checker=Symbolic_Execution_Checker()
    result=sym_checker.symbolic_explore(project,bin_cfg,0x9e208,0x9e218,"strcpy")
    #result=symbolic_explore(project,bin_cfg,0x48ab8,0x48af4,"strcat")
    #result=symbolic_explore(project,bin_cfg,0x469bd8,0x469c20,"strcpy")
    print("get result",result)
    #except:
        #print("timeout")
    
#test()