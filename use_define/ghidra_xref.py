from ghidra.util.classfinder import ClassSearcher
from ghidra.app.plugin.core.analysis import ConstantPropagationAnalyzer
from ghidra.program.model.mem import MemoryAccessException
import json
DEBUG=True

def get_xrefs(paramTargets,output):
    xref_set={}
    for i, param in enumerate(paramTargets):
        #print(i,param)
        curAddr = currentProgram.minAddress
        xref_set[param]=[]
        while curAddr < currentProgram.maxAddress:
            curAddr = find(curAddr, param)
            if curAddr is None:
                break
            if getByte(curAddr.add(len(param))) != 0:
                curAddr = curAddr.add(1)
                continue
            for ref in getReferencesTo(curAddr):
                caller = getFunctionContaining(ref.fromAddress)
                if caller is not None:
                    xref_set[param].append(ref.fromAddress.offset)
                else:
                    for ref2 in getReferencesTo(ref.fromAddress):
                        caller = getFunctionContaining(ref2.fromAddress)
                        if caller is None:
                            continue
                        xref_set[param].append(ref2.fromAddress.offset)
                
            curAddr = curAddr.add(1)
    #print("finished")
    output.write(json.dumps(xref_set))

if __name__ == '__main__':
    args = getScriptArgs()
    paramTargets = set(open(args[0]).read().strip().split())
    output = open(args[1], 'w')
    get_xrefs(paramTargets,output)
    
                