import angr
import networkx as nx

def find_shortest_path_to_vulnfunc(proj, main_fnc_addr, vuln_fnc_addr):

    # Generate the CFG and get the start and end nodes
    cfg = proj.analyses.CFGEmulated() # CFGFast gives inaccurate results
    
    cfg_nodes = cfg.nodes()
    for node in cfg_nodes:
        if node.addr == main_fnc_addr:
            start_node = node
        elif node.addr == vuln_fnc_addr:
            end_node = node

    # Get shortest path (this minimizes the number of CFG basic blocks we need to step through to reach end_node)
    shortest_path = nx.shortest_path(cfg.graph, source=start_node, target=end_node)
    shortest_path = [node for node in shortest_path if node.addr == node.function_address] # This produces shortest_path_functions from shortest_path_basic_blocks
    return shortest_path

'''
---------- Unused (Failed) ----------
to_process should be a stdin bytes object from the state found using custom_explore to 
automate figuring out what stdin is needed to get from one function address to the next
'''
def process_angr_output(to_process: bytes) -> bytes:

    process_result = b''
    for i in range(len(to_process)//9):
        chunk = to_process[i*9:(i+1)*9]

        # Cases of fizz, buzz or fizzbuzz
        if chunk[:4]== b'fizz' or chunk[:4] == b'buzz':
            process_result += chunk[:4] + b'\n'
            continue
        if chunk[:8] == b'fizzbuzz':
            process_result += b'fizzbuzz\n'
            continue

        # Cases where it should be number, or an immediate failure
        i = 0
        while chr(chunk[i]).isdigit():
            i += 1
        process_result += chunk[:i] + b'\n'

    return process_result

'''
---------- Unused (Failed) ----------
Wrapper for the closure (which is the lambda)
'''
def lambda_wrapper(proj, allowed_functions):
    '''
    Lambda function to filter the active stash to prune states which do not help in 
    reaching the next function
    '''
    def lambda_filter_states(state): 
        ip = proj.kb.functions.floor_func(state.solver.eval(state.regs.ip)).addr

        # Syscalls are emulated in proj.loader.kernel_object which is outside of 
        # proj.loader.main_obejct, but we still want to allow them
        if proj.loader.main_object.contains_addr(ip) and ip not in allowed_functions:
            return True # As in the function will be move to the stopped stash
        return False
    
    return lambda_filter_states

'''
---------- Unused (Failed) ----------
Custom explore function to automate the symbolic execution to search for the path from 
the current function to the next function, where only certain functions are allowed to
be called (else the state would be moved from active to stopped) to reduce the search
space (and thus memory used). 
'''
def custom_explore(simgr, shortest_path_functions, cur_index, proj):

    # Initialize allowed_functions (with start function address) and target_func_addr
    allowed_functions = [shortest_path_functions[cur_index]]
    target_func_addr = shortest_path_functions[cur_index+1]

    # Add setbuf, printf, etc libc calls to the list of allowed functions
    libc_calls = ['setbuf', 'printf', '__isoc99_scanf', 'strnlen', 'strncmp', 'strtol']
    for libc_call in libc_calls:
        func = next(proj.kb.functions.get_by_name(libc_call))
        allowed_functions += [func.addr]

    # Add the call chain of functions from cur_func till the target function to allowed_functions
    cur_func = proj.kb.functions.get_by_addr(shortest_path_functions[cur_index])
    for ind,site in enumerate(cur_func.get_call_sites()):
        called_func_addr = proj.kb.functions[cur_func.get_call_target(site)].addr
        allowed_functions += [called_func_addr]
        if called_func_addr == target_func_addr:
            break

    # Add the canary __i686.get_pc_thunk.ax/bx functions to allowed_functions
    allowed_functions += [0x8048590, 0x814c6ca]

    print(f"Step {cur_index+1}/{len(shortest_path_functions)-1}")
    while len(simgr.found) == 0: 
        simgr.move(from_stash='active', to_stash='found', filter_func=
            lambda s: proj.kb.functions.floor_func(s.solver.eval(s.regs.ip)).addr == target_func_addr
        )

        simgr.move(from_stash='active', to_stash='stopped', filter_func=lambda_wrapper(proj, allowed_functions))
        print(f"Active stash size: {len(simgr.active)}, Stopped stash size: {len(simgr.stopped)}")
        simgr.step()

    return simgr

# Plays fizzbuzz up till n
def play_fizzbuzz(n):
    output = b''
    for i in range(1,n+1):
        if i%15 == 0:
            output += b'fizzbuzz\n'
        elif i%5 == 0:
            output += b'buzz\n'
        elif i%3 == 0:
            output += b'fizz\n'
        else:
            output += str(i).encode() + b'\n'
    return output

def main():

    # Load the binary and generate the CFG
    proj = angr.Project('./vuln', auto_load_libs=False)

    # Function addresses - we want to reach the vulnerable function from main
    main_fnc_addr = 0x814c22c
    vuln_fnc_addr = 0x808ae73

    '''
    PART 1: FINDING THE SHORTEST PATH FROM MAIN TO VULN_FUNC
    - Uses angr's CFGEmulated and networkx's shortest_path() to construct the graph and find the shortest_path_basic_blocks
    - Regarding running the script: Generating the CFGEmulated took 3 hours on my computer, so Istrongly recommend just using the shortest path that has already been found. 
    '''
    ## Get shortest path and reduce each node to an address, OR
    # shortest_path = find_shortest_path_to_vulnfunc(proj, main_fnc_addr, vuln_fnc_addr)
    # shortest_path = [node.addr for node in shortest_path]
    
    # Use the already-found shortest path
    shortest_path_basic_blocks = [0x814c22c, 0x814c243, 0x814c25c, 0x811d5b3, 0x811d5be, 0x811d5cd, 0x811d5d9, 0x811d5de, 0x811d5e8, 0x811d5f4, 0x812d430, 0x812d43b, 0x812d44a, 0x812d456, 0x8140c2e, 0x8140c39, 0x8140c48, 0x8140c54, 0x8140c59, 0x8140c63, 0x8140c6f, 0x8140c74, 0x8140c7e, 0x8140c8a, 0x813ca30, 0x813ca3b, 0x813ca4a, 0x813ca56, 0x813ca5b, 0x813ca65, 0x813ca71, 0x813ca76, 0x813ca80, 0x813ca8c, 0x813ca91, 0x813ca9b, 0x813caa7, 0x813caac, 0x813cab6, 0x813cac2, 0x813cac7, 0x813cad1, 0x813cadd, 0x813cae2, 0x813caec, 0x813caf8, 0x813cafd, 0x813cb07, 0x813cb13, 0x813cb18, 0x813cb22, 0x813cb2e, 0x8143ffd, 0x8144008, 0x8144017, 0x8144023, 0x8144028, 0x8144032, 0x814403e, 0x81313b8, 0x81313c3, 0x81313d2, 0x81313de, 0x81313e3, 0x81313ed, 0x81313f9, 0x81313fe, 0x8131408, 0x8131414, 0x8131419, 0x8131423, 0x813142f, 0x8131434, 0x813143e, 0x813144a, 0x813144f, 0x8131459, 0x8131465, 0x813146a, 0x8131474, 0x8131480, 0x8131485, 0x813148f, 0x813149b, 0x81314a0, 0x81314aa, 0x81314b6, 0x81314bb, 0x81314c5, 0x81314d1, 0x81314d6, 0x81314e0, 0x81314ec, 0x81314f1, 0x81314fb, 0x8131507, 0x813150c, 0x8131516, 0x8131522, 0x8131527, 0x8131531, 0x813153d, 0x8131542, 0x813154c, 0x8131558, 0x813155d, 0x8131567, 0x8131573, 0x8131578, 0x8131582, 0x813158e, 0x8131593, 0x813159d, 0x81315a9, 0x81315ae, 0x81315b8, 0x81315c4, 0x81315c9, 0x81315d3, 0x81315df, 0x81315e4, 0x81315ee, 0x81315fa, 0x81315ff, 0x8131609, 0x8131615, 0x813161a, 0x8131624, 0x8131630, 0x8109f08, 0x8109f14, 0x8109f24, 0x8109f4a, 0x8109f6a, 0x8109f74, 0x8109f94, 0x8109f9a, 0x808ae73]
    shortest_path_functions = [0x814c22c, 0x811d5b3, 0x812d430, 0x8140c2e, 0x813ca30, 0x8143ffd, 0x81313b8, 0x8109f08, 0x808ae73]

    '''
    ---------- Unused (Failed) ----------
    PART 2: FINDING THE STDIN TO OBTAIN THE SHORTEST PATH
    - Uses a custom_explore function to automate searching for the stdin that will bring us from one function node to the next
    '''
    #payload = b''

    ## NOTE: This is required to populate proj.kb.functions() with Function objects
    ## If you have already run proj.analyses.CFGEmulated() in Part 1, then remove / comment out this line
    #cfg = proj.analyses.CFGFast()

    ## Find stdin to go from each function to the next (explained in solve.md)
    #for i in range(len(shortest_path_functions)):
    #    call_state = proj.factory.call_state(shortest_path_functions[i])
    #    simgr = proj.factory.simgr(call_state, stashes={"found":[], "stopped":[]})

    #    simgr = custom_explore(simgr, shortest_path_functions, i, proj)
    #    s = simgr.found[0]
    #    payload += process_angr_output(s.posix.dumps(0))

    #    print(payload)

    '''
    PART 2: FINDING THE STDIN TO OBTAIN THE SHORTEST PATH
    - Use the call chain to infer the stdin required to go from function to function
    '''

    payload = b''

    # NOTE: This is required to populate proj.kb.functions() with Function objects
    # If you have already run proj.analyses.CFGEmulated() in Part 1, then remove / comment out this line
    cfg = proj.analyses.CFGFast()

    # 1. Ignore main() because it immediately enters 0x811d5b3
    # 2. Don't include the transition from 0x8109f08 to 0x808ae73 because it differs from the rest
    for i in range(1, len(shortest_path_functions)-2):
        cur_func = proj.kb.functions.get_by_addr(shortest_path_functions[i])

        for ind,site in enumerate(cur_func.get_call_sites()):

            # Ignore the function to get a value for the canary
            if ind < 1: continue

            # Get the addr of the called function and check if we've reached
            called_func = proj.kb.functions[cur_func.get_call_target(site)]
            if called_func.addr == shortest_path_functions[i+1]:
                break

            # If called_func_addr is to play fizzbuzz, we want to fail it immediately, 
            # else we need to get the first fizzbuzz chain for that function correct
            if called_func.addr == 0x80486b1:
                payload += b'wrong\n'
            else:

                # Extract the second block
                for j,b in enumerate(called_func.blocks):
                    if j == 1:
                        scnd_block = b
                        break

                # Extract the value pushed onto the stack to play fizzbuzz
                play_value = int(str(scnd_block.disassembly).splitlines()[2].split('\t')[-1], 16)

                # Append to payload
                payload += play_fizzbuzz(play_value-1)

    # Manually craft the stdin needed for the transition from 0x8109f08 to 0x808ae73 
    payload += play_fizzbuzz(5-1) + b'wrong\n'

    # Manually craft the stdin needed to expose the buffer overflow in 0x808ae73 
    payload += b'wrong'

    print(f"{payload=}")


if __name__ == '__main__':
    main()