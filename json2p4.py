import json
from os import sys

fin = open (sys.argv[1], 'r')
js = json.load (fin)

print ("JS",js)

######## Sample JSON
##{
##  "flow": {
##    "over": "udp",
##    "scope": "flow",
##    "classify" : { "join": "and", "condition":[{"op": "eq", "arguments": ["tcp.port", 40]},  {"op": "eq", "arguments": ["ip.src", "10.1.1.1"]}]}
##  },
##  "payload": {
##	"offset": 160,
##	"struct": [{"name" : "pixel", "size": 24, "type": "bit"}],
##	"repetition": "MAX"
##  },
##  "function" : {
##    "row": { "condition": [{"op":"leq", "arguments": ["pixel","DARK"]}], "join": "none", "execute": {"action":"count", "output": {"reference":"##count"}}},
##    "flow": { "frequency":"packet", "condition": [{"op":"geq", "arguments": [{"reference":"##count"},"THRESHOLD"]}], "join": "none", "execute": {"action":"notify", "named-arguments":{"ip.dst":"10.2.2.2", "udp.dport":"2022"}, "annotation":["once"]}},
##  }
##}

# action sequence ?

#parser code

PAYLOAD_MAX=200 # set it to higher value later
GLOBAL=[]
HEADERS=[]
PARSER=[]
SCOPESEQ=['row','packet','flow']
INGRESS={}
for seq in SCOPESEQ:
    INGRESS[seq]=[]
#print ("INGRESS:",INGRESS)

template_offset='''
header offset_t {{
    bit<{offset}> skip;
}}
'''

template_payload='''
header payload_t {{
{payload_struct}
}}
'''

template_field='''    {type}<{size}> {name};'''
DELIMITER ='\n'
template_header_offset='''   offset_t offset;'''
template_header_pload='''   payload_t pload{i};'''

template_parser_offset='''
\tstate sql {
\t\tpacket.extract(hdr.offset);'''
template_parser_pload='''\t\tpacket.extract(hdr.pload{i});'''
template_parser_accept='''\t\ttransition accept;
\t}'''
locals().update(js)

def get_template_ingress_row(htype):
    if 'condition' in htype: return '''if ({CONDITION}) {{ {ACTION} }}\n'''
    return '''{ACTION};\n'''

def get_template_ingress_condition(cond):
    #print ("DEBUG get_template_ingress_condition args", cond['arguments'])
    if 'reference' in cond['arguments'][0]:
        #print ("DEBUG stmt:", " without hdr")
        return '''{arguments[0]} {op} {arguments[1]}'''
    return '''(hdr.pload{i}.{arguments[0]} {op} {arguments[1]})'''

template_ingress_row_action={'count':'''{output}={output}+1;''',
                         'sum':'''{output}={output}+{arguments[0]};'''} # can be a action sequence - TODO

def gen_payload ():
    if 'offset' in payload and payload['offset'] >0: # use templates
        GLOBAL.append(template_offset.format(**payload))
    payload_struct=''
    struct_val=[]
    for v in payload['struct']:
        struct_val.append(template_field.format(**v))
    payload_struct = DELIMITER.join(struct_val)
    #print ("PS:",payload_struct)
    GLOBAL.append(template_payload.format(payload_struct=payload_struct))
    print ("GLOBAL:",*GLOBAL,sep='')

gen_payload()


def fsize (h):
    if h['type'] == 'bit': return int(int(h['size'])/8)

FUNCTION=[]


## flow": {
##    "over": ["ethernet", "ipv4","udp"],
##    "scope": "flow", #TODO flow and mflow
##    "classify" : { "join": "and", "condition":[{"op": "eq", "arguments": ["tcp.port", 40]},  {"op": "eq", "arguments": ["ip.src", "10.1.1.1"]}]}
##  },

template_ingress_scopecheck='''hdr.{proto}_t.isValid()'''
template_ingress_flow='''
        if ({flow_cdn}) {{
            {function}
        }}
'''
FLOW_STACK_JOIN=' && '
FLOW=[]
JOIN={'and' : ' && ' , 'or' : ' || '}
OPERATOR={'and' : ' && ' , 'or' : ' || ', 'eq' :' == ', 'leq': ' <= ', 'geq': ' >= '}
template_clause_binary='''{arguments[0]} {op} {arguments[1]}'''
template_subflow_clause='''({subflow})'''
PROTO=['ethernet', 'ipv4', 'tcp', 'udp']
def gen_flow(): # assume udp_t and tcp_t are predefined
    for p in flow['over']:
        FLOW.append(template_ingress_scopecheck.format(proto=p))
    SUBFLOW=[]
    if 'classify' in flow and flow['classify']['join'] in JOIN:
        for clause in flow['classify']['condition']:
            #print ("DBG clause:", clause)
            clause['op']=OPERATOR[clause['op']]
            for idx,arg in enumerate(clause['arguments']):
                #print (arg)
                if isinstance(arg, str):
                    if '.' in arg and arg.split('.')[0] in PROTO:
                        clause['arguments'][idx] = "hdr."+ arg
                        #print (arg)
                    else:
                        clause['arguments'][idx] = '"'+arg+'"' # for ip addresses
            SUBFLOW.append(template_clause_binary.format(**clause))
        FLOW.append(template_subflow_clause.format(subflow=JOIN[flow['classify']['join']].join(SUBFLOW)))
    flow_cdn=FLOW_STACK_JOIN.join(FLOW)
    NONE='\t'*2
    print (template_ingress_flow.format(flow_cdn=flow_cdn, function=NONE.join(INGRESS['row'])))
    # runtime vs compile time
    #if flow['over'] == 'udp':
        #INGRESS.append(

def decode (k,v):
    hash={'op': OPERATOR}
    if k in hash: return (hash[k])[v]
    if k == 'reference': return v[2:]
    return v

NONE=''
def gen_repetition ():
    # calculate total size from offset and payload size
    size = PAYLOAD_MAX if payload['repetition'] == 'MAX' else int(payload['repetition'])
    #print ("DBG1:", size)
    size = size - (int(payload['offset']/8) if 'offset' in payload else 0) # should this be celing
    #print ("DBG2:", size)
    payload_size = 0
    for v in payload['struct']:
        payload_size = payload_size + fsize (v)
    repeat = int(size/payload_size)
    #print ("DBG3:", repeat, payload_size)
    if 'offset' in payload:
        HEADERS.append(template_header_offset)
        PARSER.append(template_parser_offset)
    for i in range(repeat):
        HEADERS.append(template_header_pload.format(i=i))
        PARSER.append(template_parser_pload.format(i=i))
        CONDN=[]
        for cond in function['row']['condition']:
            #print ("COND:",cond)
            hval = {k:decode(k,v) for k,v in cond.items()}
            hval['i']=i
            CONDN.append(get_template_ingress_condition(cond).format(**hval))
        #print ("CONDN:", CONDN, "JOIN", function['row']['join'])
        # template_ingress_row_action['count']
        CONDITION=function['row']['join'].join(CONDN)
        execx=function['row']['execute']
        #print ("DEBUG:", execx['output'])
        for k,v in execx['output'].items():
            ACTION=template_ingress_row_action[execx['action']].format(output=decode(k,v))
        #print ("DEBUG:", ACTION)
        INGRESS['row'].append(get_template_ingress_row(function['row']).format(CONDITION=CONDITION,ACTION=ACTION))
    PARSER.append(template_parser_accept)
    print ("HEADERS:\n",DELIMITER.join(HEADERS),sep='')
    print ("PARSER:\n",DELIMITER.join(PARSER),sep='')
    #print ("INGRESS:\n",NONE.join(INGRESS['row']),sep='')

gen_repetition()
gen_flow()

##{  "function" : {
##    "row": { "condition": [{"op":"leq", "arguments": ["pixel","DARK"]}], "join": "none", "execute": {"action":"count", "output": {"reference":"##count"}}},
##    "flow": { "frequency":"packet", "condition": [{"op":"geq", "arguments": [{"reference":"##count"},"THRESHOLD"]}], "join": "none", "execute": {"action":"notify", "named-arguments":{"ip.dst":"10.2.2.2", "udp.dport":"2022"}, "annotation":["once"]}},
##                     }}

def tabify (strin,n):
    rep='\t'*n
    return rep+strin.replace('\n','\n'+rep)
template_ingress_flow_action={'notify':'''\n\tmeta.ipv4dst="{ip-dst}";\n\tmeta.udpdport={udp-dport};\n\tnotify();\n'''} # can be a action sequence - TODO

def gen_flow_action():
    inp=function['flow']
    if inp['frequency'] in INGRESS: out = INGRESS[inp['frequency']]
    CONDN=[]
    for cond in inp['condition']:
        mcond = {k:decode(k,v) for k,v in cond.items()}
        #print ("DEBUG B", mcond, " COND", cond)
        templatestr=get_template_ingress_condition(cond)
        for idx,arg in enumerate(mcond['arguments']):
            if not isinstance(arg, str):
                mcond['arguments'][idx]=decode(list(arg.keys())[0], list(arg.values())[0])
        #print ("DEBUG B", mcond, " COND", cond)
        CONDN.append(templatestr.format(**mcond))
    CONDITION=function['row']['join'].join(CONDN)
    exe=inp['execute']
    ACT=[]
    ACT.append(template_ingress_flow_action[exe['action']].format(**exe['named-arguments']))
    ACTION=''.join(ACT)
    print(tabify(get_template_ingress_row(inp).format(CONDITION=CONDITION,ACTION=ACTION),1))
    #print ("DEBUG C:",CONDITION, "ACTION",*ACTION)

gen_flow_action()
# TODO apply define local variable 
# TODO flow condition

# storage based on scope - local variable or register or register with flow association
