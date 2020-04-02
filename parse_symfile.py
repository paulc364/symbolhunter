#! /usr/bin/env python

import sys
import json
inpath=sys.argv[1]
if len(sys.argv) > 2:
  symtype=sys.argv[2]
else:
  symtype='task_struct'

if len(sys.argv) > 3:
  start=sys.argv[3]
else:
  start=''

if len(sys.argv) > 4:
  endsym=sys.argv[4]
else:
  endsym=''

infile=open(inpath, 'rb' )

jdat=infile.read()

jobj=json.loads(jdat)

#print(jobj.keys())

if symtype == 'enums':
  utypes=jobj['enums']
  for ename in utypes:
    enumval=utypes[ename]
    for const_name in enumval['constants']:
      print("{0} : {1} : {2}".format(ename,const_name,enumval['constants'][const_name]))
  sys.exit(0)
else:
  utypes=jobj['user_types']

#print("user types: "+str(utypes.keys()))

task_struct=utypes[symtype]

# convert fields into a list so we can sort
#print(type(task_struct['fields']))

#fields=[ field for field in task_struct['fields'] ]
fields=task_struct['fields']

ff_sort=sorted( fields, key=lambda field : fields[field]['offset'] )
#fields.sort( key=lambda field : field['offset'] )

#print( ff_sort )

seenstart=False
if start=='':
  seenstart=True

def get_subtype( item ):
    substr=''
    if ('subtype' in item):
        substr=" -> "
        sub=item['subtype']
        if 'kind' in sub:
          substr += sub['kind']
        if 'name' in sub:
          substr += ' : '+sub['name']
    return substr

for field in ff_sort:
  if (not seenstart) and (field!=start):
    continue
  seenstart=True
  
  item=fields[field]
  if ('name' in item['type']):
      print( "name: "+field+", offset: "+str(item['offset'])+", kind: "+item['type']['kind']+" : "+item['type']['name'] )+get_subtype(item['type'])
  else:
    print( "name: "+field+", offset: "+str(item['offset'])+", kind: "+item['type']['kind'] )+get_subtype(item['type'])

  if (endsym != '') and (field==endsym):
    break
