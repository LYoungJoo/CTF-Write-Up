# http://nextline.tistory.com/117

import angr
import simuvex

main = 0x4007da
find = 0x404FC1

p = angr.Project('./angrybird')
init = p.factory.blank_state(addr=main)
init.options.remove(simuvex.o.LAZY_SOLVES)
init.memory.store(0x606038,"hello")

pg = p.factory.path_group(init,threads=8)
ex = pg.explore(find=find)

print ex.found[0].state.posix.dumps(1)
