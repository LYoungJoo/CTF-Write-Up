# http://nextline.tistory.com/117

import angr

main = 0x4007ed
find = 0x404FC1

p = angr.Project('./angrybird')
init = p.factory.blank_state(addr=main)
pg = p.factory.path_group(init,threads=4)
ex = pg.explore(find=find)

print ex.found[0].state.posix.dumps(1)
