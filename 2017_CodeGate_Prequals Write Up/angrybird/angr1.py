# http://nextline.tistory.com/117
import angr

proj = angr.Project("./angrybird", load_options={'auto_load_libs':False}) 
path_group = proj.factory.path_group(threads=4) 
path_group.explore(find=0x404fab)

print path_group.found[0].state.posix.dumps(0)
