
const off_t = 'long'

export const open = new NativeFunction(Module.findExportByName(null, 'open')!, 'int', ['pointer', 'int', 'int'])
export const close = new NativeFunction(Module.findExportByName(null, 'close')!, 'int', ['int'])
export const read = new NativeFunction(Module.findExportByName(null, 'read')!, 'int', ['int', 'pointer', 'int'])
export const write = new NativeFunction(Module.findExportByName(null, 'write')!, 'int', ['int', 'pointer', 'int'])
export const lseek = new NativeFunction(Module.findExportByName(null, 'lseek')!, 'int64', ['int', 'int64', 'int'])
export const mmap = new NativeFunction(Module.findExportByName(null, 'mmap')!, 'pointer', ['pointer', 'size_t', 'int', 'int', 'int', off_t])
export const munmap = new NativeFunction(Module.findExportByName(null, 'munmap')!, 'int', ['pointer', 'size_t'])
export const pipe = new NativeFunction(Module.findExportByName(null, 'pipe')!, 'int', ['pointer'])
export const dup2 = new NativeFunction(Module.findExportByName(null, 'dup2')!, 'int', ['int', 'int'])
export const fcntl = new NativeFunction(Module.findExportByName(null, 'fcntl')!, 'int', ['int', 'int', 'int'])


export const O_RDONLY = 0
export const O_RDWR = 2

export const SEEK_SET = 0


// https://github.com/apple/darwin-xnu/blob/master/bsd/sys/mman.h

export const PROT_READ = 0x1
export const PROT_WRITE = 0x2

export const MAP_SHARED = 0x1
export const MAP_PRIVATE = 0x2
