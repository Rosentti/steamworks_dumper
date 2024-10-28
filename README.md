# steamworks_dumper (fork)
Dumps internal steamclient.so API from a provided ubuntu12_32/steamclient.so binary. 

Differs from m4dengi's original version as this is infinitely more spaghetti, however the original does not dump IPC info, like functionid and fencepost. 

## building
Get yourself a copy of capstone engine and compile as such:
```
$ mkdir build
$ cd build
$ cmake ..
$ cmake --build .
```

## usage
```
./steamworks_dumper <path_to_ubuntu12_32_steamclient.so> <out_path>
```
  **_output path must be a valid existing directory!_**
  
