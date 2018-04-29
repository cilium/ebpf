# Generate BPF ByteCode For Go

To convert an object file into a consumable binary array that can be used in a go program simply run the following command:

```sh
./generate -file object_file.o -package package-name -name name-of-go-file.go
```

To get the full sweep of the options for the generate program, run:

```sh
./generate --help
```
