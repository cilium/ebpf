# core relos in metadata

* make coreRelocate take asm.Instructions
* collect core relos from metadata
* run calculation
* do fixup

* Q: how do the relos get into the metadata in the first place?

# line infos in metadata

* in the elf reader, retrieve line infos before splitting
* assign line infos to the instructions
* split instructions
