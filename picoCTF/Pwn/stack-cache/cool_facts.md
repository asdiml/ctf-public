## Segment Registers

Segment registers are part of the CPU's architecture and are used to segment memory for different purposes. In x86 architecture, the primary segment registers are:

1. CS (Code Segment): Points to the segment containing the executable code (usually to where `.text` is loaded)
2. DS (Data Segment): Points to the segment containing global and static data (usually to where `.bss`, `.data` and sometimes `.rodata` are loaded)
3. SS (Stack Segment): Points to the segment containing the stack
4. ES, FS, GS: Additional segment registers used for various purposes, such as pointing to thread-specific data or other special data segments.

## Flat Memory Model in Protected Mode

In protected mode, especially on modern x86 systems, a flat memory model is often used where

- All segment registers (CS, DS, SS, etc.) have the same base address, typically 0.
- This means that logical addresses (e.g., DS:offset) directly correspond to linear addresses, simplifying memory management.

The segmentation is mainly used for memory protection and access control, rather than dividing memory into distinct segments as in real mode.

Thus in protected mode, segment registers typically point to overlapping or identical memory regions, abstracting away the complexity of segment-based memory access. 





